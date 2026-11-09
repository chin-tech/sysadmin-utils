# Windows SMB provisioning runs over WinRM. Only Get-WindowsSmbBootScript is installed at startup.

function Get-WindowsMobileSmbInventory {
    return {
        param([string]$SmbUser)
        $interfaces = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            $_.IPAddress -like '10.*' -and $_.AddressState -eq 'Preferred'
        } | ForEach-Object {
            $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction Stop
            if ($adapter.Status -eq 'Up') {
                [pscustomobject]@{ InterfaceName = $adapter.Name; InterfaceGuid = $adapter.InterfaceGuid.ToString()
                    IPAddress = $_.IPAddress; PrefixLength = [int]$_.PrefixLength }
            }
        })
        [pscustomobject]@{ Interfaces = $interfaces; LocalAuthority = $env:COMPUTERNAME; AccountExists = [bool](Get-LocalUser -Name $SmbUser -ErrorAction SilentlyContinue)
            Drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object { $_.DeviceID.TrimEnd(':').ToUpperInvariant() }) }
    }
}

function Get-WindowsSmbBootScript {
    return {
        param([ValidateSet('Activate','RestoreBoot')][string]$Mode, [string]$Root)
        $ErrorActionPreference = 'Stop'
        $statePath = Join-Path $Root 'state.json'
        $mutex = [Threading.Mutex]::new($false, 'Global\Mobiles-Smb')
        $locked = $false; $state = $null
        try {
            try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
            if (-not $locked) { throw 'Another SMB operation is in progress.' }
            $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            if ($Mode -eq 'Activate') {
                if ($state.Status -notin @('PreparedPendingReboot','Active','ActivationFailed')) { throw 'SMB activation is not prepared.' }
                $adapter = Get-NetAdapter | Where-Object { $_.InterfaceGuid.ToString() -eq $state.Interface.InterfaceGuid } | Select-Object -First 1
                if (-not $adapter) { throw 'Saved network adapter is missing.' }
                # Changing addressing happens at startup, never in the management session.
                if ($state.OriginalDhcp -eq 'Enabled') {
                    Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -Dhcp Disabled
                    $activeAddress = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -IPAddress $state.Interface.IPAddress -ErrorAction SilentlyContinue
                    if ($activeAddress -and $activeAddress.PrefixOrigin -ne 'Manual') { $activeAddress | Remove-NetIPAddress -Confirm:$false; $activeAddress = $null }
                    if (-not $activeAddress) { New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $state.Interface.IPAddress -PrefixLength $state.Interface.PrefixLength | Out-Null }
                    # Only this interface is modified. Original DNS settings are retained.
                }
                $ready = $false
                for ($attempt = 0; $attempt -lt 15; $attempt++) {
                    $installed = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -IPAddress $state.Interface.IPAddress -ErrorAction SilentlyContinue
                    if ($installed -and $installed.AddressState -eq 'Preferred' -and $installed.PrefixLength -eq $state.Interface.PrefixLength) { $ready = $true; break }
                    Start-Sleep -Seconds 1
                }
                if (-not $ready) { throw 'Selected IPv4 address is not preferred after activation; inspect for duplicate-address or adapter failures.' }
                $state.Status = 'Active'
            } else {
                if ($state.Status -notin @('RestorePendingReboot','RestoreBootFailed','Restored')) { throw 'SMB restoration is not prepared.' }
                $adapter = Get-NetAdapter | Where-Object { $_.InterfaceGuid.ToString() -eq $state.Interface.InterfaceGuid } | Select-Object -First 1
                if (-not $adapter) { throw 'Saved network adapter is missing.' }
                if ($state.OriginalDhcp -eq 'Enabled') {
                    Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -IPAddress $state.Interface.IPAddress -ErrorAction SilentlyContinue | Where-Object PrefixOrigin -eq Manual | Remove-NetIPAddress -Confirm:$false
                    Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -Dhcp Enabled
                    if ($state.OriginalDnsStatic) { Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ($state.OriginalDnsStatic -split '[, ]+' | Where-Object { $_ }) }
                    else { Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses }
                }
                Unregister-ScheduledTask -TaskName $state.TaskName -Confirm:$false
                $state.Status = 'Restored'
            }
            $state.Error = $null
        } catch {
            if ($state) {
                $state.Error = $_.Exception.Message
                $state.Status = if ($Mode -eq 'Activate') { 'ActivationFailed' } else { 'RestoreBootFailed' }
            }
            throw
        } finally {
            try {
                if ($locked -and $state) {
                    $state.UpdatedUtc = [datetime]::UtcNow.ToString('o')
                    $state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath "$statePath.tmp" -Encoding UTF8
                    Move-Item -LiteralPath "$statePath.tmp" -Destination $statePath -Force
                    $state | ConvertTo-Json -Depth 12 -Compress | Add-Content -LiteralPath (Join-Path $Root 'history.jsonl') -Encoding UTF8
                }
            } finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
        }
        $state
    }
}

function Get-WindowsSmbTaskOptions {
    param([Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateSet('Activate','RestoreBoot')][string]$Mode)
    $arguments = '-NoProfile -File "{0}\boot.ps1" -Mode {1} -Root "{0}"' -f $Root, $Mode
    [pscustomobject]@{
        BootScript = (Get-WindowsSmbBootScript).ToString()
        TaskXml = New-TaskXML -Description "Mobile SMB network: $Mode" -Execute 'powershell.exe' -Arguments $arguments `
            -TriggerConfigs @(@{ Type = 8; Delay = 'PT30S'; EndBoundary = '' }) -ExecutionTimeLimit 'PT2M'
    }
}

function Get-WindowsMobileSmbWorker {
    return {
        param([ValidateSet('Prepare','Restore','Status')][string]$Mode,
            [string]$Root, $Options, [pscredential]$Credential)
        $ErrorActionPreference = 'Stop'
        $statePath = Join-Path $Root 'state.json'
        $state = $null
        $mutex = [Threading.Mutex]::new($false, 'Global\Mobiles-Smb')
        $locked = $false
        function Save-State {
            $state.UpdatedUtc = [datetime]::UtcNow.ToString('o')
            $state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath "$statePath.tmp" -Encoding UTF8
            Move-Item -LiteralPath "$statePath.tmp" -Destination $statePath -Force
            $state | ConvertTo-Json -Depth 12 -Compress | Add-Content -LiteralPath (Join-Path $Root 'history.jsonl') -Encoding UTF8
        }
        function Protect-Directory([string]$Path) {
            if ((Test-Path -LiteralPath $Path) -and ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Refusing a redirected SMB state directory.' }
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            $acl = [Security.AccessControl.DirectorySecurity]::new()
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($sidText in @('S-1-5-18','S-1-5-32-544')) {
                $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
            }
            $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
            Set-Acl -LiteralPath $Path -AclObject $acl
        }
        function Initialize-SmbAccount {
            $existing = Get-LocalUser -Name $state.UserName -ErrorAction SilentlyContinue
            $state.AccountOwned = -not [bool]$existing
            $state.AccountWasEnabled = [bool]($existing -and $existing.Enabled)
            if ($existing) {
                $state.UserSid = $existing.SID.Value
                Save-State
                if (-not $existing.Enabled) { Enable-LocalUser -Name $state.UserName }
            } else {
                New-LocalUser -Name $state.UserName -Password $Credential.Password -Description 'Mobile deployment SMB access' -AccountNeverExpires -PasswordNeverExpires | Out-Null
                $state.UserSid = (Get-LocalUser -Name $state.UserName).SID.Value
            }
            Save-State
        }
        function Get-AccountRules($Acl) {
            @($Acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq $state.UserSid } | ForEach-Object {
                [pscustomobject]@{ Rights=[int]$_.FileSystemRights; Type=[int]$_.AccessControlType; Inheritance=[int]$_.InheritanceFlags; Propagation=[int]$_.PropagationFlags }
            } | Sort-Object Type,Rights,Inheritance,Propagation)
        }
        function New-SmbAccountRule($Rule) {
            [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($state.UserSid), $Rule.Rights, $Rule.Inheritance, $Rule.Propagation, $Rule.Type)
        }
        function Restore-AccountRules($Acl, $Snapshot) {
            $current = ConvertTo-Json -InputObject @(Get-AccountRules $Acl) -Compress
            $before = ConvertTo-Json -InputObject @($Snapshot.Before) -Compress
            $applied = ConvertTo-Json -InputObject @($Snapshot.Applied) -Compress
            if ($current -eq $before) { return } # Preparation may have failed before Set-Acl.
            if ($current -ne $applied) { throw "SMB account ACL changed outside deployment on $($Snapshot.Drive); inspect before cleanup." }
            foreach ($rule in @($Acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq $state.UserSid })) { $Acl.RemoveAccessRuleSpecific($rule) }
            foreach ($rule in $Snapshot.Before) {
                $Acl.AddAccessRule((New-SmbAccountRule $rule))
            }
        }
        function Set-BootTask {
            # XML is built on the controller with New-TaskXML, just like other deployment tasks.
            $Options.BootScript | Set-Content -LiteralPath (Join-Path $Root 'boot.ps1') -Encoding UTF8
            Register-ScheduledTask -TaskName $state.TaskName -Xml $Options.TaskXml -User SYSTEM -Force -ErrorAction Stop | Out-Null
            Remove-Item -LiteralPath (Join-Path $Root 'worker.ps1') -Force -ErrorAction SilentlyContinue # Previous implementation.
        }
        try {
            try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
            if (-not $locked) {
                if ($Mode -eq 'Status') { return [pscustomobject]@{ Status = 'Busy' } }
                throw 'Another SMB operation is in progress.'
            }
            if (Test-Path -LiteralPath $statePath) { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json }
            if ($Mode -eq 'Status') {
                if ($state) { return $state }
                return [pscustomobject]@{ Status = 'NotPrepared' }
            }
            if ($Mode -eq 'Prepare') {
                if ($state -and $state.Status -ne 'Restored') { throw 'SMB state already exists. Inspect or check in this deployment before preparing it again.' }
                $adapter = Get-NetAdapter | Where-Object { $_.InterfaceGuid.ToString() -eq $Options.Interface.InterfaceGuid } | Select-Object -First 1
                if (-not $adapter) { throw 'Selected interface is no longer present.' }
                $index = $adapter.InterfaceIndex
                $ipInterface = Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4
                $dnsKey = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{$($Options.Interface.InterfaceGuid.Trim('{}'))}"
                Protect-Directory (Split-Path $Root -Parent)
                Protect-Directory $Root
                $state = [pscustomobject]@{ Status = 'Preparing'; UpdatedUtc = ''; Error = $null
                    UserName = $Options.UserName; UserSid = $null; AccountOwned = $false; AccountWasEnabled = $false; AddedRights = @(); AclSnapshots = @()
                    Interface = $Options.Interface; OriginalDhcp = [string]$ipInterface.Dhcp
                    OriginalDnsStatic = [string]$dnsKey.NameServer
                    Shares = @(); AclDrives = @(); FirewallName = "Mobiles-Smb-$($Options.Id)"; TaskName = "Mobiles-Smb-$($Options.Id)" }
                Save-State
                Initialize-SmbAccount
                # The account gets network logon, but cannot log on interactively.
                $inf = Join-Path $Root 'rights.inf'; $db = Join-Path $Root 'rights.sdb'
                & secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Could not read local logon rights.' }
                $cfg = Get-Content -LiteralPath $inf -Raw
                foreach ($right in @('SeNetworkLogonRight','SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight')) {
                    $pattern = '(?m)^' + $right + '\s*=\s*([^\r\n]*)'
                    $match = [regex]::Match($cfg, $pattern)
                    if ($match.Success -and "*$($state.UserSid)" -in @($match.Groups[1].Value -split ',' | ForEach-Object { $_.Trim() })) { continue }
                    $state.AddedRights += $right
                    $values = if ($match.Success -and $match.Groups[1].Value.Trim()) { $match.Groups[1].Value.Trim() + ',' } else { '' }
                    $line = "$right = $values*$($state.UserSid)"
                    if ($match.Success) { $cfg = $cfg.Remove($match.Index, $match.Length).Insert($match.Index, $line) }
                    else { $cfg += "`r`n$line`r`n" }
                }
                Save-State
                $cfg | Set-Content -LiteralPath $inf -Encoding Unicode
                & secedit /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Could not set SMB account logon rights.' }
                foreach ($drive in $Options.Drives) {
                    $path = "${drive}:\"
                    $existing = Get-SmbShare -Name $drive -ErrorAction SilentlyContinue
                    if ($existing -and $existing.Path -ine $path) { throw "Share '$drive' already points somewhere else." }
                    $account = "$env:COMPUTERNAME\$($state.UserName)"
                    $originalAllow = @()
                    if ($existing) { $originalAllow = @(Get-SmbShareAccess -Name $drive | Where-Object { $_.AccountName -ieq $account -and $_.AccessControlType -eq 'Allow' } | ForEach-Object { [string]$_.AccessRight }) }
                    $state.Shares += [pscustomobject]@{ Name = $drive; Created = (-not [bool]$existing); OriginalAllow = @($originalAllow) }
                    $state.AclDrives += $drive
                    Save-State # Write intent before changing each resource, so partial preparation is recoverable.
                    $acl = Get-Acl -LiteralPath $path
                    $beforeRules = @(Get-AccountRules $acl)
                    $rule = New-SmbAccountRule ([pscustomobject]@{ Rights=[int][Security.AccessControl.FileSystemRights]::FullControl; Inheritance=3; Propagation=0; Type=0 })
                    $acl.AddAccessRule($rule)
                    $state.AclSnapshots += [pscustomobject]@{ Drive=$drive; Before=@($beforeRules); Applied=@(Get-AccountRules $acl) }
                    Save-State
                    Set-Acl -LiteralPath $path -AclObject $acl
                    $account = "$env:COMPUTERNAME\$($state.UserName)"
                    if ($existing) { Grant-SmbShareAccess -Name $drive -AccountName $account -AccessRight Full -Force | Out-Null }
                    else { New-SmbShare -Name $drive -Path $path -FullAccess $account | Out-Null }
                }
                New-NetFirewallRule -Name $state.FirewallName -DisplayName 'Mobile SMB access' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -RemoteAddress '10.0.0.0/8' -Profile Any | Out-Null
                Set-BootTask
                $state.Status = 'PreparedPendingReboot'
            } elseif ($Mode -eq 'Restore') {
                if (-not $state -or $state.Status -eq 'Restored') { return $state }
                foreach ($share in $state.Shares) {
                    $existing = Get-SmbShare -Name $share.Name -ErrorAction SilentlyContinue
                    if (-not $existing) { continue }
                    if ($existing.Path -ine "$($share.Name):\") { throw "Share '$($share.Name)' changed outside deployment; inspect before cleanup." }
                    if ($share.Created) { Remove-SmbShare -Name $share.Name -Force }
                    else {
                        $account = "$env:COMPUTERNAME\$($state.UserName)"
                        Revoke-SmbShareAccess -Name $share.Name -AccountName $account -Force
                        foreach ($access in $share.OriginalAllow) { Grant-SmbShareAccess -Name $share.Name -AccountName $account -AccessRight $access -Force | Out-Null }
                    }
                }
                if ($state.UserSid) {
                    foreach ($drive in $state.AclDrives) {
                        $path = "${drive}:\"; $acl = Get-Acl -LiteralPath $path
                        $snapshot = $state.AclSnapshots | Where-Object Drive -eq $drive | Select-Object -First 1
                        if ($snapshot) { Restore-AccountRules $acl $snapshot }
                        elseif ($state.AccountOwned) { $acl.PurgeAccessRules([Security.Principal.SecurityIdentifier]::new($state.UserSid)) } # Legacy owned account.
                        else { continue }
                        Set-Acl -LiteralPath $path -AclObject $acl
                    }
                }
                if ($state.UserSid) {
                    $inf = Join-Path $Root 'rights.inf'; $db = Join-Path $Root 'rights.sdb'
                    & secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw 'Could not read logon rights for cleanup.' }
                    $cfg = Get-Content -LiteralPath $inf -Raw
                    $sidToken = "*$($state.UserSid)"
                    $addedRights = @($state.AddedRights)
                    if (-not $state.PSObject.Properties['AddedRights'] -and $state.AccountOwned) { $addedRights = @('SeNetworkLogonRight','SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight') }
                    $cfg = [regex]::Replace($cfg, '(?m)^(Se\w+Right\s*=\s*)([^\r\n]*)', {
                        param($match)
                        if (($match.Groups[1].Value -split '\s*=')[0] -notin $addedRights) { return $match.Value }
                        $match.Groups[1].Value + ((@($match.Groups[2].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne $sidToken })) -join ',')
                    })
                    $cfg | Set-Content -LiteralPath $inf -Encoding Unicode
                    & secedit /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw 'Could not remove SMB account logon rights.' }
                }
                if ($state.AccountOwned) {
                    $user = Get-LocalUser -Name $state.UserName -ErrorAction SilentlyContinue
                    if ($user -and $user.SID.Value -ne $state.UserSid) { throw 'SMB account identity changed; inspect before cleanup.' }
                    if ($user) { Remove-LocalUser -Name $state.UserName }
                }
                elseif ($state.AccountWasEnabled -eq $false) {
                    $user = Get-LocalUser -Name $state.UserName -ErrorAction SilentlyContinue
                    if ($user -and $user.SID.Value -ne $state.UserSid) { throw 'SMB account identity changed; inspect before cleanup.' }
                    if ($user -and $user.Enabled) { Disable-LocalUser -Name $state.UserName }
                }
                Get-NetFirewallRule -Name $state.FirewallName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
                Set-BootTask
                $state.Status = 'RestorePendingReboot'
            }
            $state.Error = $null
            Save-State
            $state
        } catch {
            if ($state) { $state.Error = $_.Exception.Message; if ($Mode -eq 'Restore') { $state.Status = "${Mode}Failed" }; Save-State }
            throw
        } finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
    }
}
