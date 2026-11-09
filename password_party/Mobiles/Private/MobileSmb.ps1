# Controller-side SMB selection, saved deployment records, coordination and status.

function Get-MobileSmbId {
    param([Parameter(Mandatory)][string]$MobileName)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($MobileName.ToLowerInvariant())))).Replace('-', '').Substring(0, 20).ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Resolve-MobileSmbHosts {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$MobileData, [AllowEmptyCollection()][string[]]$SmbHosts)
    $available = @($MobileData.Windows | Sort-Object -Unique)
    if (-not $available.Count) { throw 'SMB storage selection requires Windows computers in the mobile.' }
    $valid = @(); $invalid = @()
    foreach ($name in $SmbHosts) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $match = @($available | Where-Object { $_ -ieq $name.Trim() })
        if ($match.Count) { $valid += $match[0] } elseif (-not [string]::IsNullOrWhiteSpace($name)) { $invalid += $name }
    }
    if (-not $valid.Count -or $invalid.Count) {
        if ($invalid.Count) { Write-Warning "SMB hosts outside this mobile: $($invalid -join ', '). Select from the mobile's Windows computers." }
        $valid = @(Show-TerminalMultiPicker -Title 'Windows storage hosts to mount on Linux' -Options $available -SelectedOptions $valid)
    }
    if (-not $valid.Count) { throw 'No SMB storage hosts selected; checkout stopped before provisioning.' }
    foreach ($name in ($valid | Sort-Object -Unique)) {
        if ($name -notin $available) { throw "Invalid SMB host selection '$name'." }
        $name
    }
}

function Select-MobileSmbInterface {
    param([Parameter(Mandatory)][string]$HostName, [Parameter(Mandatory)][array]$Candidates)
    $candidates10 = @($Candidates | Where-Object { $_.IPAddress -match '^10\.(?:\d{1,3}\.){2}\d{1,3}$' })
    if (-not $candidates10.Count) { throw "${HostName}: no active interface with a 10.x IPv4 address. Configure the deployment interface before checkout." }
    if ($candidates10.Count -eq 1) { return $candidates10[0] }
    foreach ($candidate in $candidates10) {
        $candidate | Add-Member -NotePropertyName DisplayText -NotePropertyValue "$($candidate.InterfaceName): $($candidate.IPAddress)/$($candidate.PrefixLength)" -Force
    }
    $picked = Show-TerminalSinglePicker -Title "Deployment interface on $HostName" -Options $candidates10 -DisplayProperty DisplayText
    if (-not $picked -or $picked.IPAddress -notin $candidates10.IPAddress) { throw "${HostName}: interface selection cancelled." }
    $picked
}

function Get-MobileSmbMountPlan {
    param([Parameter(Mandatory)][array]$Windows, [Parameter(Mandatory)][string[]]$SmbHosts)
    foreach ($name in $SmbHosts) {
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw "Unsafe SMB hostname '$name'." }
        $hostInfo = @($Windows | Where-Object HostName -eq $name)
        if ($hostInfo.Count -ne 1) { throw "Missing or duplicate SMB inventory for '$name'." }
        $ip = [Net.IPAddress]::Parse($hostInfo[0].Interface.IPAddress)
        if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.GetAddressBytes()[0] -ne 10) { throw "Invalid storage IPv4 address for '$name'." }
        foreach ($drive in $hostInfo[0].Drives) {
            if ($drive -notmatch '^[A-Z]$') { throw "Invalid drive '$drive' on '$name'." }
            $authority = if ($hostInfo[0].LocalAuthority) { [string]$hostInfo[0].LocalAuthority } else { $name.Split('.')[0] }
            if ($authority -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw "Invalid local account authority on '$name'." }
            [pscustomobject]@{ HostName = $name; CredentialDomain = $authority; IPAddress = $ip.ToString(); Share = $drive; Source = "//$ip/$drive"; MountPoint = "/share/$name/$drive" }
        }
        if (-not @($hostInfo[0].Drives).Count) { throw "No fixed drives discovered on '$name'." }
    }
}

function Get-MobileSmbPlanPath {
    param([Parameter(Mandatory)][string]$MobileName)
    Join-Path (Join-Path $script:Config.MobileDeployments 'smb') ((Get-MobileSmbId $MobileName) + '.json')
}

function Save-MobileSmbPlan {
    param([Parameter(Mandatory)]$Plan)
    $path = Get-MobileSmbPlanPath $Plan.MobileName
    New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force | Out-Null
    $Plan | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath "$path.tmp" -Encoding UTF8
    Move-Item -LiteralPath "$path.tmp" -Destination $path -Force
}

function Read-MobileSmbPlan {
    param([Parameter(Mandatory)][string]$MobileName)
    $path = Get-MobileSmbPlanPath $MobileName
    if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
}

function ConvertFrom-MobileSmbLinuxResult {
    param([Parameter(Mandatory)]$Result)
    if ($Result.ExitCode -ne 0 -or -not $Result.StdOut) { throw "SMB SSH operation failed on $($Result.Target) (exit $($Result.ExitCode)): $($Result.StdErr)" }
    try { $Result.StdOut | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Invalid SMB response from $($Result.Target)." }
}

function Initialize-MobileSmbDeployment {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$MobileData, [Parameter(Mandatory)][string]$MobileName,
        [string[]]$SmbHosts, [pscredential]$SmbCredential, [Parameter(Mandatory)]$Run)
    $previous = Read-MobileSmbPlan $MobileName
    if ($previous -and $previous.Status -ne 'Restored') { throw 'This mobile already has saved SMB state. Use -SmbStatus or check it in before preparing again.' }
    $userName = [string]$script:Config.SMBUser
    if ($userName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,19}$') { throw 'SMBUser must be a Windows local account name of 1-20 letters, digits, dots, underscores or hyphens.' }
    if ($userName -in @($MobileData.AllUsers.Name)) { throw 'SMBUser must be distinct from mobile user accounts.' }
    $linuxGroup = if ($script:Config.SMBLinuxGroup) { [string]$script:Config.SMBLinuxGroup } else { 'users' }
    if ($linuxGroup -notmatch '^[a-z_][a-z0-9_-]*[$]?$') { throw 'SMBLinuxGroup must be a Linux group name.' }
    $storageHosts = @()
    if (@($MobileData.Linux).Count) { $storageHosts = @(Resolve-MobileSmbHosts -MobileData $MobileData -SmbHosts $SmbHosts) }
    if ($SmbHosts -and -not @($MobileData.Linux).Count) { throw '-SmbHosts selects storage for Linux; this mobile has no Linux computers.' }
    $windows = @(
        foreach ($computer in $MobileData.Windows) {
            $inventory = @(Invoke-Command -ComputerName $computer -ScriptBlock (Get-WindowsMobileSmbInventory) -ArgumentList $userName -ErrorAction Stop)
            if ($inventory.Count -ne 1 -or -not @($inventory[0].Drives).Count) { throw "Incomplete SMB inventory from '$computer'." }
            if ($inventory[0].AccountExists) { Write-Host "[+] $computer will reuse SMB account '$userName'; supply its current password." }
            [pscustomobject]@{ HostName = $computer; Interface = (Select-MobileSmbInterface -HostName $computer -Candidates @($inventory[0].Interfaces)); Drives = @($inventory[0].Drives); LocalAuthority = $inventory[0].LocalAuthority; Status = 'NotPrepared' }
        }
    )
    $linux = @(
        foreach ($computer in $MobileData.Linux) {
            $raw = @(Invoke-Linux -Computers @($computer) -Script (Get-LinuxMobileSmbInventory) -KeyPath $script:Config.SSHKeyPath)
            if ($raw.Count -ne 1) { throw "No SMB interface inventory from '$computer'." }
            $inventory = ConvertFrom-MobileSmbLinuxResult $raw[0]
            [pscustomobject]@{ HostName = $computer; Interface = (Select-MobileSmbInterface -HostName $computer -Candidates @($inventory.Interfaces)); Status = 'NotPrepared' }
        }
    )
    $mounts = @()
    if ($storageHosts.Count) { $mounts = @(Get-MobileSmbMountPlan -Windows $windows -SmbHosts $storageHosts) }
    $allHosts = @($windows) + @($linux)
    if (@($allHosts.Interface.IPAddress | Sort-Object -Unique).Count -ne $allHosts.Count) { throw 'Selected deployment interfaces have duplicate IPv4 addresses.' }
    # Isolated deployments have no assumed router. Verify direct reachability in both directions.
    foreach ($client in $allHosts) {
        $prefix = [int]$client.Interface.PrefixLength
        if ($prefix -lt 1 -or $prefix -gt 30) { throw "Unsupported deployment prefix on $($client.HostName)." }
        $own = [Net.IPAddress]::Parse($client.Interface.IPAddress).GetAddressBytes()
        foreach ($server in $allHosts) {
            $other = [Net.IPAddress]::Parse($server.Interface.IPAddress).GetAddressBytes()
            for ($bit = 0; $bit -lt $prefix; $bit++) {
                $mask = 1 -shl (7 - ($bit % 8)); $index = [int][math]::Floor($bit / 8)
                if (($own[$index] -band $mask) -ne ($other[$index] -band $mask)) { throw "$($client.HostName) and $($server.HostName) are outside the selected interface's subnet; an isolated routed network must be configured explicitly." }
            }
        }
    }
    if (-not $SmbCredential) {
        $password = Read-Host -Prompt "Password for deployment SMB account '$userName'" -AsSecureString
        $SmbCredential = [pscredential]::new($userName, $password)
    }
    if ($SmbCredential.UserName -ine $userName) { throw "The SMB credential username must match configured SMBUser '$userName'." }
    $clearPassword = $SmbCredential.GetNetworkCredential().Password
    if ([string]::IsNullOrEmpty($clearPassword) -or $clearPassword -match '[\r\n]') { throw 'SMB passwords must be nonempty and cannot contain line breaks.' }
    $clearPassword = $null
    $plan = [pscustomobject]@{ Version = 1; Id = Get-MobileSmbId $MobileName; MobileName = $MobileName
        Status = 'Preparing'; UserName = $userName; LinuxGroup = $linuxGroup; StorageHosts = $storageHosts
        Windows = @($windows); Linux = @($linux); Mounts = @($mounts) }
    Save-MobileSmbPlan $plan
    Write-MobileRunEvent -Run $Run -Event 'SmbPlan' -Data $plan # Contains no credentials or worker source.
    try {
        foreach ($hostInfo in $plan.Windows) {
            $root = "C:\ProgramData\Mobiles\Smb\$($plan.Id)"
            $options = Get-WindowsSmbTaskOptions -Root $root -Mode Activate
            $options | Add-Member -NotePropertyMembers @{ Id = $plan.Id; UserName = $userName; Interface = $hostInfo.Interface; Drives = $hostInfo.Drives }
            $result = Invoke-Command -ComputerName $hostInfo.HostName -ScriptBlock (Get-WindowsMobileSmbWorker) -ArgumentList 'Prepare', $root, $options, $SmbCredential -ErrorAction Stop
            if ($result.Status -ne 'PreparedPendingReboot') { throw "SMB preparation did not complete on $($hostInfo.HostName)." }
            $hostInfo.Status = $result.Status
            $hostInfo | Add-Member -NotePropertyName State -NotePropertyValue $result -Force
            Save-MobileSmbPlan $plan
            Write-MobileRunEvent -Run $Run -Event 'SmbPrepared' -Data @{ HostName = $hostInfo.HostName; Platform = 'Windows'; State = $result }
        }
        foreach ($hostInfo in $plan.Linux) {
            $options = [pscustomobject]@{ UserName = $userName; Interface = $hostInfo.Interface; Mounts = $plan.Mounts; LinuxGroup = $linuxGroup; LinuxUsers = @($MobileData.AllUsers | Where-Object { $null -ne $_.LinuxAccountType } | ForEach-Object LinuxName | Sort-Object -Unique) }
            $scriptText = Get-LinuxMobileSmbScript -Mode Prepare -Id $plan.Id -Options $options -Credential $SmbCredential
            $raw = @(Invoke-Linux -Computers @($hostInfo.HostName) -Script $scriptText -KeyPath $script:Config.SSHKeyPath)
            if ($raw.Count -ne 1) { throw "No SMB preparation response from $($hostInfo.HostName)." }
            $result = ConvertFrom-MobileSmbLinuxResult $raw[0]
            if ($result.Status -ne 'PreparedPendingReboot') { throw "SMB preparation did not complete on $($hostInfo.HostName)." }
            $hostInfo.Status = $result.Status
            $hostInfo | Add-Member -NotePropertyName State -NotePropertyValue $result -Force
            Save-MobileSmbPlan $plan
            Write-MobileRunEvent -Run $Run -Event 'SmbPrepared' -Data @{ HostName = $hostInfo.HostName; Platform = 'Linux'; State = $result }
        }
        $plan.Status = 'PreparedPendingReboot'
        Save-MobileSmbPlan $plan
        Write-Host '[+] SMB prepared. Disconnect the mobile from the domain network before rebooting; static addressing and mounts activate at boot.'
        $plan
    } catch { $plan.Status = 'PreparationFailed'; Save-MobileSmbPlan $plan; throw }
}

function Invoke-MobileSmbCheckInHooks {
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)]$Run, [array]$WindowsHooks, [array]$LinuxHooks)
    foreach ($hostInfo in $Plan.Windows) {
        if (-not $WindowsHooks.Count) { break }
        $result = Invoke-Command -ComputerName $hostInfo.HostName -ScriptBlock (Get-WindowsProcedureHookRunner) `
            -ArgumentList $WindowsHooks, $Plan.MobileName, 'Check-in', $Run.Id -ErrorAction Stop
        Write-MobileRunEvent -Run $Run -Event 'HostResult' -Data @{ HostName = $hostInfo.HostName; Platform = 'Windows'; Success = (-not $result.Failures.Count); Actions = $result.Actions; Failures = $result.Failures }
        if ($result.Failures.Count) { throw "Check-in hooks failed on $($hostInfo.HostName); SMB cleanup was not started." }
    }
    foreach ($hostInfo in $Plan.Linux) {
        if (-not $LinuxHooks.Count) { break }
        $scriptText = Get-LinuxProcedureHookScript -Hooks $LinuxHooks -MobileName $Plan.MobileName `
            -Procedure Check-in -RunId $Run.Id -Standalone -ToolPath (Get-MobileSmbToolPath)
        $raw = @(Invoke-Linux -Computers @($hostInfo.Interface.IPAddress) -Script $scriptText -KeyPath $script:Config.SSHKeyPath)
        if ($raw.Count -ne 1) { throw "No hook response from $($hostInfo.HostName)." }
        $result = ConvertFrom-MobileSmbLinuxResult $raw[0]
        Write-MobileRunEvent -Run $Run -Event 'HostResult' -Data @{ HostName = $hostInfo.HostName; Platform = 'Linux'; Success = (-not $result.Failures.Count); Actions = $result.Actions; Failures = $result.Failures }
        if ($result.Failures.Count) { throw "Check-in hooks failed on $($hostInfo.HostName); SMB cleanup was not started." }
    }
}

function Restore-MobileSmbDeployment {
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)]$Run)
    # Storage must remain available until every Linux client has unmounted successfully.
    foreach ($hostInfo in $Plan.Linux) {
        $raw = @(Invoke-Linux -Computers @($hostInfo.Interface.IPAddress) -Script (Get-LinuxMobileSmbScript -Mode Restore -Id $Plan.Id) -KeyPath $script:Config.SSHKeyPath)
        if ($raw.Count -ne 1) { throw "No SMB restoration response from $($hostInfo.HostName)." }
        $result = ConvertFrom-MobileSmbLinuxResult $raw[0]
        if ($result.Status -notin @('RestorePendingReboot','Restored','NotPrepared')) { throw "SMB restoration incomplete on $($hostInfo.HostName)." }
        $hostInfo.Status = $result.Status
        $hostInfo | Add-Member -NotePropertyName State -NotePropertyValue $result -Force
        Save-MobileSmbPlan $Plan
        Write-MobileRunEvent -Run $Run -Event 'SmbRestored' -Data @{ HostName = $hostInfo.HostName; Platform = 'Linux'; State = $result }
    }
    foreach ($hostInfo in $Plan.Windows) {
        $root = "C:\ProgramData\Mobiles\Smb\$($Plan.Id)"
        $result = Invoke-Command -ComputerName $hostInfo.HostName -ScriptBlock (Get-WindowsMobileSmbWorker) -ArgumentList 'Restore', $root, (Get-WindowsSmbTaskOptions -Root $root -Mode RestoreBoot) -ErrorAction Stop
        if ($result.Status -notin @('RestorePendingReboot','Restored') -and $null -ne $result) { throw "SMB restoration incomplete on $($hostInfo.HostName)." }
        $hostInfo.Status = if ($result) { $result.Status } else { 'NotPrepared' }
        $hostInfo | Add-Member -NotePropertyName State -NotePropertyValue $result -Force
        Save-MobileSmbPlan $Plan
        Write-MobileRunEvent -Run $Run -Event 'SmbRestored' -Data @{ HostName = $hostInfo.HostName; Platform = 'Windows'; State = $result }
    }
    $Plan.Status = 'RestorePendingReboot'
    Save-MobileSmbPlan $Plan
    Write-Host '[+] SMB cleanup staged. Reboot all hosts to restore original networking and Linux FIPS enforcement; query -SmbStatus afterward.'
}

function Show-MobileSmbStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$MobileName, [switch]$VerifyMounts)
    $plan = Read-MobileSmbPlan $MobileName
    if (-not $plan) { throw "No saved SMB deployment for '$MobileName'." }
    $run = New-MobileRunLog -MobileName $MobileName -Procedure 'SMB-Status'
    $linuxMode = if ($VerifyMounts) { 'Verify' } else { 'Status' }
    $states = @(
        foreach ($hostInfo in $plan.Windows) {
            try {
                $root = "C:\ProgramData\Mobiles\Smb\$($plan.Id)"
                $state = Invoke-Command -ComputerName $hostInfo.HostName -ScriptBlock (Get-WindowsMobileSmbWorker) -ArgumentList 'Status', $root -ErrorAction Stop
                $hostInfo.Status = $state.Status
                if ($state.Status -notin @('Busy','NotPrepared')) { $hostInfo | Add-Member -NotePropertyName State -NotePropertyValue $state -Force }
                [pscustomobject]@{ HostName = $hostInfo.HostName; IPAddress = $hostInfo.Interface.IPAddress; Platform = 'Windows'; Status = $state.Status; Details = $state }
            } catch { [pscustomobject]@{ HostName = $hostInfo.HostName; IPAddress = $hostInfo.Interface.IPAddress; Platform = 'Windows'; Status = 'Unreachable'; Details = $_.Exception.Message } }
        }
        foreach ($hostInfo in $plan.Linux) {
            try {
                $raw = @(Invoke-Linux -Computers @($hostInfo.HostName) -Script (Get-LinuxMobileSmbScript -Mode $linuxMode -Id $plan.Id) -KeyPath $script:Config.SSHKeyPath)
                if ($raw.Count -ne 1 -or $raw[0].ExitCode -ne 0) { $raw = @(Invoke-Linux -Computers @($hostInfo.Interface.IPAddress) -Script (Get-LinuxMobileSmbScript -Mode $linuxMode -Id $plan.Id) -KeyPath $script:Config.SSHKeyPath) }
                if ($raw.Count -ne 1) { throw 'No response.' }
                $state = ConvertFrom-MobileSmbLinuxResult $raw[0]
                $hostInfo.Status = $state.Status
                if ($state.Status -notin @('Busy','NotPrepared')) { $hostInfo | Add-Member -NotePropertyName State -NotePropertyValue $state -Force }
                [pscustomobject]@{ HostName = $hostInfo.HostName; IPAddress = $hostInfo.Interface.IPAddress; Platform = 'Linux'; Status = $state.Status; Details = $state }
            } catch { [pscustomobject]@{ HostName = $hostInfo.HostName; IPAddress = $hostInfo.Interface.IPAddress; Platform = 'Linux'; Status = 'Unreachable'; Details = $_.Exception.Message } }
        }
    )
    if ($states.Count -and @($states | Where-Object Status -ne Restored).Count -eq 0) { $plan.Status = 'Restored' }
    Save-MobileSmbPlan $plan # Keep the last reachable host snapshots when a host is offline.
    foreach ($state in $states) { Write-MobileRunEvent -Run $run -Event 'SmbStatus' -Data $state }
    Write-MobileRunEvent -Run $run -Event 'RunCompleted' -Data @{ Success = (@($states | Where-Object { $_.Status -notin @('Active','Restored') }).Count -eq 0) }
    Write-Host "[+] SMB status audit log: $($run.ReadablePath)"
    $states
}
