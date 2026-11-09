# Offline SMB workflow checks. Native networking, boot, mount and share commands are mocked.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobiles-smb-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join '; ') }
$statements = @($ast.EndBlock.Statements)
$smbAsts = @(foreach ($file in @('WindowsSmb.ps1','LinuxSmb.ps1','MobileSmb.ps1')) {
    $smbAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root "Private/$file"), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ($errors.Message -join '; ') }
    $statements += $smbAst.EndBlock.Statements
    $smbAst
})
$names = @('Get-MobileSmbToolPath','Get-MobileSmbId','Resolve-MobileSmbHosts','Select-MobileSmbInterface','Get-MobileSmbMountPlan',
    'Get-LinuxProcedureHookScript','Get-WindowsSmbBootScript','Get-WindowsSmbTaskOptions','Get-WindowsMobileSmbInventory','Get-LinuxMobileSmbInventory','Get-WindowsMobileSmbWorker','New-LinuxTask-SmbGroup','Get-LinuxSmbSessionScript','Get-LinuxSmbNetworkScript','Get-LinuxSmbBootScript','Get-LinuxSmbMountScript','Get-LinuxSmbGroupScript','Get-LinuxSmbStatusScript','Get-LinuxMobileSmbScript',
    'Get-MobileSmbPlanPath','Save-MobileSmbPlan','Read-MobileSmbPlan','ConvertFrom-MobileSmbLinuxResult','Initialize-MobileSmbDeployment',
    'Invoke-MobileSmbCheckInHooks','Restore-MobileSmbDeployment','Show-MobileSmbStatus','ConvertTo-BashArgument','New-MobileRunLog','Write-MobileRunEvent','Format-MobileRunEvent','ConvertTo-MobileLogLines')
$source = $statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -in $names } | ForEach-Object { $_.Extent.Text }
$nested = $smbAsts[0].FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Initialize-SmbAccount','Get-AccountRules','Restore-AccountRules','New-SmbAccountRule') }, $true) | ForEach-Object { $_.Extent.Text }
$source = @($source) + @($nested)
$windowsSource = (($source -join "`n").Replace("`r`n", "`n")).Replace("`n", "`r`n")
$windowsModule = New-Module -ScriptBlock ([scriptblock]::Create($windowsSource))
try {
    $normalized = & $windowsModule {
        $script:Config=[pscustomobject]@{ Preflight=@{} }
        Get-LinuxMobileSmbScript -Mode Status -Id ('0'*20)
    }
    if ($normalized.Contains("`r")) { throw 'Windows checkout emitted CRLF to the Linux command stream' }
} finally { Remove-Module $windowsModule -ErrorAction SilentlyContinue }
$module = New-Module -ScriptBlock ([scriptblock]::Create($source -join "`n"))
try {
    & $module {
        param($fixture, $root, $source)
        function Assert($condition, $message) { if (-not $condition) { throw $message } }
        $script:Config = [pscustomobject]@{ SMBUser = 'configured-smb'; SMBLinuxGroup = 'users'; SSHKeyPath = "$fixture/key"; MobileDeployments = "$fixture/logs"
            Preflight = @{ LinuxToolDirectories = @('/usr/local/sbin','/usr/local/bin','/usr/sbin','/usr/bin','/sbin','/bin') } }
        $script:pickerCalls = 0
        function Show-TerminalMultiPicker { param($Title,$Options,$SelectedOptions)
            $script:pickerCalls++; $script:pickerOptions = $Options; $script:preselected = $SelectedOptions; @('WIN-A','WIN-B') }
        $data = [pscustomobject]@{ Windows = @('WIN-A','WIN-B'); Linux = @('LINUX-A'); AllUsers = @() }
        Assert ((@(Resolve-MobileSmbHosts $data @('win-b','WIN-B')) -join ',') -eq 'WIN-B' -and $script:pickerCalls -eq 0) 'Valid case-insensitive host names should not prompt'
        $selected = @(Resolve-MobileSmbHosts $data @('WIN-A','typo'))
        Assert ($selected.Count -eq 2 -and $script:pickerCalls -eq 1 -and $script:preselected -contains 'WIN-A' -and $script:pickerOptions.Count -eq 2) 'Invalid input did not open the mobile-scoped picker preserving valid selections'
        $selected = @(Resolve-MobileSmbHosts $data @(''))
        Assert ($selected.Count -eq 2 -and $script:pickerCalls -eq 2) 'Blank input did not open the picker'
        function Show-TerminalSinglePicker { param($Title,$Options,$DisplayProperty) $Options[1] }
        $nic = Select-MobileSmbInterface WIN-A @([pscustomobject]@{ InterfaceName='a'; IPAddress='10.2.3.4'; PrefixLength=24 })
        Assert ($nic.IPAddress -eq '10.2.3.4') 'Unique 10.x NIC was not selected'
        $rejected = $false; try { Select-MobileSmbInterface WIN-A @([pscustomobject]@{ IPAddress='192.168.1.2' }) } catch { $rejected = $true }
        Assert $rejected 'Missing 10.x interface was silently accepted'
        $nic2 = Select-MobileSmbInterface WIN-A @($nic, [pscustomobject]@{ InterfaceName='b'; IPAddress='10.2.3.5'; PrefixLength=24 })
        Assert ($nic2.InterfaceName -eq 'b') 'Ambiguous interface selection was ignored'
        $inventory = @([pscustomobject]@{ HostName='WIN-A'; Interface=$nic; Drives=@('C','D') }, [pscustomobject]@{ HostName='WIN-B'; Interface=$nic2; Drives=@('E') })
        $mounts = @(Get-MobileSmbMountPlan $inventory @('WIN-A','WIN-B'))
        Assert ($mounts.Count -eq 3 -and $mounts[0].Source -eq '//10.2.3.4/C' -and $mounts[0].MountPoint -eq '/share/WIN-A/C' -and $mounts[2].Source -eq '//10.2.3.5/E') 'Mounts did not use numeric host IPs and /share/hostname/drive'
        $fqdn = [pscustomobject]@{ HostName='WIN-A.example.test'; LocalAuthority='WIN-A'; Interface=$nic; Drives=@('C') }
        $fqdnMount = Get-MobileSmbMountPlan @($fqdn) @('WIN-A.example.test')
        Assert ($fqdnMount.Source -eq '//10.2.3.4/C' -and $fqdnMount.CredentialDomain -eq 'WIN-A') 'FQDN inventory did not preserve the local account authority'
        function Show-TerminalMultiPicker { param($Title,$Options,$SelectedOptions) @() }
        $rejected = $false; try { Resolve-MobileSmbHosts $data @() } catch { $rejected = $true }
        Assert $rejected 'Cancelling SMB selection did not stop checkout'
        $credential = [pscredential]::new('configured-smb', (ConvertTo-SecureString 'fixture-pass' -AsPlainText -Force))
        $windowsWorker = Get-WindowsMobileSmbWorker
        $windowsBoot = Get-WindowsSmbBootScript
        # The existing XML builder is Windows COM-based; verify its caller's exact inputs offline.
        function New-TaskXML {
            param($Description,$Execute,$Arguments,$TriggerConfigs,$ExecutionTimeLimit)
            Assert ($Execute -eq 'powershell.exe' -and $ExecutionTimeLimit -eq 'PT2M') 'SMB task did not use the shared XML builder'
            Assert ($TriggerConfigs.Count -eq 1 -and $TriggerConfigs[0].Type -eq 8 -and $TriggerConfigs[0].EndBoundary -eq '') 'SMB startup trigger expires before an offline reboot'
            '<Task><Arguments>' + [Security.SecurityElement]::Escape($Arguments) + '</Arguments></Task>'
        }
        $bootOptions = Get-WindowsSmbTaskOptions -Root 'C:\ProgramData\Mobiles\Smb\fixture' -Mode Activate
        Assert ($bootOptions.TaskXml.Contains('boot.ps1') -and -not $bootOptions.BootScript.Contains('New-LocalUser') -and -not $bootOptions.BootScript.Contains('Register-ScheduledTask') -and -not $bootOptions.BootScript.Contains('New-SmbShare')) 'Startup still installs the provisioning worker'

        Assert (-not $windowsWorker.ToString().Contains('mobile-smb-access') -and -not $windowsWorker.ToString().Contains('SupeSecret')) 'Windows worker still embeds hardcoded credentials'
        # Run the actual account helper, independently of Windows-only ACL APIs.
        $state = [pscustomobject]@{ UserName='configured-smb'; UserSid=$null; AccountOwned=$false; AccountWasEnabled=$false }
        $script:existingAccount = [pscustomobject]@{ Name='configured-smb'; Enabled=$true; SID=[pscustomobject]@{ Value='fixture-sid' } }
        $script:createdAccounts=0; $script:enabledAccounts=0
        function Save-State { }
        function Get-LocalUser { [CmdletBinding()] param($Name) $script:existingAccount }
        function New-LocalUser { [CmdletBinding()] param($Name,$Password,$Description,[switch]$AccountNeverExpires,[switch]$PasswordNeverExpires)
            $script:createdAccounts++; $script:existingAccount=[pscustomobject]@{ Name=$Name; Enabled=$true; SID=[pscustomobject]@{ Value='new-fixture-sid' } } }
        function Set-LocalUser { throw 'An existing SMB password must not be reset' }
        function Enable-LocalUser { param($Name) $script:enabledAccounts++ }
        Initialize-SmbAccount
        Assert (-not $state.AccountOwned -and $state.AccountWasEnabled -and $script:createdAccounts -eq 0) 'Existing SMB account was rejected or recreated'
        $script:existingAccount.Enabled=$false
        Initialize-SmbAccount
        Assert (-not $state.AccountOwned -and -not $state.AccountWasEnabled -and $script:enabledAccounts -eq 1) 'Disabled account was not enabled with its original state recorded'
        $script:existingAccount=$null
        Initialize-SmbAccount
        Assert ($state.AccountOwned -and $script:createdAccounts -eq 1) 'Missing SMB account was not created'

        # Exercise the actual Windows network worker with native cmdlets mocked.
        $winRoot = "$fixture/windows-state"
        New-Item -ItemType Directory $winRoot | Out-Null
        $winState = [pscustomobject]@{ Status='PreparedPendingReboot'; UpdatedUtc=''; Error=$null; UserName='configured-smb'; UserSid=$null; AccountOwned=$false
            Interface=[pscustomobject]@{ InterfaceGuid='fixture-guid'; IPAddress='10.2.3.4'; PrefixLength=24 }; OriginalDhcp='Enabled'; OriginalDnsStatic=''
            Shares=@(); AclDrives=@(); FirewallName='fixture-firewall'; TaskName='fixture-task' }
        $winState | ConvertTo-Json -Depth 8 | Set-Content "$winRoot/state.json"
        $script:networkCalls = @(); $script:scheduledMode = ''
        function Get-NetAdapter { [pscustomobject]@{ InterfaceGuid='fixture-guid'; InterfaceIndex=7 } }
        function Get-NetIPAddress { [CmdletBinding()] param($InterfaceIndex,$AddressFamily,$IPAddress)
            [pscustomobject]@{ IPAddress=$IPAddress; PrefixOrigin='Dhcp'; InterfaceIndex=$InterfaceIndex; AddressState='Preferred'; PrefixLength=24 } }
        function Remove-NetIPAddress { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject,[switch]$Confirm)
            process { $script:networkCalls += "Remove:$($InputObject.InterfaceIndex)" } }
        function New-NetIPAddress { [CmdletBinding()] param($InterfaceIndex,$IPAddress,$PrefixLength) $script:networkCalls += "Static:${InterfaceIndex}:$IPAddress/$PrefixLength" }
        function Set-NetIPInterface { [CmdletBinding()] param($InterfaceIndex,$AddressFamily,$Dhcp) $script:networkCalls += "Dhcp:${InterfaceIndex}:$Dhcp" }
        function Set-DnsClientServerAddress { [CmdletBinding()] param($InterfaceIndex,$ServerAddresses,[switch]$ResetServerAddresses) $script:networkCalls += "Dns:${InterfaceIndex}:$ResetServerAddresses" }
        function Get-NetFirewallRule { [CmdletBinding()] param($Name) }
        function Remove-NetFirewallRule { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) }
        function Register-ScheduledTask {
            [CmdletBinding()] param($TaskName,$Xml,$User,[switch]$Force)
            $script:scheduledMode = $Xml
        }
        function Unregister-ScheduledTask { [CmdletBinding()] param($TaskName,[switch]$Confirm) }
        $savedSystemRoot = $env:SystemRoot; $env:SystemRoot = "$fixture/windows"
        try {
            $active = & $windowsBoot Activate $winRoot
            Assert ($active.Status -eq 'Active' -and $script:networkCalls -contains 'Static:7:10.2.3.4/24' -and $script:networkCalls -contains 'Dhcp:7:Disabled') 'Windows DHCP address was not frozen on the selected adapter'
            'legacy full worker' | Set-Content (Join-Path $winRoot 'worker.ps1')
            $restore = & $windowsWorker Restore $winRoot (Get-WindowsSmbTaskOptions -Root $winRoot -Mode RestoreBoot)
            Assert (-not (Test-Path (Join-Path $winRoot 'worker.ps1')) -and $script:scheduledMode.Contains('boot.ps1')) 'Legacy startup task did not migrate to the smaller boot action'
            Assert ($restore.Status -eq 'RestorePendingReboot' -and $script:scheduledMode.Contains('-Mode RestoreBoot') -and $script:networkCalls -notcontains 'Dhcp:7:Enabled') 'Windows check-in changed the network in the live session'
            $restored = & ([scriptblock]::Create((Get-Content (Join-Path $winRoot 'boot.ps1') -Raw))) -Mode RestoreBoot -Root $winRoot
            Assert ($restored.Status -eq 'Restored' -and $script:networkCalls -contains 'Dhcp:7:Enabled' -and $script:networkCalls -contains 'Dns:7:True') 'Windows startup did not restore DHCP/DNS'
            $winState.OriginalDhcp='Disabled'; $winState.Status='PreparedPendingReboot'
            $winState | ConvertTo-Json -Depth 8 | Set-Content "$winRoot/state.json"
            $script:networkCalls=@()
            $active = & $windowsBoot Activate $winRoot
            $restore = & $windowsWorker Restore $winRoot (Get-WindowsSmbTaskOptions -Root $winRoot -Mode RestoreBoot)
            $restored = & $windowsBoot RestoreBoot $winRoot
            Assert ($script:networkCalls.Count -eq 0) 'An originally static interface was changed to DHCP'
        } finally { $env:SystemRoot = $savedSystemRoot }

        # Reused accounts retain pre-existing share and logon permissions at check-in.
        $winState.Status='Active'; $winState.UserSid='fixture-sid'
        $winState | Add-Member AccountWasEnabled $true -Force
        $winState | Add-Member AddedRights @('SeDenyInteractiveLogonRight') -Force
        $winState.Shares=@([pscustomobject]@{ Name='C'; Created=$false; OriginalAllow=@('Read') })
        $winState | ConvertTo-Json -Depth 10 | Set-Content "$winRoot/state.json"
        $script:existingAccount=[pscustomobject]@{ Name='configured-smb'; Enabled=$true; SID=[pscustomobject]@{ Value='fixture-sid' } }
        $script:restoredShareAccess=@(); $script:disabledAccounts=0
        function Get-SmbShare { [CmdletBinding()] param($Name) [pscustomobject]@{ Path='C:\' } }
        function Revoke-SmbShareAccess { [CmdletBinding()] param($Name,$AccountName,[switch]$Force) }
        function Grant-SmbShareAccess { [CmdletBinding()] param($Name,$AccountName,$AccessRight,[switch]$Force) $script:restoredShareAccess += $AccessRight }
        function Remove-LocalUser { throw 'A reused SMB account must not be deleted' }
        function Disable-LocalUser { param($Name) $script:disabledAccounts++ }
        function secedit {
            $nativeArgs=@($args)
            $inf=$nativeArgs[[array]::IndexOf($nativeArgs,'/cfg')+1]
            if ($nativeArgs -contains '/export') { "[Privilege Rights]`nSeNetworkLogonRight = *fixture-sid,*other`nSeDenyInteractiveLogonRight = *fixture-sid,*other" | Set-Content $inf }
            else { $script:restoredRights=Get-Content $inf -Raw }
            $global:LASTEXITCODE=0
        }
        $savedSystemRoot=$env:SystemRoot; $env:SystemRoot="$fixture/windows"
        try {
            $restored = & $windowsWorker Restore $winRoot (Get-WindowsSmbTaskOptions -Root $winRoot -Mode RestoreBoot)
            Assert ($restored.Status -eq 'RestorePendingReboot' -and $script:restoredShareAccess -contains 'Read' -and $script:disabledAccounts -eq 0) 'Existing account/share access was not preserved'
            Assert ($script:restoredRights.Contains('SeNetworkLogonRight = *fixture-sid,*other') -and $script:restoredRights.Contains('SeDenyInteractiveLogonRight = *other')) 'Existing logon rights were removed with deployment-added rights'
            $winState.AccountWasEnabled=$false
            $winState | ConvertTo-Json -Depth 10 | Set-Content "$winRoot/state.json"
            $restored = & $windowsWorker Restore $winRoot (Get-WindowsSmbTaskOptions -Root $winRoot -Mode RestoreBoot)
            Assert ($script:disabledAccounts -eq 1) 'An account originally disabled was left enabled'
        } finally { $env:SystemRoot=$savedSystemRoot }
        # Restore only this account's NTFS rules; preserve other identities and detect external edits.
        $state.UserSid='fixture-sid'
        function New-SmbAccountRule($Rule) {
            [pscustomobject]@{ IdentityReference=[pscustomobject]@{ Value='fixture-sid' }; FileSystemRights=$Rule.Rights; AccessControlType=$Rule.Type; InheritanceFlags=$Rule.Inheritance; PropagationFlags=$Rule.Propagation }
        }
        $full=[pscustomobject]@{ Rights=2032127; Type=0; Inheritance=3; Propagation=0 }
        $read=[pscustomobject]@{ Rights=131209; Type=0; Inheritance=3; Propagation=0 }
        $foreign=New-SmbAccountRule $full; $foreign.IdentityReference.Value='other-sid'
        $acl=[pscustomobject]@{ Rules=@($foreign,(New-SmbAccountRule $full)) }
        $acl | Add-Member ScriptMethod GetAccessRules { param($explicit,$inherited,$type) $this.Rules }
        $acl | Add-Member ScriptMethod RemoveAccessRuleSpecific { param($rule) $this.Rules=@($this.Rules | Where-Object { $_ -ne $rule }) }
        $acl | Add-Member ScriptMethod AddAccessRule { param($rule) $this.Rules+= $rule }
        Restore-AccountRules $acl ([pscustomobject]@{ Drive='C'; Before=@($read); Applied=@($full) })
        Assert ($acl.Rules.Count -eq 2 -and @($acl.Rules | Where-Object { $_.IdentityReference.Value -eq 'fixture-sid' })[0].FileSystemRights -eq $read.Rights) 'Original per-account NTFS rights were lost'
        $rejected=$false
        try { Restore-AccountRules $acl ([pscustomobject]@{ Drive='C'; Before=@(); Applied=@($full) }) } catch { $rejected=$true }
        Assert $rejected 'External changes to the same account ACL were overwritten'

        if ((Get-Command bash -ErrorAction SilentlyContinue) -and (Get-Command jq -ErrorAction SilentlyContinue)) {
            $tools = "$fixture/tools"; $sandbox = "$fixture/endpoint"; $id = Get-MobileSmbId fixture
            New-Item -ItemType Directory -Path $tools, "$sandbox/etc/systemd/system", "$sandbox/boot", "$sandbox/run/lock", "$sandbox/proc/sys/crypto", "$sandbox/proc/sys/kernel/random", "$sandbox/share" | Out-Null
            $envNames = @('PATH','MOBILE_SMB_FIXTURE'); $savedEnv = @{}
            foreach ($name in $envNames) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name) }
            try {
                $env:MOBILE_SMB_FIXTURE = $sandbox
                'boot-before-checkout' | Set-Content "$sandbox/proc/sys/kernel/random/boot_id"
                @{ 'connection.autoconnect'='yes'; 'ipv4.method'='auto'; 'ipv4.addresses'=''; 'ipv4.dns'='10.2.3.1' } | ConvertTo-Json | Set-Content "$sandbox/network.json"
                '1' | Set-Content "$sandbox/proc/sys/crypto/fips_enabled"
                'kernel' | Set-Content "$sandbox/boot/vmlinuz-normal"
                'initrd' | Set-Content "$sandbox/boot/initramfs-normal.img"
                "$sandbox/boot/vmlinuz-normal" | Set-Content "$sandbox/default-kernel"
                "UUID=root / xfs defaults 0 0`n//other/share /existing cifs nofail 0 0" | Set-Content "$sandbox/etc/fstab"
                $originalFstab = Get-Content "$sandbox/etc/fstab" -Raw
                [IO.File]::WriteAllText("$tools/dzdo", "#!/bin/bash`nexec `"`$@`"`n")
                foreach ($tool in @('restorecon','usermod','gpasswd')) { [IO.File]::WriteAllText("$tools/$tool", "#!/bin/bash`nprintf '%s\\n' `"$tool `$*`" >> `"`$MOBILE_SMB_FIXTURE/commands`"`n") }
                [IO.File]::WriteAllText("$tools/mount.cifs", "#!/bin/bash`nexit 0`n")
                [IO.File]::WriteAllText("$tools/ip", "#!/bin/bash`necho '2: eth0 inet 10.2.3.6/24 scope global eth0'`n")
                [IO.File]::WriteAllText("$tools/nmcli", @'
#!/bin/bash
printf 'nmcli %s\n' "$*" >> "$MOBILE_SMB_FIXTURE/commands"
if [[ "$*" == '-t -f UUID,DEVICE connection show --active' ]]; then echo '12345678-1234-1234-1234-123456789abc:eth0'
elif [[ "$1 $2 $3 $4" == '-t --escape no -f' ]]; then
    printf '%s:%s\n' "$5" "$(jq -r --arg key "$5" '.[$key]' "$MOBILE_SMB_FIXTURE/network.json")"
elif [[ "$1 $2 $3" == 'connection modify uuid' ]]; then
    shift 4
    while (( $# )); do jq --arg key "$1" --arg value "$2" '.[$key]=$value' "$MOBILE_SMB_FIXTURE/network.json" > "$MOBILE_SMB_FIXTURE/network.tmp"; mv "$MOBILE_SMB_FIXTURE/network.tmp" "$MOBILE_SMB_FIXTURE/network.json"; shift 2; done
fi
exit 0
'@)
                [IO.File]::WriteAllText("$tools/systemctl", @'
#!/bin/bash
printf 'systemctl %s\n' "$*" >> "$MOBILE_SMB_FIXTURE/commands"
if [[ "$1" == is-active ]]; then exit 1; fi
if [[ "$1" == start ]]; then
    [[ ! -f "$MOBILE_SMB_FIXTURE/mount-fails" ]] || exit 1
    target="$(systemd-escape --unescape --path "${2%.mount}")"
    awk -v target="$target" '$2==target {print $1, $2}' "$MOBILE_SMB_FIXTURE/etc/fstab" >> "$MOBILE_SMB_FIXTURE/mounted"
fi
'@)
                [IO.File]::WriteAllText("$tools/grubby", @'
#!/bin/bash
printf 'grubby %s\n' "$*" >> "$MOBILE_SMB_FIXTURE/commands"
case "$1" in
--default-kernel) cat "$MOBILE_SMB_FIXTURE/default-kernel" ;;
--info=DEFAULT) printf 'kernel="%s/boot/vmlinuz-normal"\ninitrd="%s/boot/initramfs-normal.img"\nargs="ro fips=1"\n' "$MOBILE_SMB_FIXTURE" "$MOBILE_SMB_FIXTURE" ;;
--info=ALL) printf 'kernel="%s/boot/vmlinuz-normal"\n' "$MOBILE_SMB_FIXTURE" ;;
--info=*) [[ -f "${1#--info=}" ]] || exit 1; echo 'args="ro fips=0"' ;;
--set-default=*) printf '%s\n' "${1#--set-default=}" > "$MOBILE_SMB_FIXTURE/default-kernel" ;;
esac
'@)
                [IO.File]::WriteAllText("$tools/findmnt", @'
#!/bin/bash
while (( $# )); do if [[ "$1" == '--mountpoint' ]]; then target="$2"; shift; fi; shift; done
if [[ -f "$MOBILE_SMB_FIXTURE/mounted" ]] && grep -Fq " $target" "$MOBILE_SMB_FIXTURE/mounted"; then
    if [[ "${target:-}" != '' ]]; then awk -v target="$target" '$2==target {print $1}' "$MOBILE_SMB_FIXTURE/mounted"; fi
    exit 0
fi
exit 1
'@)
                [IO.File]::WriteAllText("$tools/mount", @'
#!/bin/bash
if [[ -f "$MOBILE_SMB_FIXTURE/mount-fails" ]]; then exit 1; fi
awk -v target="$1" '$2==target {print $1, $2}' "$MOBILE_SMB_FIXTURE/etc/fstab" >> "$MOBILE_SMB_FIXTURE/mounted"
'@)
                [IO.File]::WriteAllText("$tools/umount", @'
#!/bin/bash
if [[ -f "$MOBILE_SMB_FIXTURE/mount-busy" ]]; then exit 1; fi
awk -v target="$1" '$2!=target' "$MOBILE_SMB_FIXTURE/mounted" > "$MOBILE_SMB_FIXTURE/mounted.tmp"
mv "$MOBILE_SMB_FIXTURE/mounted.tmp" "$MOBILE_SMB_FIXTURE/mounted"
'@)
                Get-ChildItem $tools -File | ForEach-Object { & chmod +x $_.FullName }
                $env:PATH = "$tools" + [IO.Path]::PathSeparator + $env:PATH
                $script:Config.Preflight.LinuxToolDirectories = @($tools,'/usr/local/sbin','/usr/local/bin','/usr/sbin','/usr/bin','/sbin','/bin')
                $testMounts = @($mounts | ForEach-Object { [pscustomobject]@{ HostName=$_.HostName; Source=$_.Source; MountPoint="$sandbox$($_.MountPoint)" } })
                $options = [pscustomobject]@{ UserName='configured-smb'; Interface=[pscustomobject]@{ InterfaceName='eth0'; IPAddress='10.2.3.6'; PrefixLength=24 }; Mounts=$testMounts; LinuxGroup='users'; LinuxUsers=@() }
                function Convert-SandboxScript([string]$Text) {
                    # Rewrite OS paths ONLY in this test. All commands that change native state are mocked.
                    foreach ($prefix in @('/var/lib/mobiles','/etc','/boot/','/run/lock','/proc/sys/crypto','/proc/sys/kernel/','/share')) { $Text = $Text.Replace($prefix, "$sandbox$prefix") }
                    $Text
                }
                function Invoke-SandboxScript([string]$Text) {
                    $path = "$fixture/worker-test.sh"
                    [IO.File]::WriteAllText($path, $Text)
                    & bash -n $path
                    Assert ($LASTEXITCODE -eq 0) 'Generated SMB shell script is invalid'
                    $output = & bash $path 2> "$fixture/worker-error"
                    if ($LASTEXITCODE -ne 0) { throw "Fixture worker failed: $(Get-Content "$fixture/worker-error" -Raw)" }
                    ($output -join "`n") | ConvertFrom-Json
                }
                $prepare = Convert-SandboxScript (Get-LinuxMobileSmbScript -Mode Prepare -Id $id -Options $options -Credential $credential)
                Assert (-not $prepare.Contains('worker.sh') -and -not $prepare.Contains('ExecStart=') -and $prepare -notmatch '(?m)^\s*nmcli connection (up|down)') 'Checkout still installs a worker or reconnects the interface'
                $prepared = Invoke-SandboxScript $prepare
                $stateRoot = "$sandbox/var/lib/mobiles/smb/$id"
                Assert ($prepared.Status -eq 'PreparedPendingReboot' -and -not (Test-Path "$sandbox/mounted") -and -not (Test-Path "$stateRoot/worker.sh")) 'Preparation started mounts or persisted executable content'
                # The readability helpers must round-trip data, not evaluate shell syntax.
                $note = 'Operator''s "note": $(exit 99)' + "`nnext line"
                $helperScript = "root='/var/lib/mobiles/smb/$id'`n" + (Get-LinuxSmbSessionScript) + "`n" +
                    'state_set MaintenanceNote ' + (ConvertTo-BashArgument $note) + "`n" + @'
state_add MaintenanceOrder first
state_add MaintenanceOrder second
state_add MaintenanceOrder first
cat "$state"
'@
                $helperState = Invoke-SandboxScript (Convert-SandboxScript $helperScript)
                Assert ($helperState.MaintenanceNote -eq $note -and ($helperState.MaintenanceOrder -join ',') -eq 'first,second') 'State helpers changed quoted/multiline values or list order/uniqueness'
                $network = Get-Content "$sandbox/network.json" -Raw | ConvertFrom-Json
                Assert ($network.'ipv4.method' -eq 'manual' -and $network.'ipv4.addresses' -eq '10.2.3.6/24' -and $network.'ipv4.dns' -eq '10.2.3.1') 'Persistent network configuration was not staged or unrelated settings changed'
                $fstab = Get-Content "$sandbox/etc/fstab" -Raw
                Assert ($fstab.Contains('//10.2.3.4/C') -and $fstab.Contains('//10.2.3.5/E') -and $fstab.Contains('nofail,x-systemd.automount') -and $fstab.Contains('//other/share /existing')) 'Native fstab setup lost sources/options or existing entries'
                Assert (-not (Get-Content "$stateRoot/options.json" -Raw).Contains('fixture-pass')) 'Password leaked into options JSON'
                Assert ((& stat -c '%a' "$sandbox/share/WIN-A") -eq '755' -and (& stat -c '%a' "$stateRoot/credentials-WIN-A") -eq '600') 'Share parent traversal or credential permissions are incorrect'
                Assert ((Get-Content "$stateRoot/credentials-WIN-A" -Raw).Contains('username=configured-smb')) 'Configured SMB account did not reach credentials'
                $groupTask = "record_action() { printf '%s\n' `"`$4`"; }; record_failure() { echo failed >&2; return 1; }`n" + (New-LinuxTask-SmbGroup $id)
                $groupResult = Invoke-SandboxScript (Convert-SandboxScript $groupTask)
                Assert ($groupResult.Status -eq 'PreparedPendingReboot') 'SMB group task did not integrate with ordinary Linux provisioning'
                $status = Invoke-SandboxScript (Convert-SandboxScript (Get-LinuxMobileSmbScript Status $id))
                Assert ($status.Status -eq 'PreparedPendingReboot') 'Status ignored the required reboot'
                'boot-after-checkout' | Set-Content "$sandbox/proc/sys/kernel/random/boot_id"
                $status = Invoke-SandboxScript (Convert-SandboxScript (Get-LinuxMobileSmbScript Verify $id))
                Assert ($status.Status -eq 'NeedsReview' -and -not (Test-Path "$sandbox/mounted")) 'Verification mounted shares with FIPS enforced'
                '0' | Set-Content "$sandbox/proc/sys/crypto/fips_enabled"
                $status = Invoke-SandboxScript (Convert-SandboxScript (Get-LinuxMobileSmbScript Status $id))
                Assert ($status.Status -eq 'NeedsReview' -and -not (Test-Path "$sandbox/mounted")) 'Read-only status started missing mounts'
                $verified = Invoke-SandboxScript (Convert-SandboxScript (Get-LinuxMobileSmbScript Verify $id))
                Assert ($verified.Status -eq 'Active' -and $verified.Mounts.Count -eq 3) 'Explicit verification failed to mount/probe selected drives'
                New-Item -ItemType File "$sandbox/mount-busy" | Out-Null
                [IO.File]::WriteAllText("$fixture/busy.sh", (Convert-SandboxScript (Get-LinuxMobileSmbScript Restore $id)))
                & bash "$fixture/busy.sh" 2> "$fixture/worker-error" | Out-Null
                Assert ($LASTEXITCODE -ne 0 -and (Test-Path "$stateRoot/credentials-WIN-A")) 'Busy mount did not block cleanup'
                Remove-Item "$sandbox/mount-busy"
                'updated kernel' | Set-Content "$sandbox/boot/vmlinuz-new-normal"
                "$sandbox/boot/vmlinuz-new-normal" | Set-Content "$sandbox/default-kernel"
                $restored = Invoke-SandboxScript (Convert-SandboxScript (Get-LinuxMobileSmbScript Restore $id))
                Assert ($restored.Status -eq 'RestorePendingReboot' -and -not (Test-Path "$stateRoot/credentials-WIN-A")) 'Check-in did not stage restoration or remove credentials'
                $network = Get-Content "$sandbox/network.json" -Raw | ConvertFrom-Json
                Assert ($network.'ipv4.method' -eq 'auto' -and $network.'ipv4.addresses' -eq '' -and $network.'ipv4.dns' -eq '10.2.3.1') 'Original network settings were not restored'
                Assert ((Get-Content "$sandbox/default-kernel" -Raw).Trim() -eq "$sandbox/boot/vmlinuz-new-normal") 'A newer normal kernel default was overwritten'
                Assert (-not (Get-Content "$sandbox/etc/fstab" -Raw).Contains('# BEGIN MOBILES') -and -not (Test-Path "$sandbox/share/WIN-A")) 'Managed entries/directories remained after cleanup'
                '1' | Set-Content "$sandbox/proc/sys/crypto/fips_enabled"
                'boot-after-checkin' | Set-Content "$sandbox/proc/sys/kernel/random/boot_id"
                $status = Invoke-SandboxScript (Convert-SandboxScript (Get-LinuxMobileSmbScript Status $id))
                Assert ($status.Status -eq 'Restored' -and (Get-Content "$stateRoot/state.json" -Raw | ConvertFrom-Json).Status -eq 'Restored') 'Restoration was not verified/checkpointed after reboot'
                Assert (-not (Get-Content "$sandbox/commands" -Raw).Contains('connection up')) 'A command reconnected the live management interface'
                # Legacy state can be checked in without executing its CRLF worker.
                $legacy = Get-Content "$stateRoot/state.json" -Raw | ConvertFrom-Json
                $legacy.PSObject.Properties.Remove('OriginalNetwork'); $legacy.Version=1; $legacy.Status='Active'
                $legacy | Add-Member MobileConnection "mobiles-smb-$id"
                $legacy | ConvertTo-Json -Depth 12 | Set-Content "$stateRoot/state.json"
                [IO.File]::WriteAllText("$stateRoot/worker.sh", "#!/bin/bash`r`nexit 99`r`n")
                'legacy service' | Set-Content "$sandbox/etc/systemd/system/mobiles-smb-$id.service"
                $legacyRestore = Invoke-SandboxScript (Convert-SandboxScript (Get-LinuxMobileSmbScript Restore $id))
                Assert ($legacyRestore.Status -eq 'RestorePendingReboot' -and -not (Test-Path "$stateRoot/worker.sh") -and -not (Test-Path "$sandbox/etc/systemd/system/mobiles-smb-$id.service")) 'Legacy cleanup executed/retained the old worker/service'
            } finally { foreach ($name in $envNames) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name]) } }
        }
        # Controller wiring: every Windows host is shared, but only selected hosts get Linux mounts.
        $script:Config.Preflight.LinuxToolDirectories = @('/usr/local/sbin','/usr/local/bin','/usr/sbin','/usr/bin','/sbin','/bin')
        $script:preparedWindows = @(); $script:restoreOrder = @(); $script:linuxRestoreFails = $false
        $script:windowsTargets = @(); $script:failWindowsStatus = $false; $script:busyWindowsStatus = $false
        function Get-WindowsProcedureHookRunner { { param($Hooks,$MobileName,$Procedure,$RunId) } }
        function Invoke-Command {
            [CmdletBinding()] param($ComputerName,$ScriptBlock,[array]$ArgumentList)
            $script:windowsTargets += $ComputerName
            Assert ($ComputerName -in @('WIN-A','WIN-B')) 'Windows remoting must use recorded names, never captured IPs'
            if ($ArgumentList.Count -eq 4 -and $ArgumentList[2] -eq 'Check-in') {
                return [pscustomobject]@{ Actions=@(); Failures=@() }
            }
            if ($ScriptBlock.ToString().Contains('Get-CimInstance Win32_LogicalDisk')) {
                $last = if ($ComputerName -eq 'WIN-A') { 11 } else { 12 }
                [pscustomobject]@{ Interfaces = @([pscustomobject]@{ InterfaceName='Ethernet'; InterfaceGuid="guid-$ComputerName"; IPAddress="10.20.1.$last"; PrefixLength=24 })
                    LocalAuthority = $ComputerName; AccountExists = $true; Drives = @('C','D') }
            } elseif ($ArgumentList[0] -eq 'Prepare') {
                Assert ($ArgumentList[2].UserName -eq 'configured-smb' -and $ArgumentList[3].UserName -eq 'configured-smb') 'SMBUser/credential did not reach Windows preparation'
                $script:preparedWindows += $ComputerName
                [pscustomobject]@{ Status='PreparedPendingReboot'; Shares=@('C','D'); OriginalDhcp='Enabled'; OriginalDnsStatic='10.20.1.1'; AccountOwned=$false; AddedRights=@('SeNetworkLogonRight') }
            } elseif ($ArgumentList[0] -eq 'Restore') {
                $script:restoreOrder += "Windows:$ComputerName"
                [pscustomobject]@{ Status='RestorePendingReboot' }
            } elseif ($ArgumentList[0] -eq 'Status') {
                if ($script:failWindowsStatus) { throw 'Name-based management unavailable' }
                if ($script:busyWindowsStatus) { return [pscustomobject]@{ Status='Busy' } }
                [pscustomobject]@{ Status='Restored' }
            }
            else { throw 'Unexpected mocked Windows operation' }
        }
        function Invoke-Linux {
            param($Computers,$Script,$KeyPath)
            $state = $null; $code = 0; $errorText = ''
            if ($Script.Contains('run_mobile_hook')) {
                Assert ($Script.Contains('export PATH=') -and $Script.Contains('Actions:$actions')) 'SMB hooks did not use the standalone runner and configured tool path'
                $state = [pscustomobject]@{ Actions=@(); Failures=@() }
            } elseif ($Script.Contains('ip -o -4 address show up scope global')) {
                $state = [pscustomobject]@{ Interfaces=@([pscustomobject]@{ InterfaceName='eth0'; IPAddress='10.20.1.20'; PrefixLength=24 }) }
            } elseif ($Script.Contains("payload=")) {
                $match = [regex]::Match($Script, "printf '%s' '([^']+)' \| base64 -d")
                $body = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($match.Groups[1].Value)) | ConvertFrom-Json
                Assert ($body.Password -eq 'fixture-pass' -and $body.UserName -eq 'configured-smb') 'Credential did not reach Linux preparation'
                Assert ($body.Mounts.Count -eq 2 -and $body.Mounts[0].Source -eq '//10.20.1.12/C') 'Unselected Windows hosts were included in Linux mounts'
                $state = [pscustomobject]@{ Status='PreparedPendingReboot' }
            } elseif ($Script.Contains("finish RestorePendingReboot")) {
                $script:restoreOrder += "Linux:$($Computers[0])"
                if ($script:linuxRestoreFails) { $code = 2; $errorText='Busy mount' }
                $state = [pscustomobject]@{ Status='RestorePendingReboot' }
            } elseif ($Script.Contains("verify_mounts=")) { $state = [pscustomobject]@{ Status='Restored' } }
            else { throw 'Unexpected mocked Linux operation' }
            [pscustomobject]@{ Target=$Computers[0]; ExitCode=$code; StdOut=($state | ConvertTo-Json -Depth 10); StdErr=$errorText }
        }
        $run = New-MobileRunLog -MobileName orchestrated -Procedure Check-out
        $plan = Initialize-MobileSmbDeployment -MobileData $data -MobileName orchestrated -SmbHosts WIN-B -SmbCredential $credential -Run $run
        Assert ($script:preparedWindows.Count -eq 2 -and $plan.StorageHosts.Count -eq 1 -and $plan.Mounts.Count -eq 2) 'Coordinator did not separate all Windows shares from selected Linux storage'
        $windowsOnly = Initialize-MobileSmbDeployment -MobileData ([pscustomobject]@{ Windows=$data.Windows; Linux=@(); AllUsers=@() }) -MobileName windows-only -SmbCredential $credential -Run $run
        Assert ($windowsOnly.Mounts.Count -eq 0 -and $windowsOnly.StorageHosts.Count -eq 0 -and $windowsOnly.Linux.Count -eq 0) 'Windows-only deployment stored null mount entries or prompted for Linux storage'
        $savedPlan = Read-MobileSmbPlan orchestrated
        Assert ($savedPlan.Windows[0].State.OriginalDhcp -eq 'Enabled' -and $savedPlan.Windows[0].State.AddedRights.Count -eq 1 -and $savedPlan.Linux[0].State.Status -eq 'PreparedPendingReboot') 'Primary-node plan did not capture endpoint restoration state'
        $saved = Get-Content (Get-MobileSmbPlanPath orchestrated) -Raw
        $audit = Get-Content $run.Path -Raw
        Assert (-not $saved.Contains('fixture-pass') -and -not $audit.Contains('fixture-pass') -and -not $audit.Contains('payload_b64')) 'Credentials/worker payload leaked into controller state or audit'
        $script:windowsTargets = @()
        Invoke-MobileSmbCheckInHooks -Plan $plan -Run $run -WindowsHooks @([pscustomobject]@{ Name='fixture-hook' }) -LinuxHooks @([pscustomobject]@{ Name='fixture.sh'; Sha256='fixture-sha'; ContentBase64='dHJ1ZQo=' })
        Assert (($script:windowsTargets -join ',') -eq 'WIN-A,WIN-B') 'Check-in hooks did not target both recorded Windows names'
        $script:busyWindowsStatus = $true
        $null = Show-MobileSmbStatus orchestrated
        Assert ((Read-MobileSmbPlan orchestrated).Windows[0].State.OriginalDhcp -eq 'Enabled') 'Busy status erased the saved Windows recovery settings'
        $script:busyWindowsStatus = $false
        $script:linuxRestoreFails = $true
        $rejected = $false; try { Restore-MobileSmbDeployment $plan $run } catch { $rejected = $true }
        Assert ($rejected -and $script:restoreOrder.Count -eq 1 -and $script:restoreOrder[0] -like 'Linux:*') 'Windows shares were removed despite a Linux unmount failure'
        $script:linuxRestoreFails = $false; $script:restoreOrder = @()
        Restore-MobileSmbDeployment $plan $run
        Assert ($script:restoreOrder.Count -eq 3 -and $script:restoreOrder[0] -eq 'Linux:10.20.1.20' -and $script:restoreOrder[1] -like 'Windows:*') 'Check-in did not unmount Linux before removing Windows shares'
        $statuses = @(Show-MobileSmbStatus orchestrated)
        Assert ($statuses.Count -eq 3 -and (Read-MobileSmbPlan orchestrated).Status -eq 'Restored') 'Post-reboot status did not complete the saved lifecycle'

        $script:failWindowsStatus = $true; $script:windowsTargets = @()
        $unreachable = @(Show-MobileSmbStatus orchestrated)
        Assert (@($unreachable | Where-Object { $_.Platform -eq 'Windows' -and $_.Status -eq 'Unreachable' }).Count -eq 2) 'Failed name-based management was not reported as unreachable'
        Assert (($script:windowsTargets -join ',') -eq 'WIN-A,WIN-B') 'Status retried Windows management using another target'
        Assert ((Read-MobileSmbPlan orchestrated).Windows[0].State.Status -eq 'Restored') 'An unreachable host erased the last primary-node snapshot'

        'PASS: native Linux preparation/verification/restoration, no startup worker, existing account reuse, numeric mounts, nofail/automount, legacy cleanup, and controller wiring.'
    } $fixture $root $source
} finally {
    Remove-Module $module -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
