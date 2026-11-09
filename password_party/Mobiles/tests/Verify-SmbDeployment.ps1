# Offline SMB workflow checks. Native networking, boot, mount and share commands are mocked.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobiles-smb-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join '; ') }
$names = @('Get-MobileSmbToolPath','Get-MobileSmbId','Resolve-MobileSmbHosts','Select-MobileSmbInterface','Get-MobileSmbMountPlan',
    'Get-WindowsMobileSmbInventory','Get-LinuxMobileSmbInventory','Get-WindowsMobileSmbWorker','Get-LinuxMobileSmbWorker','Get-LinuxMobileSmbScript',
    'Get-MobileSmbPlanPath','Save-MobileSmbPlan','Read-MobileSmbPlan','ConvertFrom-MobileSmbLinuxResult','Initialize-MobileSmbDeployment',
    'Restore-MobileSmbDeployment','Show-MobileSmbStatus','ConvertTo-BashArgument','New-MobileRunLog','Write-MobileRunEvent','Format-MobileRunEvent','ConvertTo-MobileLogLines')
$source = $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -in $names } | ForEach-Object { $_.Extent.Text }
$module = New-Module -ScriptBlock ([scriptblock]::Create($source -join "`n"))
try {
    & $module {
        param($fixture, $root)
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
        Assert (-not $windowsWorker.ToString().Contains('mobile-smb-access') -and -not $windowsWorker.ToString().Contains('SupeSecret')) 'Windows worker still embeds hardcoded credentials'
        # Refuse pre-existing accounts before ACL/network changes, including on non-Windows test runners.
        function Get-LocalUser { [CmdletBinding()] param($Name) [pscustomobject]@{ Name = $Name } }
        $rejected = $false
        try { & $windowsWorker Prepare "$fixture/no-state" ([pscustomobject]@{ UserName='configured-smb' }) $credential } catch { $rejected = $_.Exception.Message -like '*already exists*' }
        Assert $rejected 'Existing SMB password would be overwritten'

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
        function New-ScheduledTaskAction { param($Execute,$Argument) $script:scheduledMode=$Argument; [pscustomobject]@{ Execute=$Execute; Arguments=$Argument } }
        function New-ScheduledTaskTrigger { param([switch]$AtStartup) [pscustomobject]@{ AtStartup=$true } }
        function New-ScheduledTaskSettingsSet { param([switch]$StartWhenAvailable,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries) [pscustomobject]@{} }
        function Register-ScheduledTask { [CmdletBinding()] param($TaskName,$Action,$Trigger,$Settings,$User,$RunLevel,[switch]$Force) }
        function Unregister-ScheduledTask { [CmdletBinding()] param($TaskName,[switch]$Confirm) }
        $savedSystemRoot = $env:SystemRoot; $env:SystemRoot = "$fixture/windows"
        try {
            $active = & $windowsWorker Activate $winRoot
            Assert ($active.Status -eq 'Active' -and $script:networkCalls -contains 'Static:7:10.2.3.4/24' -and $script:networkCalls -contains 'Dhcp:7:Disabled') 'Windows DHCP address was not frozen on the selected adapter'
            $restore = & $windowsWorker Restore $winRoot
            Assert ($restore.Status -eq 'RestorePendingReboot' -and $script:scheduledMode.Contains('-Mode RestoreBoot') -and $script:networkCalls -notcontains 'Dhcp:7:Enabled') 'Windows check-in changed the network in the live session'
            $restored = & $windowsWorker RestoreBoot $winRoot
            Assert ($restored.Status -eq 'Restored' -and $script:networkCalls -contains 'Dhcp:7:Enabled' -and $script:networkCalls -contains 'Dns:7:True') 'Windows startup did not restore DHCP/DNS'
            $winState.OriginalDhcp='Disabled'; $winState.Status='PreparedPendingReboot'
            $winState | ConvertTo-Json -Depth 8 | Set-Content "$winRoot/state.json"
            $script:networkCalls=@()
            $active = & $windowsWorker Activate $winRoot
            $restored = & $windowsWorker RestoreBoot $winRoot
            Assert ($script:networkCalls.Count -eq 0) 'An originally static interface was changed to DHCP'
        } finally { $env:SystemRoot = $savedSystemRoot }

        if ((Get-Command bash -ErrorAction SilentlyContinue) -and (Get-Command jq -ErrorAction SilentlyContinue)) {
            $tools = "$fixture/tools"; $sandbox = "$fixture/endpoint"; $id = Get-MobileSmbId fixture
            New-Item -ItemType Directory -Path $tools, "$sandbox/etc/systemd/system", "$sandbox/boot", "$sandbox/run/lock", "$sandbox/proc/sys/crypto", "$sandbox/share" | Out-Null
            $envNames = @('PATH','MOBILE_SMB_FIXTURE'); $savedEnv = @{}
            foreach ($name in $envNames) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name) }
            try {
                $env:MOBILE_SMB_FIXTURE = $sandbox
                '1' | Set-Content "$sandbox/proc/sys/crypto/fips_enabled"
                'kernel' | Set-Content "$sandbox/boot/vmlinuz-normal"
                'initrd' | Set-Content "$sandbox/boot/initramfs-normal.img"
                "$sandbox/boot/vmlinuz-normal" | Set-Content "$sandbox/default-kernel"
                "UUID=root / xfs defaults 0 0`n//other/share /existing cifs nofail 0 0" | Set-Content "$sandbox/etc/fstab"
                $originalFstab = Get-Content "$sandbox/etc/fstab" -Raw
                [IO.File]::WriteAllText("$tools/dzdo", "#!/bin/bash`nexec `"`$@`"`n")
                foreach ($tool in @('systemctl','restorecon','usermod','gpasswd')) { [IO.File]::WriteAllText("$tools/$tool", "#!/bin/bash`nprintf '%s\\n' `"$tool `$*`" >> `"`$MOBILE_SMB_FIXTURE/commands`"`n") }
                [IO.File]::WriteAllText("$tools/mount.cifs", "#!/bin/bash`nexit 0`n")
                [IO.File]::WriteAllText("$tools/ip", "#!/bin/bash`necho '2: eth0 inet 10.2.3.6/24 scope global eth0'`n")
                [IO.File]::WriteAllText("$tools/nmcli", @'
#!/bin/bash
printf 'nmcli %s\n' "$*" >> "$MOBILE_SMB_FIXTURE/commands"
if [[ "$*" == '-t -f UUID,DEVICE connection show --active' ]]; then echo '12345678-1234-1234-1234-123456789abc:eth0'
elif [[ "$*" == '-t -f NAME connection show' ]]; then [[ ! -f "$MOBILE_SMB_FIXTURE/clone" ]] || cat "$MOBILE_SMB_FIXTURE/clone"
elif [[ "$1 $2" == 'connection clone' ]]; then printf '%s' "$5" > "$MOBILE_SMB_FIXTURE/clone"
elif [[ "$1 $2" == 'connection delete' ]]; then rm -f "$MOBILE_SMB_FIXTURE/clone"
fi
exit 0
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
                    foreach ($prefix in @('/var/lib/mobiles','/etc','/boot','/run/lock','/proc/sys/crypto','/share')) { $Text = $Text.Replace($prefix, "$sandbox$prefix") }
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
                # The payload itself is encoded. Replace the embedded worker in the fixture options before encoding it.
                $decodedMatch = [regex]::Match($prepare, "payload_b64='([^']+)'")
                $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($decodedMatch.Groups[1].Value)) | ConvertFrom-Json
                $payload.Worker = Convert-SandboxScript $payload.Worker
                $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 12 -Compress)))
                $prepare = $prepare.Replace($decodedMatch.Groups[1].Value, $encoded)
                $prepared = Invoke-SandboxScript $prepare
                $stateRoot = "$sandbox/var/lib/mobiles/smb/$id"
                $unitText = Get-Content "$sandbox/etc/systemd/system/$($prepared.Unit)" -Raw
                Assert ($unitText.Contains('Type=simple') -and $unitText.Contains('/usr/bin/timeout 300')) 'Mount verification delayed boot or lacked a runtime bound'
                Assert ($prepared.Status -eq 'PreparedPendingReboot' -and -not (Test-Path "$sandbox/mounted")) 'Preparation activated network or mounts immediately'
                Assert ((Get-Content "$sandbox/etc/fstab" -Raw) -eq $originalFstab) 'Preparation changed fstab before the disconnected boot'
                Assert (-not (Get-Content "$stateRoot/options.json" -Raw).Contains('fixture-pass')) 'Password leaked into options JSON'
                $creds = Get-Content "$stateRoot/credentials-WIN-A" -Raw
                Assert ($creds.Contains('username=configured-smb') -and $creds.Contains('domain=WIN-A')) 'Configured account/server authority did not reach Linux credentials'
                [IO.File]::WriteAllText("$fixture/fips-enforced.sh", "/bin/bash '$stateRoot/worker.sh' Activate '$stateRoot'")
                & bash "$fixture/fips-enforced.sh" 2> "$fixture/worker-error" | Out-Null
                Assert ($LASTEXITCODE -ne 0 -and -not (Test-Path "$sandbox/mounted")) 'SMB activated while FIPS was still enforced'
                '0' | Set-Content "$sandbox/proc/sys/crypto/fips_enabled"
                $activated = Invoke-SandboxScript "/bin/bash '$stateRoot/worker.sh' Activate '$stateRoot'"
                Assert ($activated.Status -eq 'Active' -and $activated.Mounts.Count -eq 3) 'SMB activation did not mount all selected hosts/drives'
                $fstab = Get-Content "$sandbox/etc/fstab" -Raw
                Assert ($fstab.Contains('//10.2.3.4/C') -and $fstab.Contains('//10.2.3.5/E') -and $fstab.Contains('sec=ntlmssp') -and $fstab.Contains('nofail') -and $fstab.Contains('_netdev') -and $fstab.Contains('//other/share /existing')) 'Managed fstab lost IPs, mount options or unrelated entries'
                $again = Invoke-SandboxScript "/bin/bash '$stateRoot/worker.sh' Activate '$stateRoot'"
                Assert ($again.Status -eq 'Active') 'Already-mounted expected shares were not reused'
                New-Item -ItemType File "$sandbox/mount-busy" | Out-Null
                [IO.File]::WriteAllText("$fixture/busy.sh", "/bin/bash '$stateRoot/worker.sh' Restore '$stateRoot'")
                & bash "$fixture/busy.sh" 2> "$fixture/worker-error" | Out-Null
                Assert ($LASTEXITCODE -ne 0 -and (Test-Path "$stateRoot/credentials-WIN-A")) 'Busy unmount did not prevent credential removal'
                Remove-Item "$sandbox/mount-busy"
                # Simulate a kernel update advancing the normal default while checked out.
                'updated kernel' | Set-Content "$sandbox/boot/vmlinuz-new-normal"
                "$sandbox/boot/vmlinuz-new-normal" | Set-Content "$sandbox/default-kernel"
                $restored = Invoke-SandboxScript "/bin/bash '$stateRoot/worker.sh' Restore '$stateRoot'"
                Assert ($restored.Status -eq 'RestorePendingReboot' -and -not (Test-Path "$stateRoot/credentials-WIN-A")) 'Check-in did not remove credentials and stage restoration'
                Assert ((Get-Content "$sandbox/default-kernel" -Raw).Trim() -eq "$sandbox/boot/vmlinuz-new-normal") 'Check-in overwrote a newer normal default kernel'
                $after = Get-Content "$sandbox/etc/fstab" -Raw
                Assert ($after.Contains('//other/share /existing') -and -not $after.Contains('# BEGIN MOBILES')) 'Check-in removed unrelated fstab entries or left managed entries'
                '1' | Set-Content "$sandbox/proc/sys/crypto/fips_enabled"
                $restoredBoot = Invoke-SandboxScript "/bin/bash '$stateRoot/worker.sh' RestoreBoot '$stateRoot'"
                Assert ($restoredBoot.Status -eq 'Restored' -and -not (Test-Path "$sandbox/clone")) 'Check-in boot did not restore the original profile'
                Assert (-not (Test-Path "$sandbox/share/WIN-A") -and (Test-Path "$sandbox/share")) 'Created parent mount directories were left behind or an existing /share was removed'
                Assert ((Get-Content "$sandbox/commands" -Raw).Contains('connection up uuid 12345678-1234-1234-1234-123456789abc')) 'Original NM profile was not restored by UUID'
            } finally { foreach ($name in $envNames) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name]) } }
        }
        # Controller wiring: every Windows host is shared, but only selected hosts get Linux mounts.
        $script:Config.Preflight.LinuxToolDirectories = @('/usr/local/sbin','/usr/local/bin','/usr/sbin','/usr/bin','/sbin','/bin')
        $script:preparedWindows = @(); $script:restoreOrder = @(); $script:linuxRestoreFails = $false
        function Invoke-Command {
            [CmdletBinding()] param($ComputerName,$ScriptBlock,[array]$ArgumentList)
            if ($ScriptBlock.ToString().Contains('Get-CimInstance Win32_LogicalDisk')) {
                $last = if ($ComputerName -eq 'WIN-A') { 11 } else { 12 }
                [pscustomobject]@{ Interfaces = @([pscustomobject]@{ InterfaceName='Ethernet'; InterfaceGuid="guid-$ComputerName"; IPAddress="10.20.1.$last"; PrefixLength=24 })
                    LocalAuthority = $ComputerName; AccountExists = $false; Drives = @('C','D') }
            } elseif ($ArgumentList[0] -eq 'Prepare') {
                Assert ($ArgumentList[2].UserName -eq 'configured-smb' -and $ArgumentList[3].UserName -eq 'configured-smb') 'SMBUser/credential did not reach Windows preparation'
                $script:preparedWindows += $ComputerName
                [pscustomobject]@{ Status='PreparedPendingReboot'; Shares=@('C','D') }
            } elseif ($ArgumentList[0] -eq 'Restore') {
                $script:restoreOrder += "Windows:$ComputerName"
                [pscustomobject]@{ Status='RestorePendingReboot' }
            } elseif ($ArgumentList[0] -eq 'Status') { [pscustomobject]@{ Status='Restored' } }
            else { throw 'Unexpected mocked Windows operation' }
        }
        function Invoke-Linux {
            param($Computers,$Script,$KeyPath)
            $state = $null; $code = 0; $errorText = ''
            if ($Script.Contains('ip -o -4 address show up')) {
                $state = [pscustomobject]@{ Interfaces=@([pscustomobject]@{ InterfaceName='eth0'; IPAddress='10.20.1.20'; PrefixLength=24 }) }
            } elseif ($Script.Contains("payload_b64='")) {
                $match = [regex]::Match($Script, "payload_b64='([^']+)'")
                $body = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($match.Groups[1].Value)) | ConvertFrom-Json
                Assert ($body.Password -eq 'fixture-pass' -and $body.UserName -eq 'configured-smb') 'Credential did not reach Linux preparation'
                Assert ($body.Mounts.Count -eq 2 -and $body.Mounts[0].Source -eq '//10.20.1.12/C') 'Unselected Windows hosts were included in Linux mounts'
                $state = [pscustomobject]@{ Status='PreparedPendingReboot' }
            } elseif ($Script -match "worker.sh' Restore") {
                $script:restoreOrder += "Linux:$($Computers[0])"
                if ($script:linuxRestoreFails) { $code = 2; $errorText='Busy mount' }
                $state = [pscustomobject]@{ Status='RestorePendingReboot' }
            } elseif ($Script -match "worker.sh' Status") { $state = [pscustomobject]@{ Status='Restored' } }
            else { throw 'Unexpected mocked Linux operation' }
            [pscustomobject]@{ Target=$Computers[0]; ExitCode=$code; StdOut=($state | ConvertTo-Json -Depth 10); StdErr=$errorText }
        }
        $run = New-MobileRunLog -MobileName orchestrated -Procedure Check-out
        $plan = Initialize-MobileSmbDeployment -MobileData $data -MobileName orchestrated -SmbHosts WIN-B -SmbCredential $credential -Run $run
        Assert ($script:preparedWindows.Count -eq 2 -and $plan.StorageHosts.Count -eq 1 -and $plan.Mounts.Count -eq 2) 'Coordinator did not separate all Windows shares from selected Linux storage'
        $windowsOnly = Initialize-MobileSmbDeployment -MobileData ([pscustomobject]@{ Windows=$data.Windows; Linux=@(); AllUsers=@() }) -MobileName windows-only -SmbCredential $credential -Run $run
        Assert ($windowsOnly.Mounts.Count -eq 0 -and $windowsOnly.StorageHosts.Count -eq 0 -and $windowsOnly.Linux.Count -eq 0) 'Windows-only deployment stored null mount entries or prompted for Linux storage'
        $saved = Get-Content (Get-MobileSmbPlanPath orchestrated) -Raw
        $audit = Get-Content $run.Path -Raw
        Assert (-not $saved.Contains('fixture-pass') -and -not $audit.Contains('fixture-pass') -and -not $audit.Contains('payload_b64')) 'Credentials/worker payload leaked into controller state or audit'
        $script:linuxRestoreFails = $true
        $rejected = $false; try { Restore-MobileSmbDeployment $plan $run } catch { $rejected = $true }
        Assert ($rejected -and $script:restoreOrder.Count -eq 1 -and $script:restoreOrder[0] -like 'Linux:*') 'Windows shares were removed despite a Linux unmount failure'
        $script:linuxRestoreFails = $false; $script:restoreOrder = @()
        Restore-MobileSmbDeployment $plan $run
        Assert ($script:restoreOrder.Count -eq 3 -and $script:restoreOrder[0] -eq 'Linux:10.20.1.20' -and $script:restoreOrder[1] -like 'Windows:*') 'Check-in did not unmount Linux before removing Windows shares'
        $statuses = @(Show-MobileSmbStatus orchestrated)
        Assert ($statuses.Count -eq 3 -and (Read-MobileSmbPlan orchestrated).Status -eq 'Restored') 'Post-reboot status did not complete the saved lifecycle'

        'PASS: SMB host/interface selection, IP-based mount plans, configured credentials, nofail mounts, deferred networking, busy-mount gates, preserved fstab entries, and restoration.'
    } $fixture $root
} finally {
    Remove-Module $module -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
