# Offline checks only: all account, network, task and boot commands use harmless substitutes.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobiles-smb-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $fixture | Out-Null
$tokens = $null; $issues = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'MobileManager.psm1'), [ref]$tokens, [ref]$issues)
if ($issues.Count) { throw ($issues.Message -join '; ') }
$names = @('Edit-UserRight','Get-MobileSmbCredential','Get-MobileSmbWindowsNetwork','New-LinuxFsTabEntry','New-WindowsPostTask-Smb',
    'New-WindowsPostTask-UserRights','Get-PostDeployScript','New-LinuxTask-Smb','New-LinuxTask-SmbBoot','New-LinuxTask-RestoreSmbBoot',
    'ConvertTo-BashArgument','Get-LinuxResultHeader','Get-LinuxResultFooter','Register-MobileDeployment')
$parts = $ast.EndBlock.Statements | Where-Object {
    ($_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -in $names) -or
    ($_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$script:WindowsDeployBlock')
} | ForEach-Object { $_.Extent.Text }
$module = New-Module -ScriptBlock ([scriptblock]::Create($parts -join "`n"))
try {
    & $module {
        param($fixture)
        function Assert($condition,$message) { if (-not $condition) { throw $message } }
        function Get-DeploymentTaskSelection { param($Platform,$Phase) 'UserRights' }
        $script:Config = [pscustomobject]@{ SmbUserName='mobile-smb-access'; MobileDump=$fixture; CertName='fixture-cert' }
        # Exercise credential generation/reuse without a Windows certificate store.
        function Get-ChildItem { param($Path) [pscustomobject]@{ Subject='fixture-cert'; HasPrivateKey=$true } }
        function Protect-CmsMessage { [CmdletBinding()] param($To,$Content,$OutFile) $script:password=$Content; Set-Content $OutFile 'encrypted-fixture' }
        function Unprotect-CmsMessage { [CmdletBinding()] param($Path) $script:password }
        $credential = Get-MobileSmbCredential fixture
        $again = Get-MobileSmbCredential fixture
        Assert ($credential.GetNetworkCredential().Password -eq $again.GetNetworkCredential().Password -and $script:password.Length -ge 40) 'SMB credential was rotated or weak'
        Assert ((Get-Content "$fixture/fixture.smb.cms" -Raw).Trim() -eq 'encrypted-fixture') 'Credential persistence bypassed CMS'
        $cfg = "[Privilege Rights]`nSeNetworkLogonRight = *S-1-5-11,*S-1-5-32-544`n"
        $edited = Edit-UserRight $cfg SeNetworkLogonRight S-1-5-21-100 Add
        Assert ((Edit-UserRight $edited SeNetworkLogonRight S-1-5-21-100 Add) -eq $edited) 'Rights were duplicated'
        $removed = Edit-UserRight $edited SeNetworkLogonRight S-1-5-21-100 Remove
        Assert ($removed.Contains('*S-1-5-11,*S-1-5-32-544') -and -not $removed.Contains('S-1-5-21-100')) 'Rights removal lost other principals'
        $network = [pscustomobject]@{ HostName='WIN01'; IP='10.5.6.7'; PrefixLength=24; InterfaceIndex=12; Gateway='10.5.6.1'; Dns=@('10.5.6.2'); Shares=@('C','D') }
        $post = Get-PostDeployScript -SmbNetwork $network -SmbUserName $credential.UserName
        $tokens=$null; $errors=$null
        $postAst=[System.Management.Automation.Language.Parser]::ParseInput($post,[ref]$tokens,[ref]$errors)
        Assert (-not $errors.Count) ('SMB post task does not parse: ' + ($errors.Message -join '; '))
        Assert ($post.Contains('function Edit-UserRight') -and $post.Contains('10.5.6.7') -and -not $post.Contains($script:password)) 'Post task omitted its helper/network or contains a password'
        Assert ($post.Contains('-Sid $smbUserSid') -and -not $post.Contains('@($rights,$denyRights)')) 'SMB denies target the wrong principal'
        $helper=$postAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Edit-UserRight' },$true)
        $generated = & {
            param($definition,$cfg)
            . ([scriptblock]::Create($definition))
            Edit-UserRight $cfg SeNetworkLogonRight S-1-5-21-100 Add
        } $helper.Extent.Text $cfg
        Assert ($generated.Contains('*S-1-5-21-100')) 'The generated rights helper lost its parameter bindings'
        Assert (([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($post))).Length -lt 32000) 'Post task exceeded the Windows command-line length limit'
        # Both account creation and repeated deployment use the same credential without failing on existence.
        function Get-LocalUser { [CmdletBinding()] param($Name) if ($script:exists) { [pscustomobject]@{ Name=$Name } } }
        function New-LocalUser { [CmdletBinding()] param($Name,$Password,$PasswordNeverExpires,$Description) $script:created++ }
        function Set-LocalUser { [CmdletBinding()] param($Name,$Password,$PasswordNeverExpires) $script:updated++ }
        function Enable-LocalUser { [CmdletBinding()] param($Name) $script:enabled++ }
        $payload = [pscustomobject]@{ AllUsers=@(); ProvisioningTasks=@(); TaskData=@(); SmbCredential=$credential; Disjoin=$false; Hooks=@() }
        $first = & $script:WindowsDeployBlock $payload
        $script:exists=$true
        $second = & $script:WindowsDeployBlock $payload
        Assert ($first.Success -and $second.Success -and $script:created -eq 1 -and $script:updated -eq 1 -and $script:enabled -eq 2) 'Existing SMB user was not reused/enabled'
        # Execute the share/network post fragment with command substitutes.
        $script:granted=@(); $script:staticCalls=@()
        function Get-SmbShare { [CmdletBinding()] param($Name) if ($Name -eq 'C') { [pscustomobject]@{ Path='C:\' } } }
        function New-SmbShare { [CmdletBinding()] param($Name,$Path,$FullAccess) $script:newShare=$Name }
        function Grant-SmbShareAccess { [CmdletBinding()] param($Name,$AccountName,$AccessRight,[switch]$Force) $script:granted += $Name }
        function icacls { $global:LASTEXITCODE=0 }
        function Get-NetFirewallRule { [CmdletBinding()] param($Name) $null }
        function New-NetFirewallRule { param($Name,$DisplayName,$Direction,$Action,$Protocol,$LocalPort,$RemoteAddress,$Profile) }
        function netsh { $script:staticCalls += ($args -join ' '); $global:LASTEXITCODE=0 }
        function Set-DnsClientServerAddress { [CmdletBinding()] param($InterfaceIndex,$ServerAddresses) }
        function record_action { param($Category,$Name,$Status,$Details) }
        function record_failure { param($Message) throw $Message }
        $smbNetwork=$network; $smbUserName=$credential.UserName
        & ([scriptblock]::Create((New-WindowsPostTask-Smb)))
        Assert ($script:newShare -eq 'D' -and ($script:granted -join ',') -eq 'C,D') 'Existing/new shares were not granted access'
        Assert ($script:staticCalls[0].Contains('address=10.5.6.7 mask=255.255.255.0 gateway=10.5.6.1 store=persistent')) 'Static address/prefix/gateway changed'

        if ((Get-Command bash -ErrorAction SilentlyContinue) -and (Get-Command jq -ErrorAction SilentlyContinue)) {
            $entries = (New-LinuxFsTabEntry WIN01 10.5.6.7 @('C','D')) -join "`n"
            $fstab = Join-Path $fixture 'fstab'
            $unrelated = '//10.9.8.7/OTHER /existing cifs defaults 0 0'
            Set-Content $fstab $unrelated
            # Redirect file writes and directory creation into this fixture.
            $entries = $entries.Replace('/etc/fstab',$fstab).Replace('/share/',"$fixture/share/")
            $path=Join-Path $fixture 'fstab.sh'
            [IO.File]::WriteAllText($path,$entries)
            & bash $path; & bash $path
            Assert ($LASTEXITCODE -eq 0) 'fstab fragment failed'
            $lines=@(Get-Content $fstab)
            Assert ($lines.Count -eq 3 -and $lines[0] -eq $unrelated) 'fstab repeated run duplicated entries or lost unrelated mounts'
            Assert ($lines[1] -like '//10.5.6.7/C * cifs defaults,_netdev,nofail,sec=ntlmssp,credentials=* 0 0') 'fstab source/options/column order wrong'
            $linux = New-LinuxTask-Smb -Source $network -Credential $credential
            $linux | & bash -n
            Assert ($LASTEXITCODE -eq 0) 'Linux SMB payload does not parse'
            $setup = $linux.Replace('/etc/security/mobiles-smb.conf', "$fixture/credentials").Replace('/etc/fstab',$fstab).Replace('/share/',"$fixture/share/").Replace('/proc/sys/crypto/fips_enabled',"$fixture/fips")
            Set-Content "$fixture/fips" 0
            $mocks = @'
ip() { echo '2: eth0 inet 10.2.3.4/24 brd 10.2.3.255 scope global eth0'; }
nmcli() {
    if [[ "$1" == -g ]]; then
        case "$2" in GENERAL.CON-UUID) echo fixture-uuid ;; IP4.GATEWAY) echo 10.2.3.1 ;; IP4.DNS) echo 10.2.3.2 ;; esac
    else printf '%s\n' "$*" >> __NETWORK__; fi
}
dzdo() { "$@"; }
function mount.cifs() { :; }
export -f ip nmcli dzdo mount.cifs
'@
            $setupPath=Join-Path $fixture 'setup.sh'
            $scriptText=(Get-LinuxResultHeader)+"`n"+$mocks.Replace('__NETWORK__',"$fixture/network")+"`n"+$setup+"`n"+(Get-LinuxResultFooter)
            [IO.File]::WriteAllText($setupPath,$scriptText)
            $reply=((& bash $setupPath) -join "`n") | ConvertFrom-Json
            Assert ($LASTEXITCODE -eq 0 -and $reply.Success -and $reply.Actions[0].Status -eq 'Prepared') 'Linux preparation corrupted its host result or failed'
            Assert ($reply.Actions[0].Details.Contains('10.2.3.4/24') -and -not ($reply | ConvertTo-Json -Depth 5).Contains($script:password)) 'Linux network snapshot was lost or exposed a password'
            Assert ((Get-Content "$fixture/network" -Raw).Contains('ipv4.method manual ipv4.addresses 10.2.3.4/24 ipv4.gateway 10.2.3.1 ipv4.dns 10.2.3.2')) 'Linux current IP/gateway/DNS was not persisted'
            $permissions = & stat -c %a "$fixture/credentials"
            Assert ($permissions -eq '600') 'Linux credential permissions are not private'
            # Run boot setup on both legacy GRUB and BLS fixtures, including a second run and restoration.
            foreach ($bls in @($false,$true)) {
                $bootRoot=Join-Path $fixture "boot-$bls"
                New-Item -ItemType Directory "$bootRoot/entries" | Out-Null
                $boot = (New-LinuxTask-SmbBoot).Replace('/proc/sys/crypto/fips_enabled',"$bootRoot/fips").Replace('/etc/security/mobiles-smb-boot-original',"$bootRoot/original").Replace('/boot/loader/entries',"$bootRoot/entries")
                Set-Content "$bootRoot/fips" 1
                if ($bls) { Set-Content "$bootRoot/entries/original.conf" "title Normal`nlinux /vmlinuz`noptions root=UUID=fixture fips=1 quiet" }
                $mock = @'
set -e
mobile=0
normal=1
grubby() {
    case "$1" in
        --default-title) echo Normal ;;
        --info=DEFAULT) printf '%s\n' 'kernel="/boot/vmlinuz"' 'initrd="/boot/initrd"' 'id="original"' 'args="root=UUID=fixture fips=1 quiet"' ;;
        '--info=TITLE=Mobile SMB (fips=0)') if [[ $mobile == 1 || -f __ROOT__/entries/original-mobiles-smb.conf ]]; then echo index=0; else return 1; fi ;;
        --info=TITLE=Normal) echo index=1 ;;
        --add-kernel=*) mobile=1 ;;
        --set-default-index=0) normal=0 ;;
        --set-default-index=1) normal=1 ;;
        --remove-kernel=0) mobile=0; rm -f __ROOT__/entries/original-mobiles-smb.conf ;;
        *) echo "Unexpected grubby argument: $1" >&2; return 1 ;;
    esac
}
'@
                $mock=$mock.Replace('__ROOT__',$bootRoot)
                $bootPath=Join-Path $bootRoot 'setup.sh'
                [IO.File]::WriteAllText($bootPath,$mock+"`n"+$boot+"`n"+$boot)
                & bash $bootPath | Out-Null
                Assert ($LASTEXITCODE -eq 0 -and (Get-Content "$bootRoot/original") -eq 'Normal') 'Boot setup/repeat lost the original default'
                if ($bls) {
                    $original=Get-Content "$bootRoot/entries/original.conf" -Raw
                    $clone=Get-Content "$bootRoot/entries/original-mobiles-smb.conf" -Raw
                    Assert ($original.Contains('fips=1') -and $clone.Contains('fips=0') -and -not $clone.Contains('fips=1')) 'BLS clone modified the original or retained fips=1'
                }
                $restore=(New-LinuxTask-RestoreSmbBoot).Replace('/etc/security/mobiles-smb-boot-original',"$bootRoot/original")
                # Export the same safe grubby substitute into the privileged child shell.
                $restoreMocks=$mock+"`n"+@'
dzdo() { "$@"; }
export -f grubby dzdo
record_action() { :; }
record_failure() { echo "$@" >&2; exit 1; }
'@+"`n"
                [IO.File]::WriteAllText($bootPath,$restoreMocks+$restore)
                & bash $bootPath | Out-Null
                Assert ($LASTEXITCODE -eq 0 -and -not (Test-Path "$bootRoot/original") -and -not (Test-Path "$bootRoot/entries/original-mobiles-smb.conf")) 'Boot restoration failed or left its marker/clone'
            }
        }
        # Exercise controller wiring without remoting, keys, account changes or actual task registration.
        function New-MobileRunLog { param($MobileName,$Procedure) [pscustomobject]@{ Id='fixture'; Path='fixture'; ReadablePath='fixture' } }
        function Write-MobileRunEvent { param($Run,$Event,$Data) }
        function Get-MobileProcedureHooks { param($Procedure) @() }
        function Get-WindowsProcedureHookRunner { { } }
        function Get-MobileData { param($MobileName) [pscustomobject]@{ Windows=@('WIN01','WIN02'); Linux=@('linux'); AllUsers=@() } }
        function Assert-MobileEnvironment { param([switch]$Linux) }
        function Get-DeploymentTaskSelection { param($Platform,$Phase) if ($Phase -eq 'Scheduled') { 'PostDeploy' } }
        function Get-UserCreds { param($MobileName,$AllUsers,$mobileDumpPath) @() }
        function Get-MobileSmbWindowsNetwork { param($Computers)
            foreach ($name in $Computers) { [pscustomobject]@{ HostName=$name; IP='10.5.6.7'; PrefixLength=24; Shares=@('C') } }
        }
        function Get-MobileSmbCredential { param($MobileName) $credential }
        function Get-TaskData { param($hasLinux,$SmbNetwork,$SmbUserName)
            [pscustomobject]@{ TaskName='fixture'; Host=$SmbNetwork.HostName; User=$SmbUserName }
        }
        function Invoke-Command { [CmdletBinding()] param($ComputerName,$ScriptBlock,$ArgumentList)
            $script:visited += $ComputerName
            Assert ($ComputerName -notlike '10.*') 'Controller used IP-based WinRM'
            if ($ArgumentList.SmbCredential) {
                Assert ($ArgumentList.TaskData[0].Host -eq $ComputerName -and $ArgumentList.SmbCredential.UserName -eq 'mobile-smb-access') 'Host-specific task/credential was not forwarded'
            }
            foreach ($name in $ComputerName) { [pscustomobject]@{ PSComputerName=$name; Success=$true; Actions=@(); Failures=@() } }
        }
        function ConvertFrom-WindowsDeploymentResult { param($Results,$Computers,$TransportErrors) $Results }
        function Get-LinuxDeployScript { param($allUsers,$Hooks,$MobileName,$RunId,$SmbSource,$SmbCredential)
            $script:linuxSmbSource=$SmbSource
            if ($SmbSource) { Assert ($SmbSource.HostName -eq 'WIN01' -and $SmbCredential.UserName -eq 'mobile-smb-access') 'Selected source/credential was not forwarded to Linux' }
            'fixture'
        }
        function Invoke-Linux { param($Computers,$Script,$KeyPath) [pscustomobject]@{ Success=$true } }
        function ConvertFrom-LinuxDeploymentResult { param($Results) $Results }
        function Format-DeploymentResults { param($results,$allUsers) }
        $script:visited=@()
        Register-MobileDeployment fixture -SmbHost WIN01
        Assert (($script:visited -join ',') -eq 'WIN01,WIN02' -and $script:linuxSmbSource.HostName -eq 'WIN01') 'SMB deployment missed Windows members or the selected source'
        $script:visited=@()
        Register-MobileDeployment fixture -SmbHost ' '
        Assert ($script:visited.Count -eq 2 -and $null -eq $script:linuxSmbSource) 'Blank SMB host did not skip optional preparation'
        $script:visited=@(); $rejected=$false
        try { Register-MobileDeployment fixture -SmbHost misspelled } catch { $rejected=$true }
        Assert ($rejected -and $script:visited.Count -eq 0) 'Invalid SMB host reached deployment'
        'PASS: SMB credential reuse, rights preservation, existing accounts/shares, static IPv4, secret-free post tasks, idempotent fstab and GRUB/BLS boot clones.'
    } $fixture
} finally {
    Remove-Module $module -ErrorAction SilentlyContinue
    Remove-Item $fixture -Recurse -Force
}
