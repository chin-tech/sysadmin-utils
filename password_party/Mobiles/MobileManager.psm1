# --- Configuration Loader ---
$manifestCfg = $Script:DefaultConfig = $MyInvocation.MyCommand.Module.PrivateData.PSData.DefaultConfig

$adminRoot = $PSScriptRoot
$mobileRoot = Join-Path $manifestCfg.nfsHomeRoot ".mobiles"

$script:Config = [PSCustomObject]@{
    GpoID             = $manifestCfg.GpoID
    nfsHomeRoot       = $manifestCfg.nfsHomeRoot
    # LinuxBastion      = $manifestCfg.linuxBastion
    SshKeyName        = $manifestCfg.sshKey
    CertName          = $manifestCfg.CertName
    fallbackPass      = $manifestCfg.fallbackPass
    curLuks           = $manifestCfg.curLuks
    encryptionPin     = $manifestCfg.encryptionPin
    AdminRoot         = $adminRoot
    NfsHome           = (Join-Path $manifestCfg.nfsHomeRoot $env:USERNAME)
    MobileRoot        = $mobileRoot
    MobileEntries     = (Join-Path $mobileRoot 'entries')     # Or wherever mobile INI/text files live
    mobileDefaultUsers      = (Join-Path $mobileRoot '.default')
    MobileDump        = (Join-Path $mobileRoot '.dump')
    MobileDeployments = (Join-Path $mobileRoot '.deployments')
}

function Get-MobileConfig
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$CustomConfig
    )

    $merged = @{}

    # Copy defaults from the base script Config
    if ($script:Config)
    {
        foreach ($prop in $script:Config.PSObject.Properties)
        {
            $merged[$prop.Name] = $prop.Value
        }
    }

    # Overlay user-provided configs (supports Hashtable, PSCustomObject, or IDictionary)
    if ($CustomConfig)
    {
        if ($CustomConfig -is [System.Collections.IDictionary])
        {
            foreach ($k in $CustomConfig.Keys)
            {
                $merged[$k] = $CustomConfig[$k]
            }
        } else
        {
            foreach ($prop in $CustomConfig.PSObject.Properties)
            {
                $merged[$prop.Name] = $prop.Value
            }
        }
    }

    return [PSCustomObject]$merged
}

# --- Private Helper Functions (Not Exported) ---
#

#### UTILS

$Sha512CryptSource = @"
using System;
using System.Text;
using System.Security.Cryptography;

public class Sha512Crypt
{
    private const string B64Alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    public static string Crypt(string password, string salt = null, int rounds = 5000)
    {
        if (salt == null)
        {
            byte[] saltBytes = new byte[12];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(saltBytes);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 12; i++) sb.Append(B64Alphabet[saltBytes[i] % 64]);
            salt = sb.ToString();
        }
        else if (salt.Length > 16)
        {
            salt = salt.Substring(0, 16);
        }

        byte[] keyBytes = Encoding.UTF8.GetBytes(password);
        byte[] saltBytesArray = Encoding.UTF8.GetBytes(salt);

        using (SHA512 sha = SHA512.Create())
        {
            // Digest B
            sha.TransformBlock(keyBytes, 0, keyBytes.Length, null, 0);
            sha.TransformBlock(saltBytesArray, 0, saltBytesArray.Length, null, 0);
            sha.TransformFinalBlock(keyBytes, 0, keyBytes.Length);
            byte[] altResult = sha.Hash;

            // Digest A
            sha.Initialize();
            sha.TransformBlock(keyBytes, 0, keyBytes.Length, null, 0);
            sha.TransformBlock(saltBytesArray, 0, saltBytesArray.Length, null, 0);
            
            for (int i = keyBytes.Length; i > 64; i -= 64)
                sha.TransformBlock(altResult, 0, 64, null, 0);
            if (keyBytes.Length % 64 > 0)
                sha.TransformBlock(altResult, 0, keyBytes.Length % 64, null, 0);

            for (int i = keyBytes.Length; i > 0; i >>= 1)
            {
                if ((i & 1) != 0)
                    sha.TransformBlock(altResult, 0, 64, null, 0);
                else
                    sha.TransformBlock(keyBytes, 0, keyBytes.Length, null, 0);
            }
            sha.TransformFinalBlock(new byte[0], 0, 0);
            byte[] pResult = sha.Hash;

            // P-Sequence
            sha.Initialize();
            for (int i = 0; i < keyBytes.Length; i++)
                sha.TransformBlock(keyBytes, 0, keyBytes.Length, null, 0);
            sha.TransformFinalBlock(new byte[0], 0, 0);
            byte[] pBytes = new byte[keyBytes.Length];
            for (int i = 0; i < keyBytes.Length; i++)
                pBytes[i] = sha.Hash[i % 64];

            // S-Sequence
            sha.Initialize();
            for (int i = 0; i < 16 + pResult[0]; i++)
                sha.TransformBlock(saltBytesArray, 0, saltBytesArray.Length, null, 0);
            sha.TransformFinalBlock(new byte[0], 0, 0);
            byte[] sBytes = new byte[saltBytesArray.Length];
            for (int i = 0; i < saltBytesArray.Length; i++)
                sBytes[i] = sha.Hash[i % 64];

            // 5000+ Rounds
            for (int i = 0; i < rounds; i++)
            {
                sha.Initialize();
                if ((i & 1) != 0)
                    sha.TransformBlock(pBytes, 0, pBytes.Length, null, 0);
                else
                    sha.TransformBlock(pResult, 0, 64, null, 0);

                if (i % 3 != 0)
                    sha.TransformBlock(sBytes, 0, sBytes.Length, null, 0);

                if (i % 7 != 0)
                    sha.TransformBlock(pBytes, 0, pBytes.Length, null, 0);

                if ((i & 1) != 0)
                    sha.TransformBlock(pResult, 0, 64, null, 0);
                else
                    sha.TransformBlock(pBytes, 0, pBytes.Length, null, 0);

                sha.TransformFinalBlock(new byte[0], 0, 0);
                pResult = sha.Hash;
            }

            // Custom Base64 Encoding
            StringBuilder res = new StringBuilder();
            if (rounds != 5000) res.AppendFormat("`$6`$rounds={0}`${1}`$", rounds, salt);
            else res.AppendFormat("`$6`${0}`$", salt);

            int[][] order = new int[][] {
                new int[] {0, 21, 42}, new int[] {22, 43, 1}, new int[] {44, 2, 23},
                new int[] {3, 24, 45}, new int[] {25, 46, 4}, new int[] {47, 5, 26},
                new int[] {6, 27, 48}, new int[] {28, 49, 7}, new int[] {50, 8, 29},
                new int[] {9, 30, 51}, new int[] {31, 52, 10}, new int[] {53, 11, 32},
                new int[] {12, 33, 54}, new int[] {34, 55, 13}, new int[] {56, 14, 35},
                new int[] {15, 36, 57}, new int[] {37, 58, 16}, new int[] {59, 17, 38},
                new int[] {18, 39, 60}, new int[] {40, 61, 19}, new int[] {62, 20, 41}
            };

            foreach (var trio in order)
            {
                int val = (pResult[trio[0]] << 16) | (pResult[trio[1]] << 8) | pResult[trio[2]];
                for (int j = 0; j < 4; j++) { res.Append(B64Alphabet[val & 0x3F]); val >>= 6; }
            }

            int lastVal = pResult[63];
            for (int j = 0; j < 2; j++) { res.Append(B64Alphabet[lastVal & 0x3F]); lastVal >>= 6; }

            return res.ToString();
        }
    }
}
"@

# Load the class into memory once per session
if (-not ([System.Management.Automation.PSTypeName]'Sha512Crypt').Type)
{
    Add-Type -TypeDefinition $Sha512CryptSource
}



function Set-Groups
{
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [array]$Groups
    )

    $grps = @("local")
    if ($Groups.Length -eq 0)
    {
        return $grps
    }

    foreach ($g in $Groups)
    {
        switch -WildCard ($g)
        {
            'i*'
            { return @('isso')
            }
            't*'
            { return @('adm')
            }
            'p*'
            {$grps += @("priv")
            }
            'd*rw'
            { $grps += @("dtrw")
            }
            'd*ro'
            { $grps += @("dtro")
            }
        }
    }
    return $grps
}


enum TaskTriggerType
{
    Time         = 1
    Daily        = 2
    Weekly       = 3
    Registration = 7
    Boot         = 8
    Logon        = 9
}

function New-TaskXML
{
    [CmdletBinding()]
    param(
        [Parameter()][string]$Description = "Automated Task",
        [Parameter()][string]$Author = "SYSTEM",
        
        [Parameter(Mandatory=$true)]
        [string]$Execute,
        
        [Parameter()]
        [string]$Arguments = "",
        
        # Pass a hashtable or array of hashtables describing triggers
        [Parameter()]
        [hashtable[]]$TriggerConfigs = @(@{ Type = [TaskTriggerType]::Boot }),
        
        [Parameter()][string]$UserId = "NT AUTHORITY\SYSTEM",
        [Parameter()][int]$LogonType = 5, # 5 = TASK_LOGON_SERVICE / SYSTEM
        [Parameter()][int]$RunLevel = 1,  # 1 = TASK_RUNLEVEL_HIGHEST
        
        [Parameter()][bool]$Hidden = $true,
        [Parameter()][string]$ExecutionTimeLimit = "PT72H"
    )

    $ts = New-Object -ComObject "Schedule.Service"
    $ts.Connect()

    # 0 = TASK_CREATE (Task Definition)
    $taskDef = $ts.NewTask(0)
    
    # 1. Registration Info
    $taskDef.RegistrationInfo.Description = $Description
    $taskDef.RegistrationInfo.Author = $Author

    # 2. Task Settings
    $taskDef.Settings.Enabled = $true
    $taskDef.Settings.Hidden = $Hidden
    $taskDef.Settings.StartWhenAvailable = $true
    $taskDef.Settings.AllowDemandStart = $true
    $taskDef.Settings.WakeToRun = $true
    $taskDef.Settings.DisallowStartIfOnBatteries = $false
    $taskDef.Settings.StopIfGoingOnBatteries = $false
    $taskDef.Settings.ExecutionTimeLimit = $ExecutionTimeLimit

    # 3. Principal Configuration
    $taskDef.Principal.UserId = $UserId
    $taskDef.Principal.LogonType = $LogonType
    $taskDef.Principal.RunLevel = $RunLevel

    # 4. Triggers Configuration
    foreach ($cfg in $TriggerConfigs)
    {
        $tType = [TaskTriggerType]$cfg.Type
        $trigger = $taskDef.Triggers.Create([int]$tType)
        $trigger.Enabled = if ($cfg.ContainsKey('Enabled'))
        { $cfg.Enabled 
        } else
        { $true 
        }
        
        if ($cfg.ContainsKey('StartBoundary'))
        {
            $trigger.StartBoundary = $cfg.StartBoundary
        }

        switch ($tType)
        {
            ([TaskTriggerType]::Logon)
            {
                # Specific user or $null / empty string for all users
                if ($cfg.ContainsKey('UserId'))
                {
                    $trigger.UserId = $cfg.UserId
                }
                if ($cfg.ContainsKey('Delay'))
                {
                    $trigger.Delay = $cfg.Delay # e.g. "PT30S"
                }
            }
            ([TaskTriggerType]::Boot)
            {
                if ($cfg.ContainsKey('Delay'))
                {
                    $trigger.Delay = $cfg.Delay # e.g. "PT1M"
                }
            }
            ([TaskTriggerType]::Daily)
            {
                $trigger.DaysInterval = if ($cfg.ContainsKey('DaysInterval'))
                { $cfg.DaysInterval 
                } else
                { 1 
                }
                if (-not $trigger.StartBoundary)
                {
                    $trigger.StartBoundary = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
                }
            }
            ([TaskTriggerType]::Weekly)
            {
                $trigger.WeeksInterval = if ($cfg.ContainsKey('WeeksInterval'))
                { $cfg.WeeksInterval 
                } else
                { 1 
                }
                # DaysOfWeek bitmask: 1=Sun, 2=Mon, 4=Tue, 8=Wed, 16=Thu, 32=Fri, 64=Sat
                $trigger.DaysOfWeek = if ($cfg.ContainsKey('DaysOfWeek'))
                { $cfg.DaysOfWeek 
                } else
                { 2 
                } # Monday default
                if (-not $trigger.StartBoundary)
                {
                    $trigger.StartBoundary = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
                }
            }
            ([TaskTriggerType]::Time)
            {
                if (-not $trigger.StartBoundary)
                {
                    $trigger.StartBoundary = (Get-Date).AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss")
                }
            }
            ([TaskTriggerType]::Registration)
            {
                if ($cfg.ContainsKey('Delay'))
                {
                    $trigger.Delay = $cfg.Delay
                }
            }
        }
    }

    # 5. Action Configuration (0 = ExecAction)
    $action = $taskDef.Actions.Create(0)
    $action.Path = $Execute
    $action.Arguments = $Arguments

    return $taskDef.XmlText
}

function ConvertTo-BashArgument
{
    param([string]$v)
    "'" + $v.Replace("'","'\''") + "'"
}

function Invoke-Linux
{
    param(
        [string]$mobileName,
        [string]$bastionHost,
        [string]$sshKeyPath,
        [string]$scriptName,
        [string[]]$extraArgs
    )
    $a = @($mobileName) + $extraArgs
    $remoteArgs = ($a | ForEach-Object { ConvertTo-BashArgument $_}) -join ' '


    (Get-Content $scriptName -Raw) -replace "`r`n","`n" | ssh -i $sshKeyPath -q $bastionHost "bash -s -- $remoteArgs"
}



function New-DeployerCertificate
{
    [CmdletBinding()]
    param(
        [Parameter()][securestring]$certPass = (ConvertTo-SecureString -AsPlainText -Force 'deployer'),
        [Parameter()][string]$outPath = "\\nas\home\$env:USERNAME"
    )
    $c = New-SelfSignedCertificate -Subject 'CN=MobileDeployer' -Type DocumentEncryptionCert -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5)
    Export-PFXCertificate -Cert $c -FilePath (Join-Path $outPath "Deployer.pfx") -Password $certPass
    Export-Certificate -Cert $c -FilePath (Join-Path $outPath "Deployer.cer") 
    
}



function Initialize-Ssh-Environment
{
    [CmdletBinding()]
    param(
        [Parameter()][string]$KeyName = 'deployer',
        [Parameter()][string]$nfsHome 
    )
    # r = remote ; l = local
    $nfsSSH = Join-Path  $nfsHome '.ssh'
    $localSSh = Join-Path "${env:HOME}" ".ssh"
    $rConfig = Join-Path  $nfsSSH 'config'
    $rAuthorized = Join-Path $nfsSSH 'authorized_keys'
    $rKey = Join-Path $nfsSSH $keyName


    @($nfsSSH, $localSSH) | Where-Object { -not (Test-Path $_) } | ForEach-Object {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }

    if (-not (Select-String -Pattern $KeyName -Path $rConfig -Quiet))
    {
        if (-not (Test-Path $rKey))
        {
            ssh-keygen -f "$rKey" -C "''" -N "''" -t ecdsa -q
        }
        $pubKey = ssh-keygen -yf $rKey

        if (-not (Select-String -Pattern $pubKey -Path $rAuthorized))
        {
            $pubKey | Add-Content -Encoding UTF8 -Path $rAuthorized
        }
        
    }

}

function Get-PostDeployScript
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$userRights,
        [switch]$Sharing,
        [switch]$acls,

        [Parameter()]
        [array]$driveLetters
    )

    $s = [System.Collections.Generic.List[string]]::new()

    $s.Add(@'
# ==================
# Automated Post-Deployment
# (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# ==================
'@)
    if ($userRights)
    {
        if ($sharing)
        {
            $smbPass = "SupeSecretSMBP@ssw0rd99"
            $s.Add(@"
New-LocalUser -Name mobile-smb-access -Password (ConvertTo-SecureString -AsPlainText -Force '$smbPass')
`$sharingSid = (Get-LocalUser -Name mobile-smb-access).Sid.Value
"@)
        }
        $s.Add(@'
$tmpSec = Join-Path $env:TEMP sec_export.inf
$tmpDB  = Join-Path $env:TEMP sec_temp.sdb

secedit /export /cfg $tmpSec /quiet
$objUser = New-Object System.Security.Principal.NTAccount("Authenticated Users")
$objSid = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
$secSid = "*$objSid"
$rights = @('SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight', 'SeNetworkLogonRight')
$denyRights = @( 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight')

$cfg = Get-Content -Raw -Encoding Unicode $tmpSec
for ($r in $rights) {
    if (-not ($cfg.Contains($r))) {
        Add-Content -Path $tmpSec -Value "`n$r = $secSid"
    } else {
        $pattern = "(?m)^\s*$([regex]::Escape($r))\s*=[^\r\n]*"
        $line = [regex]::Match($cfg,$pattern).Value
        if ($line -match "$objSid") { continue }
        $cfg = $cfg -replace $pattern, "`$0,$secSid"
        
    }

}
if ($null -ne $sharingSid) {
    $shareSid = "*${sharingSid}"
    for ($r in $denyRights) {

        if (-not ($cfg.Contains($r))) {
            Add-Content -Path $tmpSec -Value "`n$r = $shareSid"
        } else {
            $pattern = "(?m)^\s*$([regex]::Escape($r))\s*=[^\r\n]*"
            $line = [regex]::Match($cfg,$pattern).Value
            if ($line -match "$sharingSid") { continue }
            $cfg = $cfg -replace $pattern, "`$0,$shareSid"
            
        }

    }
}

$cfg | Set-Content -Path $tmpSec 

secedit /configure /db $tmpDB /cfg $tmpSec /areas USER_RIGHTS /quiet
Remove-Item $tmpSec,$tmpDB -Force -ErrorAction SilentlyContinue
'@)

    }

    if ($Sharing)
    {
        if ($null -ne  $driveLetters)
        {
            $driveList = ($driveLetters | ForEach-Object { "'$_'" }) -join ','
            $s.Add(@"
`$driveList = $driveList
"@)
        }
        $s.Add(@'
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue
if ($null -eq $driveList) { $driveList  = (Get-PSDrive -PSProvider Filesystem).Name} 
foreach ($d in $driveList) {
    if (Test-Path $d) {
        if (-not (Get-SMBShare -Name $d -ErrorAction SilentlyContinue)) {
            New-SMBShare -Name $d -Path $d -FullAccess 'Authenticated Users','mobile-smb-access' | Out-Null
        }
    }
}

'@)
    }

    if ($acls)
    {
        $s.Add(@'
icacls.exe C:\Support /inheritance:r /T /Q
icacls.exe C:\Support /grant Administrators:F ISSO:F /T /Q

'@)
    }

    $s.Add('"[ Post Deployment Ran - $(Get-Date)]" | Out-File C:\Post-Deploy.info ')
    return ($s -join "`n`n")
}



# function Get-UserFullName
# {
#     [CmdLetBinding()]
#     param(
#         [Parameter()][string]$UserName,
#         [Parameter()][string]$FullName
#     )
#
#     if ([String]::IsNullOrWhiteSpace($FullName))
#     {
#         $uData = Get-ADUser -Filter "SamAccountName -eq '$UserName'" -Properties Name,DisplayName,GivenName,Surname 
#         if (! ([string]::IsNullOrWhiteSpace($uData.DisplayName)))
#         { 
#             return $uData.DisplayName 
#         }
#         if (! ([string]::IsNullOrWhiteSpace($uData.GivenName) -and [string]::IsNullOrWhiteSpace($uData.SurName)))
#         { 
#             return $uData.GivenName + $uData.Surname 
#         }
#     }
#
#     return $FullName
#
# }

function Get-UserFullName
{
    [CmdletBinding()]
    param(
        [Parameter()][string]$UserName,
        [Parameter()][string]$FullName
    )

    if ([string]::IsNullOrWhiteSpace($FullName) -and -not [string]::IsNullOrWhiteSpace($UserName))
    {
        $searcher = [System.DirectoryServices.DirectorySearcher]::new()
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$([System.Security.SecurityElement]::Escape($UserName))))"
        $searcher.PropertiesToLoad.AddRange(@('displayName', 'givenName', 'sn'))

        $result = $searcher.FindOne()
        if ($result)
        {
            $props = $result.Properties
            if ($props.Contains('displayName') -and -not [string]::IsNullOrWhiteSpace($props['displayName'][0]))
            {
                return $props['displayName'][0]
            }

            $first = if ($props.Contains('givenName'))
            { $props['givenName'][0] 
            } else
            { '' 
            }
            $last  = if ($props.Contains('sn'))
            { $props['sn'][0] 
            } else
            { '' 
            }
            $combined = "$first $last".Trim()

            if (-not [string]::IsNullOrWhiteSpace($combined))
            {
                return $combined
            }
        }
    }

    return $FullName
}



function Get-LinuxDeployScript
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$allUsers,
        [Parameter(Mandatory = $true)]
        [string]$oldEncryption,

        [Parameter(Mandatory = $true)]
        [string]$encryptionPin,
        [Parameter(Mandatory = $true)]
        [string]$nfsHome

    )

    $linuxUsernames = @{}
    foreach ($u in $allUsers)
    {
        $baseName = ($u.Name -split '\.')[0]
        switch -Regex ($u.Name)
        {
            'dt[ro]$'
            { continue 
            }
            '(priv|admin)$'
            {
                $linuxUsernames[$baseName] = "admin:$($u.MustChangePassword):$($baseName):$($u.LinuxPassword)"
                continue
            }
            default
            {
                if (-not ($linuxUsernames.ContainsKey($baseName)))
                {
                    $linuxUsernames[$baseName] = "local:$($u.MustChangePassword):$($baseName):$($u.LinuxPassword)"
                }

            }
        }
    }

    $userFile = Join-Path $nfsHome "mobile.users"
    $linuxUsernames.Values | Set-Content -Path $userFile -Encoding UTF8

    ## Generate script that has content in NFS share, so each host will have this content
    $scriptContent = @'
#!/usr/bin/env bash
mHome='/mobiles/home'

dzdo mkdir -p $mHome
while IFS=: read -r admin expire username pwhash; do
    addToWheel=""
    [[ $admin == "admin" ]] && addToWheel="-G wheel"
    [[ -z $username ]] && continue
    if id "$username" &>/dev/null; then
        dzdo usermod -p "$pwhash" $addToWheel "$username"
    else
        dzdo useradd $addToWheel -m -b $mHome -c 'Mobile' -p "$pwhash" "$username"
    fi
    if [[ $expire == "true" ]]; then
        dzdo chage -d 0 "$username"
    fi
done < mobile.users

cat << 'EOF' | dzdo tee /etc/systemd/system/mobile-logrotate.timer > /dev/null
[Unit]
Description=Mobile Log Rotate Timer
[Timer]
OnCalendar=Sun 23:59
Persistent=True
[Install]
WantedBy=timers.target
EOF

cat << 'EOF' |  dzdo tee /etc/systemd/system/mobile-logrotate.service > /dev/null
[Unit]
Description=Mobile Log Rotate Service
[Service]
Restart=on-failure
RemainAfterExit=no
ExecStart=/path-to-logrotate
[Install]
WantedBy=multi-user.target
EOF

dzdo systemctl daemon-reload
dzdo systemctl enable --now mobile-logrotate.timer

mapfile -t luks_devices < <(lsblk -rno PATH,FSTYPE | awk '$2 == "crypto_LUKS" {print $1}')
for dev in "${luks_devices[@]}"; do
'@
    $scriptContent += @"
    printf "%s\n%s\n" "$oldEncryption" "$encryptionPin" | dzdo cryptsetup luksAddKey --force --batch-mode `$dev
done
"@
    return $scriptContent
}

### END UTILS

function Get-EncryptedCredRSA
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PassFile,
        [Parameter(Mandatory = $true)]
        [string]$DefaultPass,
        [Parameter(Mandatory = $true)]
        [string]$PfxPath
    )

    if (-not (Test-Path $PassFile) -or -not (Test-Path $PfxPath))
    {
        return $DefaultPass
    }

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath)
    $rsa  = $cert.GetRSAPrivateKey()

    try
    {
        $eBytes  = [System.Convert]::FromBase64String((Get-Content $PassFile -Raw).Trim())
        $padding = [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1
        $dBytes  = $rsa.Decrypt($eBytes, $padding)
        return [System.Text.Encoding]::UTF8.GetString($dBytes)
    } catch
    {
        Write-Warning "Decryption failed for $PassFile. Returning default password."
        return $DefaultPass
    } finally
    {
        if ($rsa)
        { $rsa.Dispose() 
        }
        if ($cert)
        { $cert.Dispose() 
        }
    }
}

#### USER PASSWORD AND DERIVATION FUNCTIONS

function Get-UserCreds
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MobileName,
        [Parameter(Mandatory = $true)][array]$AllUsers,
        [Parameter(Mandatory = $true)][string]$mobileDumpPath
    )

    $ADUsers = $AllUsers.Name | ForEach-Object { ($_ -split '\.')[0] } | Sort-Object -unique
    foreach ($u in $ADUsers)
    {
        $PwFile = Join-Path  $mobileDumpPath $u
        if ( ! (Test-Path $PwFile ))
        {
            continue
        }
        $content = Unprotect-CmsMessage -Content (Get-Content $PwFile)
        foreach ($line in $content.Split('\r?\n'))
        {
            $timestamp, $username, $pw = $line -split (':')
            foreach ($userObject in $AllUsers)
            {
                if ($userObject.Name -eq $username)
                {
                    $userObject.Password = ConvertTo-SecureString -AsPlainText -Force $pw
                    $userObject.LinuxPassword = [Sha512Crypt]::Crypt($pw)
                }
            }
        }
    }

    $pw = $null
    [System.GC]::Collect()
    return $AllUsers
}

# --- Public Exported Functions ---







## MOBILE RETRIEVAL

function Get-MobileData
{
    [CmdletBinding(DefaultParameterSetName = 'ExplicitPaths')]
    param(
        [Parameter(Position = 0)]
        [string]$MobileName,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ExplicitPaths')]
        [string]$defaultUserpath,
        [Parameter(Mandatory = $true, ParameterSetName = 'ExplicitPaths')]
        [string]$mobileEntriesPath,
        [Parameter(Mandatory = $true, ParameterSetName = 'ExplicitPaths')]
        [string]$fallbackPass,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Config')]
        [PSCustomObject]$Config

    )



    if ($PSCmdlet.ParameterSetName -eq 'Config')
    {
        $defaultUserpath = $Config.mobileDefaultUsers
        $mobileEntriesPath = $config.MobileEntries
        $fallbackPass = $config.fallbackPass
    }


    $result = [PsCustomObject]@{
        AllMobiles   = @()
        MobileUsers  = @()
        DefaultUsers = @()
        AllUsers     = @()
        Linux        = @()
        Windows      = @()
    }

    if (Test-Path $mobileEntriesPath)
    {
        $result.AllMobiles = Get-ChildItem -Path $mobileEntriesPath  |
            Select-Object -ExpandProperty BaseName -Unique
    }

    if ([string]::IsNullOrWhiteSpace($MobileName))
    {
        return [PSCustomObject]$result
    }
    ## Default users
    $result.DefaultUsers = Get-ChildItem -Force -Path $defaultUserpath | Get-Content | ConvertFrom-CSV 


    ## Actual Mobile Data
    $path = Join-Path $mobileEntriesPath $MobileName

    $currentSection = $null
    $sections = @{}

    foreach ($line in Get-Content $path)
    {
        $trimmed = $line.Trim()

        if (
            [string]::IsNullOrWhiteSpace($trimmed) -or
            $trimmed.StartsWith('#') -or
            $trimmed.StartsWith(';')
        )
        {
            continue
        }

        if ($trimmed -match '^\[(?<Header>.+)\]$')
        {
            $currentSection = $Matches.Header

            if (-not $sections.ContainsKey($currentSection))
            {
                $sections[$currentSection] =
                [System.Collections.Generic.List[string]]::new()
            }

            continue
        }

        if ($null -ne $currentSection)
        {
            $sections[$currentSection].Add($trimmed)
        }
    }

    if ($sections.ContainsKey('users'))
    {
        $result.MobileUsers = @(
            $sections['users'] |
                ConvertFrom-Csv |
                ForEach-Object {
                    [PSCustomObject]@{
                        Username = $_.username
                        Groups   = if ($_.groups)
                        {
                            $_.groups -split ';'
                        } else
                        {
                            @()
                        }
                        Name = $_.name
                    }
                }
        )
    }

    if ($sections.ContainsKey('Windows'))
    {
        $result.Windows = @($sections['Windows'])
    }

    if ($sections.ContainsKey('Linux'))
    {
        $result.Linux = @($sections['Linux'])
    }
    $tmp = @($result.DefaultUsers) + @($result.MobileUsers)

    $allUsers = [System.Collections.Generic.List[object]]::new()

    foreach ($u in $tmp)
    {
        $fullName = Get-UserFullName $u.Username $u.Name
        $grps = Set-Groups $u.Groups
        foreach ($grp in $grps)
        {
            $desc = "[Mobile] $($u.Name) - "
            switch -Regex ($grp)
            {
                '^a.*'
                {$desc += 'System Administrator'
                }
                '^i.*'
                {$desc += 'Cybersecurity'
                }
                '^l.*'
                {$desc += 'General User'
                }
                '^d.*'
                {$desc += 'Data Transfer'
                }
                '^p.*'
                {$desc += 'Privileged User'
                }
            }

            $uData = [PSCustomObject]@{
                Name     = $u.Username
                FullName = $fullName
                Password = (ConvertTo-SecureString -AsPlainText -Force $fallbackPass)
                LinuxPassword = [sha512Crypt]::Crypt($fallbackPass)
                Description = "$desc"
                MustChangePassword = $false
            }
            $uData.Name += ".$grp"


            $allUsers.Add($uData)
        }
    }
    $allUsers = $allUsers | Sort-Object Name -Unique

    $result.AllUsers = $allUsers

    [PSCustomObject]$result
}




function Get-TaskData
{
    param(
        [string]$tasksPath
    )

    $taskData = @()
    $disjoinData = Get-PostDeployScript -userRights -Sharing -acls
    $disjoinB64 = [Convert]::ToBase64String(($disJoinData))
    $domainDisjoinTask = New-TaskXML -Description 'Runs once after domain disjoin' `
        -Author '[Mobile Administration]' -Execute 'powershell.exe' `
        -Arguments "-NoProfile -ExecutionPolicyBypass -Encoded $disjoinB64" `
        -TriggerConfigs @(
        @{
            Type = [TaskTriggerType]::Boot
            Delay = 'PT1M'
        }


    )


    $logCollect = New-TaskXML -Description 'Mobile Auto Log Collecot' `
        -Author '[Mobile Administration]' -Execute 'C:\Supportbin\logcollect' `
        -TriggerConfigs @(
        @{
            Type = [TaskTriggerType]::Weekly
            DaysOfWeek = 1
            StartBoundary = (Get-Date "00:00:00").AddDays(1).ToString('s')                   
        }


    )

    $taskData += @([PsCustomObject]@{Taskname = "Mobile-LogCollect"; TaskXml = $logCollect})
    $taskData += @([PsCustomObject]@{Taskname = "Mobile-DisjoinTask"; TaskXml = $domainDisjoinTask})
    
    return $taskData
}




function Get-MobileOverview
{
    [CmdletBinding(DefaultParameterSetName = 'ExplicitPaths')]
    param(

        [Parameter(Mandatory = $true, Position = 0)]
        [string]$MobileName,

        [Parameter(ParameterSetName='Config')]
        [PSCustomObject]$Config,


        [Parameter(ParameterSetName='ExplicitPaths', Mandatory=$true)]
        [string]$defaultUsersPath,

        [Parameter(ParameterSetName='ExplicitPaths', Mandatory=$true)]
        [string]$mobileEntriesPath,

        [Parameter(ParameterSetName='ExplicitPaths', Mandatory=$true)]
        [string]$fallBackPass

    )

    if ($PSCmdlet.ParameterSetName -eq 'Config')
    {
        $defaultUsersPath = $config.MobileDefault
        $mobileEntriesPath = $config.MobileEntries
        $fallBackPass = $config.fallbackPass
    }



    $data = Get-MobileData -MobileName $MobileName -defaultUserpath $defaultUsersPath -mobileEntriesPath $mobileEntriesPath -fallbackPass $fallBackPass

    # Overall display width
    $width = 72

    function Write-CenteredHeader
    {
        param(
            [string]$Text,
            [ConsoleColor]$Color = 'Cyan'
        )

        $border = '=' * $width
        $padding = [Math]::Max(0, [Math]::Floor(($width - $Text.Length) / 2))

        Write-Host $border -ForegroundColor $Color
        Write-Host (' ' * $padding + $Text) -ForegroundColor $Color
        Write-Host $border -ForegroundColor $Color
    }

    function Write-Section
    {
        param(
            [string]$Text,
            [ConsoleColor]$Color = 'DarkYellow'
        )

        Write-Host ""
        Write-Host ("[{0}]" -f $Text) -ForegroundColor $Color
        Write-Host ('-' * $width) -ForegroundColor DarkGray
    }

    if ($data.AllMobiles.Count -eq 0)
    {
        Write-Host "No available mobiles found." -ForegroundColor Yellow
        return
    }

    Write-Host ""

    if ([string]::IsNullOrWhiteSpace($MobileName))
    {
        Write-CenteredHeader -Text 'AVAILABLE MOBILES'

        foreach ($name in $data.AllMobiles)
        {
            Write-Host ("  {0,-30}" -f $name) -ForegroundColor Green
        }

        Write-Host ""
        return
    }

    Write-CenteredHeader -Text "MOBILE: $MobileName"

    Write-Section -Text 'USERS' -Color DarkYellow
    Write-Host (
        "  {0,-20} {1,-20} {2}" -f
        'USERNAME',
        'GROUPS',
        'FULL NAME'
    ) -ForegroundColor DarkYellow

    foreach ($u in ($data.MobileUsers| Sort-Object Username))
    {
        $groups = $u.Groups -join ', '

        Write-Host (
            "  {0,-20} {1,-20} {2}" -f
            $u.Username,
            $groups,
            $u.Name
        ) -ForegroundColor Yellow
    }

    if ($data.Windows.Count -gt 0)
    {
        Write-Section -Text 'WINDOWS' -Color DarkBlue

        foreach ($c in ($data.Windows| Sort-Object))
        {
            Write-Host ("  {0}" -f $c) -ForegroundColor Blue
        }
    }

    if ($data.Linux.Count -gt 0)
    {
        Write-Section -Text 'LINUX' -Color DarkRed

        foreach ($c in ($data.Linux | Sort-Object))
        {
            Write-Host ("  {0}" -f $c) -ForegroundColor Red
        }
    }

    Write-Section -Text 'SIMULATED DEPLOY' -Color Gray

    Write-Host (
        "  {0,-22} {1,-25} {2}" -f
        'USERNAME',
        'FULL NAME',
        'DESCRIPTION'
    ) -ForegroundColor DarkGreen

    foreach ($u in $data.AllUsers)
    {
        Write-Host (
            "  {0,-22} {1,-25} {2}" -f
            $u.Name,
            $u.FullName,
            $u.Description
        ) -ForegroundColor Green
    }

    Write-Host ""
}


# function Set-MobileGpoPermission
# {
#     [CmdletBinding(DefaultParameterSetName = 'Add')]
#     param(
#         [Parameter(Mandatory = $true, Position = 0)]
#         [string]$MobileName,
#
#         [Parameter(Mandatory = $true)]
#         [string]$GpoID,
#
#         [Parameter(Mandatory = $true, ParameterSetName = 'Add')]
#         [switch]$Add,
#
#         [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
#         [switch]$Remove,
#
#         [Parameter(ParameterSetName = 'Remove')]
#         [switch]$Force,
#
#         [Parameter()]
#         [PSCustomObject]$Config
#
#     )
#
#     $cfg = Get-MobileConfig $Config
#
#
#     if ($Force -and $Remove)
#     {
#         Get-GPPermission -Guid $gpoId -All |
#             Where-Object { $_.Trustee.SidType -eq 'User' -and $_.Permission -eq 'GpoRead' } |
#             ForEach-Object {
#                 Set-GPPermission -Guid $gpoId -TargetName $_.Trustee.Name -TargetType User -PermissionLevel None -Confirm:$false
#             }
#         Write-Host "[+] Force removed all user permissions from GPO ($gpoId)" -ForegroundColor Yellow
#         return
#     }
#
#     $mobileData = Get-MobileData -MobileName $MobileName -Config $cfg
#     $targetUsers = if ($Add)
#     { 
#         $mobileData.AllUsers 
#     } else
#     { 
#         $mobileData.MobileUsers 
#     }
#
#     foreach ($u in $targetUsers)
#     {
#         $permLevel = if ($Add)
#         { 
#             'GpoRead' 
#         } else
#         { 
#             'None' 
#         }
#         Set-GPPermission -Guid $gpoId -TargetName $u.Name -TargetType User -PermissionLevel $permLevel -Confirm:$false -ErrorAction SilentlyContinue
#     }
#
#     $actionText = if ($Add)
#     { 
#         "Added" 
#     } else
#     {
#         "Removed" 
#     }
#     Write-Host "[+] $actionText users from '$MobileName' for GPO ($gpoId)" -ForegroundColor Green
# }

function Set-MobileGpoPermission
{
    [CmdletBinding(DefaultParameterSetName = 'Add')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$MobileName,

        [Parameter(Mandatory = $true)]
        [string]$GpoID,

        [Parameter(Mandatory = $true, ParameterSetName = 'Add')]
        [switch]$Add,

        [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
        [switch]$Remove,

        [Parameter(ParameterSetName = 'Remove')]
        [switch]$Force,

        [Parameter()]
        [PSCustomObject]$Config
    )

    $cfg = Get-MobileConfig $Config

    # Standardize GPO GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    $cleanGuid = if ($GpoID -match '^{[0-9a-fA-F-]+}$')
    { $GpoID 
    } else
    { "{$GpoID}" 
    }

    # Bind to GPO container in AD
    $rootDSE       = [ADSI]"LDAP://RootDSE"
    $namingContext = $rootDSE.defaultNamingContext
    $gpoPath       = "LDAP://CN=$cleanGuid,CN=Policies,CN=System,$namingContext"
    
    $gpoEntry = [System.DirectoryServices.DirectoryEntry]::new($gpoPath)
    if (-not $gpoEntry.Path)
    {
        Write-Error "Could not bind to GPO ($cleanGuid) in Active Directory."
        return
    }

    $secDesc      = $gpoEntry.ObjectSecurity
    $applyGpoGuid = [Guid]"edacfc86-b327-11d2-9701-00c04fd91ab0"

    if ($Force -and $Remove)
    {
        # Get only explicit Access Control Entries (exclude inherited container ACLs)
        $rules = $secDesc.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
        $removedCount = 0

        # Protected well-known administrative SIDs (Domain Admins, Enterprise Admins, SYSTEM, etc.)
        # Domain Admins ends in -512, Enterprise Admins in -519, Domain Controllers in -516
        $adminRids = @(512, 516, 519)

        foreach ($rule in $rules)
        {
            $sid = $rule.IdentityReference.Value
            
            # Skip well-known built-in/service identities (NT AUTHORITY, SYSTEM, etc.)
            if ($sid -match '^S-1-5-(18|19|20|32-544)')
            {
                continue
            }

            # Check if this rule is a domain administrative group by RID
            $isProtectedAdmin = $false
            foreach ($rid in $adminRids)
            {
                if ($sid -match "-$rid$")
                {
                    $isProtectedAdmin = $true
                    break
                }
            }

            if ($isProtectedAdmin)
            {
                continue
            }

            # Target only GpoRead (GenericRead) or ExtendedRight (Apply Group Policy)
            $isReadOrApply = ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericRead) -or
            ($rule.ObjectType -eq $applyGpoGuid)

            if ($isReadOrApply)
            {
                $secDesc.RemoveAccessRuleSpecific($rule) | Out-Null
                $removedCount++
            }
        }

        $gpoEntry.CommitChanges()
        Write-Host "[+] Force removed $removedCount GpoRead / Apply ACEs from GPO ($cleanGuid)" -ForegroundColor Yellow
        return
    }

    $mobileData  = Get-MobileData -MobileName $MobileName -Config $cfg
    $targetUsers = if ($Add)
    { $mobileData.AllUsers 
    } else
    { $mobileData.MobileUsers 
    }

    foreach ($u in $targetUsers)
    {
        try
        {
            $account = [System.Security.Principal.NTAccount]::new($u.Name)
            $sid     = $account.Translate([System.Security.Principal.SecurityIdentifier])
        } catch
        {
            Write-Warning "Could not resolve SID for user: $($u.Name)"
            continue
        }

        $ruleRead = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $sid,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $ruleApply = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $sid,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $applyGpoGuid
        )

        if ($Add)
        {
            $secDesc.AddAccessRule($ruleRead)
            $secDesc.AddAccessRule($ruleApply)
        } else
        {
            $secDesc.RemoveAccessRule($ruleRead)
            $secDesc.RemoveAccessRule($ruleApply)
        }
    }

    $gpoEntry.CommitChanges()

    $actionText = if ($Add)
    { "Added" 
    } else
    { "Removed" 
    }
    Write-Host "[+] $actionText users from '$MobileName' on GPO ($cleanGuid)" -ForegroundColor Green
}


function Start-MobileDeployment
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$MobileName,
        [Parameter()]
        [PSCustomObject]$Config
        # [Parameter()]
        # [string]$EncryptPass = 'defaultPin',
        # [Parameter()]
        # [string]$userFallBackPass    = 'defaultPassword',
    )

    $cfg = Get-MobileConfig $Config
    $mobileData = Get-MobileData -MobileName $MobileName -Config $cfg
    $sshKeyPath = Join-Path $cfg.nfsHome ".ssh\$($cfg.sshKeyName)"
    $mobileData.AllUsers  = Get-UserCreds -MobileName $MobileName -AllUsers $mobileData.AllUsers -mobileDumpPath $cfg.MobileDump 
    $taskData = Get-TaskData
    $groupDict = @{
        'Administrators' = @("isso","adm","priv")
        'ISSO' = @("isso")
        'DTRW' = @("dtrw")
        'DTRO' = @("dtro")
    }
    $disJoin = $true

    $scriptBlock = {
        param($allusers, $taskData, $groupDict,$mobileName, $disJoin)

        foreach ($u in $allUsers)
        {
            $uParams = @{Name = $u.Name; FullName =$u.FullName; Password = $u.Password; Description = $u.Description}
            New-LocalUser @uParams -ErrorAction SilentlyContinue

            if ($u.MustChangePassword)
            {
                $a = [ADSI]"WinNT://./$($u.Name),user"
                $a.PasswordExpired = 1
                $a.SetInfo()
            }

        }

        foreach ($grp in $groupDict.Keys)
        {
            Get-Localuser | Where-Object {$_.Name -match "($($groupDict[$grp] -join '|'))$"} | Add-LocalGroupMember -Group $grp
        }

        foreach ($t in $taskData)
        {
            Register-ScheduledTask -TaskName $t.TaskName -xml $t.TaskXML -User System -Force
        }

        if ($disJoin)
        {
            Remove-Computer -Force -Restart -WorkGroupName "$mobileName"
        }

    }
    Invoke-Command -ComputerName $mobileData.Windows -ScriptBlock $scriptBlock -ArgumentList $mobileData.AllUsers,$taskData,$groupDict,$mobileName,$disJoin

    # Need the linux computers and the linux computers there for easy processing
    # $mobileData.AllUsers | Out-File -Encoding UTF8 (Join-Path $cfg['netAppHome'] "${env:Username}/")
    
    if ($mobileData.Linux.Count -gt 0)
    {
        $linuxDeploy = Get-LinuxDeployScript -oldEncryption $cfg.curLuks -encryptionPin $cfg.encryptionPin -nfsHome $cfg.nfsHome -allUsers $mobileData.AllUsers
        $jobs = foreach ($h in $mobileData.Linux)
        {
            Start-Job -ScriptBlock {
                param($target, $payload, $key)
                $payload | ssh -i $key -o BatchMode=yes -o StrictHostKeyChecking=no $target "bash -s --"

            } -ArgumentList $h,$linuxDeploy,$sshKeyPath
        }
        $linRes = $jobs | Receive-Job -Wait -AutoRemoveJob

    }


}


function Invoke-InformationCollector 
{
    [CmdletBinding()]
    param([Parameter()][array]$winComputers, [array]$linComputers, [string]$nfsHome, [string]$sshKeyName)
    $sshKey = Join-Path $nfsHome ".ssh\$sshKeyName"

    $bashScript = @'
#!/usr/bin/env bash
collect_hostname()   { printf "hostname\t%s\n" "$(hostname)"; }
collect_cores()      { printf "cores\t%s\n"    "$(nproc)"; }
collect_kernel()     { printf "kernel\t%s\n"   "$(uname -r)"; }
collect_clamAVDefs() { printf "ClamAV\t%s\n" "$(clamscan --version | awk -F'/' '{print $NF}')"}
collect_lastUpdate() { printf "UpdateHistory\t%s\n" "$( (yum history list 2>/dev/null || dnf history list 2>/dev/null) | awk -F'|' 'tolower($0) ~ /(update|upgrade)/ {gsub(/^[ \t]+|[ \t]+$/, "", $0); print; exit}')"; }
collect_hasRotate()  { printf "HasAdminRotate\t%s\n" "$(find /etc/systemd -iname '*laps*' 2>/dev/null | head -n 1)"; }
{
  collect_hostname
  collect_cores
  collect_kernel
  collect_clamAVDefs
  collect_lastUpdate
  collect_hasRotate
} | jq -Rs '
  reduce (split("\n")[] | select(length > 0) | split("\t")) as $item
    ({}; . + { ($item[0]): ($item[1] | tonumber? // .) })
'

'@

    $windowsInformationBlock = {
        $ivantiVersion = (Get-ItemProperty -Path @(
                'HKLM:\SOFTWARE\LANDesk\ManagementSuite\WinClient'
                'HKLM:\SOFTWARE\WOW6432Node\LANDesk\ManagementSuite\WinClient'
                'HKLM:\SOFTWARE\Wow6432Node\LANDesk\Inventory'
                'HKLM:\SOFTWARE\Ivanti\Endpoint Manager'
            ) -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Version -ErrorAction SilentlyContinue)


        $SymantecAvDefs = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Storages\Definitions\VirusDefs' -ErrorAction SilentlyContinue).DefSetVersion

        $symantecBackupPath = Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Storages\Definitions' -Recurse -ErrorAction SilentlyContinue |
            Get-ItemProperty | Select-Object PSPath, DefSetVersion, DefSetId, LatestVirusDefsDate

        $Packages = Get-ItemProperty @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        ) -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and -not $_.SystemComponent -and $_.WindowsInstaller -ne 1 -or $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Sort-Object DisplayName -Unique
        $adminRotateScriptVersion = ((schtasks /query /tn admin-task /xml) | Select-String -Pattern '<Version>(.*?)</Version>').Matches.Groups[1].Value

        $activation = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" |    Where-Object { $_.PartialProductKey } | Select-Object -First 1 -ExpandProperty LicenseStatus

        $licenseStatusMap = @{
            0 = 'Unlicensed'
            1 = 'Licensed'
            2 = 'OOB Grace'
            3 = 'OOT Grace'
            4 = 'Non-Genuine Grace'
            5 = 'Notification'
            6 = 'Extended Grace'
        }

        $activationStatus = $licenseStatusMap[[int]$activation]

        $Session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $Session.CreateUpdateSearcher()

        $latestUpdates = $searcher.QueryHistory(0,10) | Select-Object Title, Date, @{Name="Status"; Expression= {
                switch ($_.ResultCode)
                {
                    2
                    {"Succeeded"
                    }
                    3
                    {"Succeeded With Errors"
                    }
                    4
                    {"Failed"
                    }
                    5
                    {"Aborted"
                    }
                    default
                    { "Other: ($($_.ResultCode))"
                    }
                }
            }
        }

        return [PSCustomObject]@{
            WindowsLicense = $activationStatus
            WinUpdates = $latestUpdates
            IvantiVersion = $ivantiVersion
            AVDefs = $SymantecAvDefs
            Packages = $Packages
            AdminRotateVersion = $adminRotateScriptVersion
        }

        
    }
    $winResult = @()
    $linResult = @()
    if ($winComputers -gt 0)
    {
        $winResult = Invoke-Command -ComputerName $winComputers -ScriptBlock $windowsInformationBlock
    }
    if ($linComputers -gt 0)
    {
        $jobs = foreach ($linHost in $linComputers)
        {
            Start-Job -ScriptBlock {
                param($hostName, $script, $key)
                $o = $script | ssh -o BatchMode=yes -o StrictHostKeyChecking=no -qi $key $hostName "bash -s --" 
                $p = if ($LASTEXITCODE -eq 0 -and $o)
                {
                    $o | ConvertFrom-Json
                } else
                { $null 
                }
                [PSCustomObject]@{
                    HostName = $hostName
                    Cores = $p.Cores
                    Kernel = $p.Kernel
                    ClamAvDefs = $p.ClamAv
                    LastUpdate = $p.LastUpdate
                    HasLas = [bool]$p.HasLaps
                    Success = ($LASTEXITCODE -eq 0)
                }

            } -ArgumentList $linHost,$bashScript,$sshKey
        }
        $linResult = $jobs | Receive-Job -Wait -AutoRemoveJob
    }
    return [PSCustomObject]@{ 
        Windows = $winResult
        Linux = $linResult
    }

}






# function Unregister-Deployment
# {
#     [CmdletBinding()]
#     param(
#         [Parameter(Mandatory = $true)]
#         [string]$MobileName,
#
#         [Parameter(Mandatory = $true)]
#         [hashtable]$Config,
#
#         [Parameter()]
#         [string]$archiveDir = "C:\Mobiles\"
#
#     )
#
#     $cfg = Get-MobileConfig $config
#     $mobileData = Get-MobileData  -MobileName $MobileName -defaultUserpath $cfg.DefaultUsers -mobileEntriesPath $cfg.MobileEntries -fallbackPass $cfg.DefaultPass
#     $taskData = Get-TaskData
#
#     $scriptBlock = {
#         param([array]$AllUsers, [hashtable]$Tasks, [string]$archiveDir)
#
#         $curDate = Get-Date
#         $archivePath = Join-Path $archiveDir "$($curDate.Year)"
#         if (-not (Test-Path $archivePath))
#         {
#             New-Item -ItemType Directory -Force $archivePath
#         }
#
#
#
#         foreach ($u in $AllUsers)
#         {
#             $name = $u.Name
#             $sid = (Get-LocalUser -Name $name -ErrorAction SilentlyContinue).Sid.Value
#
#             $profilePath = "C:\Users\$name"
#             if (Test-Path $profilePath)
#             {
#                 $ts = (Get-Date).ToString('yyyyMMdd')
#                 $archiveFile = Join-Path $archivePath "$($name)_${ts}.zip"
#                 Compress-Archive -Path $profilePath -DestinationPath $archiveFile -CompressionLevel Optimal
#
#             }
#             $profileObject = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $sid -or $_.LocalPath -ieq $profilePath }
#
#             if ($profileObject)
#             {$profileObject | Remove-CimInstance
#             } elseif (Test-Path $profilePath)
#             { Remove-Item -Force -Recurse -Path $profilePath -ErrorAction SilentlyContinue
#             }
#             Remove-LocalUser $name -ErrorAction SilentlyContinue
#         }
#
#     }
#
#
#     Invoke-Command -ComputerName $mobileData.Windows -ScriptBlock $scriptBlock -ArgumentList $mobileData.AllUsers,$taskData,$archiveDir
#     $linuxDeploy = Get-LinuxDeployScript -oldEncryption $config.curLuks -encryptionPin $Config.encryptionPin  
#     $jobs = foreach ($h in $mobileData.Linux)
#     {
#         Start-Job -ScriptBlock {
#             param($target, $payload, $key)
#             $payload | ssh -i $key -o BatchMode=yes -o StrictHostKeyChecking=no $target "bash -s --"
#
#         } -ArgumentList $h,$bashScript,$sshKey
#     }
#     $linRes = $jobs | Receive-Job -Wait -AutoRemoveJob
#
# }
#
#
#
