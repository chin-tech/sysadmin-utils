# --- Configuration Loader ---
$module = $MyInvocation.MyCommand.ScriptBlock.Module
if (-not $module) { $module = $MyInvocation.MyCommand.Module 
}

# Support both PrivateData.PSData.DefaultConfig and direct PrivateData.DefaultConfig
$rawCfg = $module.PrivateData
if ($rawCfg.PSData.DefaultConfig) {
    $manifestCfg = $rawCfg.PSData.DefaultConfig
} elseif ($rawCfg.DefaultConfig) {
    $manifestCfg = $rawCfg.DefaultConfig
} else {
    $manifestCfg = @{}
}

$Script:DefaultConfig = $manifestCfg

$adminRoot = $PSScriptRoot
$nfsRoot   = if ($manifestCfg.nfsHomeRoot) { 
    $manifestCfg.nfsHomeRoot 
} else { 
    "C:\Temp\Mobiles" 
} # Or appropriate fallback path
$mobileRoot = Join-Path $nfsRoot ".mobiles"
$script:Config = [PSCustomObject]@{
    nfsHomeRoot        = $nfsRoot
    AdminRoot          = $adminRoot
    MobileRoot         = $mobileRoot
    GpoID              = $manifestCfg.GpoID
    SshKeyName         = $manifestCfg.sshKey
    CertName           = $manifestCfg.CertName
    fallbackPass       = $manifestCfg.fallbackPass
    curLuks            = $manifestCfg.curLuks
    encryptionPin      = $manifestCfg.encryptionPin
    NfsHome            = (Join-Path $nfsRoot $env:USERNAME)
    MobileEntries      = (Join-Path $mobileRoot 'entries')
    mobileDefaultUsers = (Join-Path $mobileRoot '.default')
    MobileDump         = (Join-Path $mobileRoot '.dump')
    MobileDeployments  = (Join-Path $mobileRoot '.deployments')
    SSHKeyPath         = Join-Path (Join-Path $nfsRoot $env:USERNAME) ".ssh\Deployer"
}


enum GroupType {
    Local
    ISSO
    Admin
    Priv
    DTRW
    DTRO
}

enum LinuxAccountType {
    Wheel
    General
}

$script:GroupMetadata = @{
    [GroupType]::ISSO = @{
        Patterns         = @('i*', 'isso')
        Description      = 'Mobile - ISSO'
        Suffix           = 'isso'
        LinuxAccountType = [LinuxAccountType]::Wheel
        Exclusive        = $true
        Selectable       = $false
        Priority         = 100
        WindowsGroups    = @("Administrators", "ISSO")
        
    }

    [GroupType]::Admin = @{
        Patterns         = @('t*', 'adm*', 'admin')
        Description      = 'Mobile - System Admin'
        Suffix           = [GroupType]::Admin.ToString().ToLower()
        LinuxAccountType = [LinuxAccountType]::Wheel
        Exclusive        = $true
        Selectable       = $false
        Priority         = 90
        WindowsGroups    = @("Administrators")
    }

    [GroupType]::Priv = @{
        Patterns         = @('p*', 'priv')
        Description      = 'Mobile - Privileged User'
        Suffix           = [GroupType]::Priv.ToString().ToLower()
        LinuxAccountType = [LinuxAccountType]::Wheel
        Exclusive        = $false
        Selectable       = $true
        Priority         = 50
        WindowsGroups    = @("Administrators")
    }

    [GroupType]::DTRW = @{
        Patterns         = @('d*rw', 'dtrw')
        Description      = 'Mobile - Data Transfer Read Write'
        Suffix           = [GroupType]::DTRW.ToString().ToLower()
        LinuxAccountType = $null
        Exclusive        = $false
        Selectable       = $true
        Priority         = 40
        WindowsGroups    = @("DTRW")
    }

    [GroupType]::DTRO = @{
        Patterns         = @('d*ro', 'dtro')
        Description      = 'Mobile - Data Transfer Read Only'
        Suffix           = [GroupType]::DTRO.ToString().ToLower()
        LinuxAccountType = $null
        Exclusive        = $false
        Selectable       = $true
        Priority         = 40
        WindowsGroups    = @("DTRO")
    }

    [GroupType]::Local = @{
        Patterns         = @()
        Description      = 'Mobile - General User'
        Suffix           = [GroupType]::Local.ToString().ToLower()
        LinuxAccountType = [LinuxAccountType]::General
        Exclusive        = $false
        Selectable       = $false
        Priority         = 0
    }
}


class WindowsPayload {
    [string] $MobileName
    [bool]   $Archive
    [PSObject[]] $AllUsers
    [PSObject[]] $TaskData
    [string] $Bitlocker


    # WindowsPayload([string]mobileName, [PSObject[]]$users, [PsObject[]]$tasks) {
    #     $this.MobileName = $mobileName
    #     $this.allUsers = $users
    #     $this.TaskData = $tasks
    # }
}



$script:WindowsDeployBlock = {
    param([PsCustomObject]$payload)

    $actions  = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()

    function Add-Action {
        param(
            [string]$Category,
            [string]$Name,
            [string]$Status,
            [object]$Details = $null
        )

        $actions.Add([PSCustomObject]@{
                Category = $Category
                Name     = $Name
                Status   = $Status
                Details  = $Details
            })
    }

    function Invoke-Step {
        param(
            [Parameter(Mandatory)]
            [string]$Context,

            [Parameter(Mandatory)]
            [scriptblock]$Action,

            [type[]]$IgnoreExceptions = @()
        )

        try {
            & $Action | Out-Null
            return $true
        } catch {
            foreach ($ignored in $IgnoreExceptions) {
                if ($_.Exception -is $ignored) {
                    return $true
                }
            }

            $failures.Add("${Context}: $($_.Exception.Message)")
            return $false
        }
    }

    if (-not $payload.AllUsers -or $payload.AllUsers.Count -eq 0) {
        $failures.Add('No users provided in payload')
    }

    #
    # Users
    #
    foreach ($u in $payload.AllUsers) {

        $existing = Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue

        if ($existing) { 
            Add-Action  -Category 'User'  -Name $u.Name  -Status 'Existed' 
        } else {
            $uParams = @{
                Name        = $u.Name
                FullName    = $u.FullName
                Password    = $u.Password
                Description = $u.Description
                ErrorAction = 'Stop'
            }

            if ( Invoke-Step  -Context "User '$($u.Name)'"  -Action { New-LocalUser @uParams }) {
                Add-Action  -Category 'User'  -Name $u.Name  -Status 'Created' 
            } else {
                Add-Action  -Category 'User'  -Name $u.Name  -Status 'Failed'
            }
        }

        #
        # Password expiration
        #
        if ($u.MustChangePassword) {

            $success = Invoke-Step  -Context "Password expiry '$($u.Name)'"  -Action { $adsiUser = [ADSI]"WinNT://./$($u.Name),user"; $adsiUser.PasswordExpired = 1; $adsiUser.SetInfo() }

            Add-Action  -Category 'PasswordExpiry'  -Name $u.Name  -Status $(if ($success) { 'Changed' 
                } else { 'Failed' 
                })
        }

        #
        # Groups
        #
        foreach ($g in $u.WindowsGroups) {

            if (-not (Get-LocalGroup $g -ErrorAction SilentlyContinue)) {
                New-LocalGroup $g
            }

            $alreadyMember = $false

            try {
                $alreadyMember = [bool]( Get-LocalGroupMember  -Group $g  -Member $u.Name  -ErrorAction Stop)
            } catch {
                # Absence is expected here.
            }

            if ($alreadyMember) {
                Add-Action  -Category 'Privilege'  -Name "$($u.Name):$g"  -Status 'Existed'
                continue
            }

            $success = Invoke-Step  -Context "Group '$g' for '$($u.Name)'"  -Action { Add-LocalGroupMember  -Group $g  -Member $u.Name  -ErrorAction Stop }

            Add-Action  -Category 'Privilege'  -Name "$($u.Name):$g"  -Status $(if ($success) { 'Changed' 
                } else { 'Failed' 
                })
        }
    }

    #
    # Scheduled tasks
    #
    foreach ($t in $payload.TaskData) {

        $success = Invoke-Step  -Context "Scheduled task '$($t.TaskName)'"  -Action { Register-ScheduledTask  -TaskName $t.TaskName  -Xml $t.TaskXML  -User System  -Force  -ErrorAction Stop }

        Add-Action  -Category 'ScheduledTask'  -Name $t.TaskName  -Status $(if ($success) { 'Changed' 
            } else { 'Failed' 
            })
    }

    #
    # BitLocker
    #
    $drives = @( Get-BitLockerVolume | Where-Object VolumeType -eq 'OperatingSystem')

    $tpm = Get-Tpm

    foreach ($drive in $drives) {

        $bitLockerParams = @{
            MountPoint  = $drive.MountPoint
            ErrorAction = 'Stop'
        }

        if ($tpm.IsPresent -and $tpm.IsEnabled) {
            $bitLockerParams.TpmAndPinProtector = $true
            $bitLockerParams.Pin = ConvertTo-SecureString  -String $payload.Bitlocker  -AsPlainText  -Force
        } else {
            $bitLockerParams.PasswordProtector = $true
            $bitLockerParams.Password = ConvertTo-SecureString  -String $payload.Bitlocker  -AsPlainText  -Force
        }

        $success = Invoke-Step  -Context "BitLocker '$($drive.MountPoint)'"  -Action { Enable-BitLocker @bitLockerParams
        }

        Add-Action  -Category 'DiskEncryption'  -Name $drive.MountPoint  -Status $(if ($success) { 'Changed' 
            } else { 'Failed' 
            })
    }

    #
    # Domain
    #
    if ($payload.DisJoin) {

        $success = Invoke-Step  -Context 'Domain Disjoin'  -Action { Remove-Computer  -WorkGroupName $payload.MobileName  -Force  -Restart:$false  -ErrorAction Stop }

        Add-Action  -Category 'Domain'  -Name 'Disjoin'  -Status $(if ($success) { 'Changed' 
            } else { 'Failed' 
            })
    }

    [PSCustomObject]@{
        Platform = 'Windows'
        Success  = ($failures.Count -eq 0)
        Actions  = $actions.ToArray()
        Failures = $failures.ToArray()
    }
}


$script:WindowsUnregisterBlock = {
    param([PSCustomObject]$payload)

    $archive  = [bool]$payload.Archive
    $allUsers = @($payload.AllUsers)
    $taskData = @($payload.TaskData)

    $timeStamp   = (Get-Date).ToString('yyyyMMdd')
    $monthYear   = (Get-Date).ToString('MM-yyyy')
    $archivePath = "C:\Mobiles\Archive\$monthYear"

    $actions  = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()

    function Invoke-Step {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Category,
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][scriptblock]$ScriptBlock
        )

        try {
            $details = & $ScriptBlock

            $actions.Add([PSCustomObject]@{
                    Category = $Category
                    Name     = $Name
                    Status   = 'Success'
                    Details  = $details
                })

            return $true
        } catch {
            $actions.Add([PSCustomObject]@{
                    Category = $Category
                    Name     = $Name
                    Status   = 'Failed'
                    Details  = $null
                })

            $failures.Add("${Category} '$Name': $($_.Exception.Message)")
            return $false
        }
    }

    $archiveReady = $true

    if ($archive) {
        $archiveReady = Invoke-Step -Category 'ArchiveDirectory' -Name $archivePath -ScriptBlock {
            if (-not (Test-Path $archivePath)) {
                New-Item -ItemType Directory -Force -Path $archivePath -ErrorAction Stop | Out-Null
            }
        }
    }

    foreach ($u in $allUsers) {
        $name = $u.Name
        $profilePath = "C:\Users\$name"
        $localUser = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        $sid = if ($localUser) { $localUser.SID.Value } else { $null }

        if ($archive -and -not $archiveReady) {
            continue
        }

        if ($archive -and (Test-Path $profilePath)) {
            $archiveFile = Join-Path $archivePath "$name-$timeStamp.zip"

            $archiveOk = Invoke-Step -Category 'ProfileArchive' -Name $name -ScriptBlock {
                Compress-Archive -Path $profilePath -DestinationPath $archiveFile -CompressionLevel Optimal -Force -ErrorAction Stop
                $archiveFile
            }

            if (-not $archiveOk) { continue }
        }

        if (Test-Path $profilePath) {
            $profileOk = Invoke-Step -Category 'ProfileRemoval' -Name $name -ScriptBlock {
                $profileObject = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { ($sid -and $_.SID -eq $sid) -or $_.LocalPath -ieq $profilePath }

                if ($profileObject) { $profileObject | Remove-CimInstance -ErrorAction Stop }
                if (Test-Path $profilePath) { Remove-Item -Path $profilePath -Recurse -Force -ErrorAction Stop }
            }

            if (-not $profileOk) { continue }
        }

        if ($localUser) {
            Invoke-Step -Category 'UserRemoval' -Name $name -ScriptBlock {
                Remove-LocalUser -Name $name -ErrorAction Stop
            } | Out-Null
        } else {
            $actions.Add([PSCustomObject]@{
                    Category = 'UserRemoval'
                    Name     = $name
                    Status   = 'Success'
                    Details  = 'Already absent'
                })
        }
    }

    foreach ($t in $taskData) {
        $existingTask = Get-ScheduledTask -TaskName $t.TaskName -ErrorAction SilentlyContinue

        if ($existingTask) {
            Invoke-Step -Category 'ScheduledTask' -Name $t.TaskName -ScriptBlock {
                Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false -ErrorAction Stop
            } | Out-Null
        } else {
            $actions.Add([PSCustomObject]@{
                    Category = 'ScheduledTask'
                    Name     = $t.TaskName
                    Status   = 'Success'
                    Details  = 'Already absent'
                })
        }
    }

    Invoke-Step -Category 'DiskEncryption' -Name 'C:' -ScriptBlock {
        $tpm = Get-Tpm -ErrorAction Stop

        if (-not ($tpm.TpmPresent -and $tpm.TpmEnabled)) {
            throw 'TPM is unavailable or disabled'
        }

        $volume = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
        $hasTpm = @($volume.KeyProtector | Where-Object KeyProtectorType -eq 'Tpm').Count -gt 0

        if (-not $hasTpm) {
            Add-BitLockerKeyProtector -MountPoint 'C:' -TpmProtector -ErrorAction Stop | Out-Null
        }
    } | Out-Null

    [PSCustomObject]@{
        Platform = 'Windows'
        Success  = ($failures.Count -eq 0)
        Actions  = $actions.ToArray()
        Failures = $failures.ToArray()
    }
}


function ConvertFrom-Base64 {
    param ([string]$text)
    return [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($text))
}

function ConvertTo-Base64 {
    param (
        [string]$text
    )

    return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($text))
}



function Get-MobileConfig {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$CustomConfig
    )

    $merged = @{}

    # Copy defaults from the base script Config
    if ($script:Config) {
        foreach ($prop in $script:Config.PSObject.Properties) {
            $merged[$prop.Name] = $prop.Value
        }
    }

    # Overlay user-provided configs (supports Hashtable, PSCustomObject, or IDictionary)
    if ($CustomConfig) {
        if ($CustomConfig -is [System.Collections.IDictionary]) {
            foreach ($k in $CustomConfig.Keys) {
                $merged[$k] = $CustomConfig[$k]
            }
        } else {
            foreach ($prop in $CustomConfig.PSObject.Properties) {
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
if (-not ([System.Management.Automation.PSTypeName]'Sha512Crypt').Type) {
    Add-Type -TypeDefinition $Sha512CryptSource
}



function Invoke-Linux {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Computers,

        [Parameter(Mandatory=$true)]
        [string]$Script,

        [Parameter(Mandatory=$true)]
        [string]$KeyPath
    )

    # Clean the script once, up front — no point repeating this per-job
    $cleanScript = ($Script -replace "`r","").TrimEnd() + "`n"

    $jobs = foreach ($target in $Computers) {
        Start-Job -ScriptBlock {
            param($target, $payload, $key)

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "ssh"
            $psi.Arguments = "-i `"$key`" -o UpdateHostKeys=no -o BatchMode=yes -o StrictHostKeyChecking=no $target `"bash -s --`""
            $psi.RedirectStandardInput = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false

            $proc = [System.Diagnostics.Process]::Start($psi)
            $proc.StandardInput.Write($payload)
            $proc.StandardInput.Close()

            $stdout = $proc.StandardOutput.ReadToEnd()
            $stderr = $proc.StandardError.ReadToEnd()
            $proc.WaitForExit()

            return [PSCustomObject]@{
                Target   = $target
                ExitCode = $proc.ExitCode
                StdOut   = $stdout
                StdErr   = $stderr
            }
        } -ArgumentList $target, $cleanScript, $KeyPath
    }

    $res = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
    return $res
}




function Resolve-GroupType {
    param(
        [Parameter(Mandatory)]
        [string]$Group
    )

    foreach ($groupType in $script:GroupMetadata.Keys) {
        foreach ($pattern in $script:GroupMetadata[$groupType].Patterns) {
            if ($Group -like $pattern) {
                return $groupType
            }
        }
    }

    return $null
}


function Set-Groups {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [array]$Groups
    )

    if (-not $groups) { return @([GroupType]::Local)
    }

    $resolved = foreach ($g in $groups) {
        $type = Resolve-GroupType $g
        if ($null -ne $type) {
            $type
        }
    } 
    $resolved = ($resolved | Sort-Object -Unique)

    $exclusive = $resolved |
        Where-Object {
            $script:GroupMetadata[$_].Exclusive
        } |
        Sort-Object {
            $script:GroupMetadata[$_].Priority
        } -Descending |
        Select-Object -First 1

    if ($null -ne $exclusive) {
        return @($exclusive)
    }
    return @(
        [GroupType]::Local
        $resolved
    ) | Select-Object -unique
}


enum TaskTriggerType {
    Time         = 1
    Daily        = 2
    Weekly       = 3
    Registration = 7
    Boot         = 8
    Logon        = 9
}

function New-TaskXML {
    [CmdletBinding()]
    param(
        [Parameter()][string]$Description = "Automated Task",
        [Parameter()][string]$Author = "SYSTEM",
        [Parameter()][string]$Version = "1.0",
        
        [Parameter()]
        [string]$Execute,
        [string]$ToEncode,
        
        [Parameter()]
        [string]$Arguments = "",
        
        # Pass a hashtable or array of hashtables describing triggers
        [Parameter()]
        [hashtable[]]$TriggerConfigs = @(@{ Type = [TaskTriggerType]::Registration }),
        
        [Parameter()][string]$UserId = "NT AUTHORITY\SYSTEM",
        [Parameter()][int]$LogonType = 5, # 5 = TASK_LOGON_SERVICE / SYSTEM
        [Parameter()][int]$RunLevel = 1,  # 1 = TASK_RUNLEVEL_HIGHEST
        
        [Parameter()][bool]$Hidden = $true,
        [Parameter()][string]$ExecutionTimeLimit = "PT72H"
    )

    $defaultPSArgs = if ($Execute.ToLower().Contains('powershell')) { "-ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive "
    }
    $encoded = if (-not ([string]::IsNullOrWhiteSpace($toEncode))) { "-Encoded $(ConvertTo-Base64 $ToEncode)"
    }
    $arguments += ($defaultPSArgs + $encoded + $arguments)

    $ts = New-Object -ComObject "Schedule.Service"
    $ts.Connect()

    # 0 = TASK_CREATE (Task Definition)
    $taskDef = $ts.NewTask(0)
    
    # 1. Registration Info
    $taskDef.RegistrationInfo.Description = $Description
    $taskDef.RegistrationInfo.Author = $Author
    $taskDef.RegistrationInfo.Version = $Version

    # 2. Task Settings
    $taskDef.Settings.Enabled = $true
    $taskDef.Settings.Hidden = $Hidden
    $taskDef.Settings.StartWhenAvailable = $true
    $taskDef.Settings.AllowDemandStart = $true
    $taskDef.Settings.WakeToRun = $true
    $taskDef.Settings.DisallowStartIfOnBatteries = $false
    $taskDef.Settings.StopIfGoingOnBatteries = $false
    $taskDef.Settings.ExecutionTimeLimit = $ExecutionTimeLimit
    $hasEndBoundary = $TriggerConfigs | Where-Object { $_.ContainsKey("EndBoundary") }
    if ($hasEndBoundary) {
        $taskDef.Settings.DeleteExpiredTaskAfter = 'PT0S'
    }

    # 3. Principal Configuration
    $taskDef.Principal.UserId = $UserId
    $taskDef.Principal.LogonType = $LogonType
    $taskDef.Principal.RunLevel = $RunLevel
    function Get-ValOrFallBack {
        param($map, $key, $default)
        if ($map.ContainsKey($key)) { 
            $map[$key]

        } else { 
            $default 
        }
    }

    # 4. Triggers Configuration
    foreach ($cfg in $TriggerConfigs) {
        $tType = [TaskTriggerType]$cfg.Type
        $trigger = $taskDef.Triggers.Create([int]$tType)
        $trigger.Enabled = Get-ValOrFallBack $cfg "Enabled" $true        

        switch ($tType) {
            ([TaskTriggerType]::Logon) {
                # Specific user or $null / empty string for all users
                $trigger.UserID  = Get-ValOrFallBack $cfg "UserId" $null
                $trigger.Delay = Get-ValOrFallBack $cfg "Delay" "PT30S"
            }
            ([TaskTriggerType]::Boot) {
                $trigger.Delay = Get-ValOrFallBack $cfg "Delay" "PT30S"
                $trigger.EndBoundary = Get-ValOrFallBack $cfg 'EndBoundary' (Get-Date).AddMinutes(30).ToString('s')
                $taskDef.Settings.DeleteExpiredTaskAfter = 'PT0S'
            }
            ([TaskTriggerType]::Daily) {

                $trigger.StartBoundary = Get-ValOrFallBack $cfg 'StartBoundary' (Get-Date).AddMinutes(1).ToString('s')
                $trigger.DaysInterval = Get-ValOrFallBack $cfg "DaysInterval" 1 
            }
            ([TaskTriggerType]::Weekly) {
                $trigger.StartBoundary = Get-ValOrFallBack $cfg 'StartBoundary' (Get-Date).AddMinutes(1).ToString('s')
                $trigger.WeeksInterval = Get-ValOrFallBack $cfg 'WeeksInterval' 1
                # DaysOfWeek bitmask: 1=Sun, 2=Mon, 4=Tue, 8=Wed, 16=Thu, 32=Fri, 64=Sat
                $trigger.DaysOfWeek = Get-ValOrFallBack $cfg 'DaysOfWeek' 1
            }
            ([TaskTriggerType]::Time) {
                ## StartBoundary set earlier
                $trigger.StartBoundary = Get-ValOrFallBack $cfg 'StartBoundary' (Get-Date).AddMinutes(1).ToString('s')
            }
            ([TaskTriggerType]::Registration) {
                $trigger.Delay = Get-ValOrFallBack $cfg 'Delay' 'PT0S'
                $trigger.EndBoundary = Get-ValOrFallBack $cfg 'EndBoundary' (Get-Date).AddSeconds(15).ToString('s')
                $taskDef.Settings.DeleteExpiredTaskAfter = 'PT0S'
            }
        }
    }
    

    # 5. Action Configuration (0 = ExecAction)
    $action = $taskDef.Actions.Create(0)
    $action.Path = $Execute
    $action.Arguments = $Arguments

    return $taskDef.XmlText
}

function ConvertTo-BashArgument {
    param([string]$v)
    "'" + $v.Replace("'","'\''") + "'"
}
function Repair-GpoPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoID
    )

    $cleanGuid = if ($GpoID -match '^\{[0-9a-fA-F-]+\}$') { $GpoID.ToUpper() } else { "{$($GpoID.ToUpper())}" }

    $rootDSE = [ADSI]"LDAP://RootDSE"
    $namingContext = $rootDSE.defaultNamingContext
    $policyContainer = "CN=Policies,CN=System,$namingContext"
    $gpoLdapUri = "LDAP://CN=$cleanGuid,$policyContainer"

    if (-not [System.DirectoryServices.DirectoryEntry]::Exists($gpoLdapUri)) {
        throw "GPO $cleanGuid not found in AD."
    }

    $gpoEntry = [System.DirectoryServices.DirectoryEntry]::new($gpoLdapUri)
    $sec = $gpoEntry.ObjectSecurity

    # Convert common identities to SIDs
    $sidAuthUsers    = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")      # Authenticated Users
    $sidDomainAdmins = [System.Security.Principal.NTAccount]::new("Domain Admins").Translate([System.Security.Principal.SecurityIdentifier])
    $sidSystem       = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")      # NT AUTHORITY\SYSTEM
    $sidEnterprise   = [System.Security.Principal.NTAccount]::new("Enterprise Admins").Translate([System.Security.Principal.SecurityIdentifier])

    $applyGpoGuid = [Guid]"edacfc86-b327-11d2-9701-00c04fd91ab0"

    # 1. Grant Domain Admins & SYSTEM Full Control on AD Container
    $ruleDomainAdmin = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $sidDomainAdmins,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $ruleSystem = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $sidSystem,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $ruleEnterprise = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $sidEnterprise,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    # 2. Grant Authenticated Users: Read + Apply Group Policy
    $ruleAuthRead = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $sidAuthUsers,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $ruleAuthApply = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $sidAuthUsers,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $applyGpoGuid
    )

    $sec.AddAccessRule($ruleDomainAdmin)
    $sec.AddAccessRule($ruleSystem)
    $sec.AddAccessRule($ruleEnterprise)
    $sec.AddAccessRule($ruleAuthRead)
    $sec.AddAccessRule($ruleAuthApply)

    $gpoEntry.CommitChanges()

    # 3. Match SYSVOL ACLs
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $gpoSysvolPath = "\\$domain\sysvol\$domain\policies\$cleanGuid"

    if (Test-Path $gpoSysvolPath) {
        icacls.exe $gpoSysvolPath /inheritance:e /T /C /Q 2>$null | Out-Null
        icacls.exe $gpoSysvolPath /grant "Domain Admins:(OI)(CI)(F)" "SYSTEM:(OI)(CI)(F)" /T /C /Q 2>$null | Out-Null
        icacls.exe $gpoSysvolPath /grant "Authenticated Users:(OI)(CI)(RX)" /T /C /Q 2>$null | Out-Null
    }

    Write-Host "[+] Fixed AD Container and SYSVOL ACLs for $cleanGuid" -ForegroundColor Green
}

function New-ShortcutGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetOUFriendlyName,

        [Parameter()]
        [string]$GpoID = "{00000000-7E5A-C0DE-7E5A-000000000000}",

        [Parameter()]
        [string]$ShortcutName = "LocalAccountCreator",

        [Parameter()]
        [string]$TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",

        [Parameter()]
        [string]$Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File ""C:\Supportbin\script.ps1""",

        [Parameter()]
        [string]$IconPath = "%SystemRoot%\System32\SHELL32.dll",

        [Parameter()]
        [int]$IconIndex = 301,

        [Parameter()]
        [string]$Comment = "LOCAL ACCOUNTS",
        [switch]$Quiet
    )

    $cleanGpoID = if ($GpoID -match '^\{[0-9a-fA-F-]+\}$') { $GpoID.ToUpper() } else { "{$($GpoID.ToUpper())}" }
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $gpoName = "Mobile Logon"

    $rootDSE = [ADSI]"LDAP://RootDSE"
    $ctx = $rootDSE.DefaultNamingContext
    $policyContainerPath = "CN=Policies,CN=System,$ctx"
    $targetOU_DN = "OU=$TargetOUFriendlyName,$ctx"
    $gpoLdapPath = "[LDAP://CN=$cleanGpoID,$policyContainerPath;0]"
    $gpoSysvolPath = "\\$domain\sysvol\$domain\policies\$cleanGpoID"

    #
    # 1. Active Directory GPC Object
    #
    $policiesContainer = [ADSI]"LDAP://$policyContainerPath"
    $gpoLdapUri = "LDAP://CN=$cleanGpoID,$policyContainerPath"

    $isNew = $false
    if ([System.DirectoryServices.DirectoryEntry]::Exists($gpoLdapUri)) {
        $gpoEntry = [ADSI]$gpoLdapUri
    } else {
        $gpoEntry = $policiesContainer.Create("groupPolicyContainer", "CN=$cleanGpoID")
        $isNew = $true
    }

    # Verified extension GUIDs from working GPO
    $exactExtensionWithLogon = "[{00000000-0000-0000-0000-000000000000}{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}][{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}][{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}]"
    $exactExtension = "[{00000000-0000-0000-0000-000000000000}{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}][{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}]"

    $versionNumber = (1 -shl 16) # User version = 1, Computer version = 0

    $gpoEntry.Put("displayName", $gpoName)
    $gpoEntry.Put("flags", 0)
    $gpoEntry.Put("gPCFunctionalityVersion", 2)
    $gpoEntry.Put("gPCFileSysPath", $gpoSysvolPath)
    $gpoEntry.Put("gPCUserExtensionNames", $exactExtension)
    $gpoEntry.Put("versionNumber", $versionNumber)
    $gpoEntry.Put("showInAdvancedViewOnly", "TRUE")

    # Clone parent ACL to avoid Access Denied in GPMC
    if ($isNew) {
        $parentSec = $policiesContainer.Properties["ntSecurityDescriptor"].Value
        if ($parentSec) {
            $gpoEntry.Properties["ntSecurityDescriptor"].Value = $parentSec
        }
    }

    $gpoEntry.SetInfo()

    #
    # 2. Build SYSVOL Directory Structure
    #
    $userPrefPath = Join-Path $gpoSysvolPath "User\Preferences\Shortcuts"
    $machinePath  = Join-Path $gpoSysvolPath "Machine"

    @($gpoSysvolPath, $userPrefPath, $machinePath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -Path $_ -ItemType Directory -Force | Out-Null
        }
    }

    try {
        icacls.exe $gpoSysvolPath /inheritance:e /T /C /Q 2>$null | Out-Null
    } catch { }

    #
    # 3. gpt.ini
    #
    $gptIni = @"
[General]
Version=$versionNumber
displayName=$gpoName
"@
    Set-Content -Path (Join-Path $gpoSysvolPath "gpt.ini") -Value $gptIni -Encoding Ascii

    #
    # 4. Generate Working Shortcuts.xml
    #
    $timeNow = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    $desktopUid = [Guid]::NewGuid().ToString("B").ToUpper()
    $startMenuUid = [Guid]::NewGuid().ToString("B").ToUpper()

    # Escape XML entities in arguments
    $xmlEscapedArgs = [System.Security.SecurityElement]::Escape($Arguments)

    $xmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Shortcuts clsid="{872ECB34-B2EC-401b-A585-D32574AA90EE}">
  <Shortcut clsid="{4F2F7C55-2790-433e-8127-0739D1CFA327}" name="$ShortcutName" status="$ShortcutName" image="1" changed="$timeNow" uid="$desktopUid" userContext="1" bypassErrors="1" removePolicy="1">
    <Properties pidl="" targetType="FILESYSTEM" action="U" comment="$Comment" shortcutKey="0" startIn="" arguments="$xmlEscapedArgs" iconIndex="$IconIndex" targetPath="$TargetPath" iconPath="$IconPath" window="MIN" shortcutPath="%DesktopDir%\$ShortcutName" />
  </Shortcut>
  <Shortcut clsid="{4F2F7C55-2790-433e-8127-0739D1CFA327}" name="$ShortcutName" status="$ShortcutName" image="1" changed="$timeNow" uid="$startMenuUid" userContext="1" bypassErrors="1" removePolicy="1">
    <Properties pidl="" targetType="FILESYSTEM" action="U" comment="$Comment" shortcutKey="0" startIn="" arguments="$xmlEscapedArgs" iconIndex="$IconIndex" targetPath="$TargetPath" iconPath="$IconPath" window="MIN" shortcutPath="%StartMenuDir%\$ShortcutName" />
  </Shortcut>
</Shortcuts>
"@

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText((Join-Path $userPrefPath "Shortcuts.xml"), $xmlContent.Trim(), $utf8NoBom)

    #
    # 5. Link to OU
    #
    if ([System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$targetOU_DN")) {
        $targetOU = [ADSI]"LDAP://$targetOU_DN"
        $existingLinks = $targetOU.Properties['gPLink'].Value
        if ($existingLinks) {
            if ($existingLinks -notlike "*$cleanGpoID*") {
                $targetOU.Properties['gPLink'].Value = "$gpoLdapPath$existingLinks"
            }
        } else {
            $targetOU.Properties['gPLink'].Value = $gpoLdapPath
        }

        if (-not $targetOU.Properties['gPOptions'].Value) {
            $targetOU.Properties['gPOptions'].Value = 0
        }

        $targetOU.SetInfo()
    } else {
        Write-Warning "Target OU '$TargetOUFriendlyName' not found. Link skipped."
    }

    if ($quiet) { return }
    Write-Host "[+] Successfully created and populated Shortcut GPO ($cleanGpoID)" -ForegroundColor Green
}

function New-CustomGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetOUFriendlyName,

        [Parameter()]
        [string]$GpoID = "{00000000-7E5A-C0DE-7E5A-000000000000}",

        [Parameter()]
        [string]$GpoDisplayName = "Mobile Logon"
    )

    $cleanGuid = if ($GpoID -match '^\{[0-9a-fA-F-]+\}$') { $GpoID.ToUpper() } else { "{$($GpoID.ToUpper())}" }

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $rootDSE = [ADSI]"LDAP://RootDSE"
    $namingContext = $rootDSE.defaultNamingContext
    $policyContainer = "CN=Policies,CN=System,$namingContext"
    $targetOU_DN = "OU=$TargetOUFriendlyName,$namingContext"

    $gpoSysvolPath = "\\$domain\sysvol\$domain\policies\$cleanGuid"
    $gpoLdapPath   = "[LDAP://CN=$cleanGuid,$policyContainer;0]"

    # 1. Create or bind to the AD Group Policy Container (GPC)
    $gpoLdapUri = "LDAP://CN=$cleanGuid,$policyContainer"
    if ([System.DirectoryServices.DirectoryEntry]::Exists($gpoLdapUri)) {
        $gpoEntry = [ADSI]$gpoLdapUri
        Write-Host "[-] GPC object already exists in AD: $cleanGuid" -ForegroundColor Yellow
    } else {
        $policiesDir = [ADSI]"LDAP://$policyContainer"
        $gpoEntry = $policiesDir.Create("groupPolicyContainer", "CN=$cleanGuid")
    }

    $gpoEntry.Put("displayName", $GpoDisplayName)
    $gpoEntry.Put("flags", 0)                 # 0 = Both User & Computer enabled
    $gpoEntry.Put("gPCFileSysPath", $gpoSysvolPath)
    $gpoEntry.Put("versionNumber", 0)          # 0 = Brand new / clean version
    $gpoEntry.Put("showInAdvancedViewOnly", "TRUE")
    $gpoEntry.SetInfo()

    # 2. Build standard SYSVOL folder structure
    $machinePath = Join-Path $gpoSysvolPath "Machine"
    $userPath    = Join-Path $gpoSysvolPath "User"

    @($gpoSysvolPath, $machinePath, $userPath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -Path $_ -ItemType Directory -Force | Out-Null
        }
    }

    # 3. Create minimal gpt.ini
    $gptIniContent = @"
[General]
Version=0
displayName=$GpoDisplayName
"@
    Set-Content -Path (Join-Path $gpoSysvolPath "gpt.ini") -Value $gptIniContent -Encoding Ascii

    # 4. Link GPO to target OU
    if (-not [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$targetOU_DN")) {
        Write-Warning "Target OU '$targetOU_DN' does not exist. GPO created, but link was skipped."
        return
    }

    $targetOU = [ADSI]"LDAP://$targetOU_DN"
    $existingLinks = $targetOU.Properties['gPLink'].Value

    if ($existingLinks) {
        if ($existingLinks -notlike "*$cleanGuid*") {
            $targetOU.Properties['gPLink'].Value = "$gpoLdapPath$existingLinks"
        }
    } else {
        $targetOU.Properties['gPLink'].Value = $gpoLdapPath
    }

    if (-not $targetOU.Properties['gPOptions'].Value) {
        $targetOU.Properties['gPOptions'].Value = 0
    }

    $targetOU.SetInfo()
    Write-Host "[+] Created clean GPO '$GpoDisplayName' ($cleanGuid) and linked to '$TargetOUFriendlyName'." -ForegroundColor Green
    Write-Host "[+] Ready for editing via GPMC." -ForegroundColor DarkGray
}


### INITIALIZE

function New-InitResult {
    param(
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][ValidateSet('OK', 'CREATED', 'REPAIRED', 'FAILED', 'SKIPPED')][string]$Status,
        [Parameter(Mandatory)][string]$Details,
        [switch]$Fatal
    )
    [PSCustomObject]@{
        Component = $Component
        Status    = $Status
        Details   = $Details
        Fatal     = [bool]$Fatal
    }
}

function Test-AndFixDirectories {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$PathMap
    )
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($name in $PathMap.Keys) {
        $path = $PathMap[$name]

        if ([string]::IsNullOrWhiteSpace($path)) {
            $results.Add((New-InitResult -Component "Dir:$name" -Status 'FAILED' -Details "Path configuration is blank" -Fatal))
            continue
        }

        if (Test-Path -Path $path) {
            $results.Add((New-InitResult -Component "Dir:$name" -Status 'OK' -Details $path))
        } else {
            try {
                New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
                $results.Add((New-InitResult -Component "Dir:$name" -Status 'CREATED' -Details $path))
            } catch {
                $results.Add((New-InitResult -Component "Dir:$name" -Status 'FAILED' -Details "Failed to create '$path': $($_.Exception.Message)" -Fatal))
            }
        }
    }
    return $results
}


function Test-AndFixDeployerCert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CertName,
        [Parameter(Mandatory)][string]$PfxStoragePath,
        [securestring]$CertPassword
    )

    $existingCert = Get-ChildItem -Path Cert:\CurrentUser\My |
        Where-Object { $_.Subject -like "*$CertName*" } |
        Select-Object -First 1

    if ($existingCert) {
        return (New-InitResult -Component 'Cert:Store' -Status 'OK' -Details "Thumbprint: $($existingCert.Thumbprint)")
    }

    $pfxFile = Join-Path $PfxStoragePath "$CertName.pfx"
    $cerFile = Join-Path $PfxStoragePath "$CertName.cer"

    # Case A: Import existing PFX from centralized share
    if (Test-Path $pfxFile) {
        if (-not $CertPassword) {
            $CertPassword = Read-Host -AsSecureString -Prompt "[!] Certificate password required to import '$pfxFile'"
        }
        try {
            Import-PfxCertificate -FilePath $pfxFile -CertStoreLocation Cert:\CurrentUser\My -Password $CertPassword -ErrorAction Stop | Out-Null
            return (New-InitResult -Component 'Cert:Store' -Status 'REPAIRED' -Details "Imported $pfxFile")
        } catch {
            return (New-InitResult -Component 'Cert:Store' -Status 'FAILED' -Details "Failed to import $pfxFile : $($_.Exception.Message)" -Fatal)
        }
    }

    # Case B: Mint new certificate, export to share, install locally
    try {
        if (-not $CertPassword) {
            $CertPassword = ConvertTo-SecureString -AsPlainText -Force 'deployer'
        }

        $c = New-SelfSignedCertificate `
            -Subject "CN=$CertName" `
            -Type DocumentEncryptionCert `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyExportPolicy Exportable `
            -NotAfter (Get-Date).AddYears(5) `
            -ErrorAction Stop

        Export-PfxCertificate -Cert $c -FilePath $pfxFile -Password $CertPassword -ErrorAction Stop | Out-Null
        Export-Certificate -Cert $c -FilePath $cerFile -ErrorAction Stop | Out-Null

        return (New-InitResult -Component 'Cert:Store' -Status 'CREATED' -Details "Minted new cert and stored to $pfxFile")
    } catch {
        return (New-InitResult -Component 'Cert:Store' -Status 'FAILED' -Details "Creation failed: $($_.Exception.Message)" -Fatal)
    }
}

function Test-AndFixSshEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$NfsHome,
        [Parameter()][switch]$quiet
    )

    if ([string]::IsNullOrWhiteSpace($KeyPath) -or $KeyPath.EndsWith('\')) {
        return (New-InitResult -Component 'SSH:Config' -Status 'FAILED' -Details "Invalid SSH key path: '$KeyPath'" -Fatal)
    }

    $nfsSsh      = Join-Path $NfsHome '.ssh'
    $localSsh    = Join-Path $env:USERPROFILE '.ssh'
    $rAuthorized = Join-Path $nfsSsh 'authorized_keys'

    try {
        # 1. Directory checks
        foreach ($dir in @($localSsh, $nfsSsh)) {
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
            }
        }

        # 2. Permissions lock-down (Inheritance removal + single-owner grant)
        icacls.exe $localSsh /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)(F)" 2>$null | Out-Null
        icacls.exe $nfsSsh   /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)(F)" 2>$null | Out-Null

        # 3. Keypair generation
        $keyCreated = $false
        if (-not (Test-Path $KeyPath)) {
            $keyDir = Split-Path -Parent $KeyPath
            if (-not (Test-Path $keyDir)) { New-Item -ItemType Directory -Path $keyDir -Force | Out-Null }
            ssh-keygen -f "$KeyPath" -C 'MobileDeployer' -N '""' -t ecdsa -q
            $keyCreated = $true
        }

        icacls.exe $KeyPath /inheritance:r /grant:r "$($env:USERNAME):(R)" 2>$null | Out-Null

        # 4. Authorized keys enrollment
        $pubKey = (ssh-keygen -yf $KeyPath).Trim()
        if (-not (Test-Path $rAuthorized)) {
            New-Item -ItemType File -Path $rAuthorized -Force | Out-Null
        }

        $existingAuth = Get-Content -Path $rAuthorized -ErrorAction SilentlyContinue
        if ($existingAuth -notcontains $pubKey) {
            Add-Content -Path $rAuthorized -Value $pubKey -Encoding UTF8
            icacls.exe $rAuthorized /inheritance:r /grant:r "$($env:USERNAME):(R)" 2>$null | Out-Null
        }

        $status = if ($keyCreated) { 'CREATED' } else { 'OK' }
        if ($quiet) { return $true }
        return (New-InitResult -Component 'SSH:Environment' -Status $status -Details "Key at $KeyPath enrolled in $rAuthorized")
    } catch {
        if ($quiet) { return $false }
        return (New-InitResult -Component 'SSH:Environment' -Status 'FAILED' -Details $_.Exception.Message -Fatal)
    }
}


function Initialize-Environment {
    [CmdletBinding()]
    param(
        [Parameter()][string]$SshKeyPath   = $Script:Config.SSHKeyPath,
        [Parameter()][string]$NfsHome      = $Script:Config.NfsHome,
        [Parameter()][string]$AdminRoot    = $Script:Config.AdminRoot,
        [Parameter()][string]$MobileDump   = $Script:Config.MobileDump,
        [Parameter()][string]$MobileEntries= $Script:Config.MobileEntries,
        [Parameter()][string]$CertName      = $(if ($Script:Config.CertName) { $Script:Config.CertName } else { 'MobileDeployer' }),
        [Parameter()][switch]$HaltOnError,
        [Parameter()][switch]$Console
    )

    if ($console) { Write-Host "`n[+] Executing System Requirements & Provisioning..." -ForegroundColor Cyan }
    $results = [System.Collections.Generic.List[object]]::new()

    # 1. Directory Structure Mapping
    $requiredPaths = @{
        'NfsHome'       = $NfsHome
        'AdminRoot'     = $AdminRoot
        'MobileDump'    = $MobileDump
        'MobileEntries' = $MobileEntries
    }
    $results.AddRange((Test-AndFixDirectories -PathMap $requiredPaths))

    # 2. SSH Environment
    $results.Add((Test-AndFixSshEnvironment -KeyPath $SshKeyPath -NfsHome $NfsHome))

    # 3. Document Encryption Cert
    $results.Add((Test-AndFixDeployerCert -CertName $CertName -PfxStoragePath $AdminRoot))

    $results.Add((New-ShortcutGPO -TargetOUFriendlyName "LabUsers" -quiet))

    #
    # Pretty-Print Provisioning Ledger
    #
    $colorMap = @{
        'OK'       = 'Green'
        'CREATED'  = 'Cyan'
        'REPAIRED' = 'Yellow'
        'SKIPPED'  = 'DarkGray'
        'FAILED'   = 'Red'
    }

    if ($console) {
        Write-Host ""
        Write-Host ("  {0,-20} {1,-10} {2}" -f 'COMPONENT', 'STATUS', 'DETAILS') -ForegroundColor DarkGray
        Write-Host ("  {0,-20} {1,-10} {2}" -f ('-' * 20), ('-' * 10), ('-' * 45)) -ForegroundColor DarkGray


        foreach ($r in $results) {
            $color = $colorMap[$r.Status]
            Write-Host ("  {0,-20} " -f $r.Component) -NoNewline
            Write-Host ("[{0,-8}]" -f $r.Status) -ForegroundColor $color -NoNewline
            Write-Host (" {0}" -f $r.Details)
        }
        Write-Host ""
    }

    #
    # Final Validation Guard
    #
    $criticalFails = @($results | Where-Object { $_.Fatal -and $_.Status -eq 'FAILED' })

    if ($criticalFails.Count -gt 0) {
        Write-Host "[!] Preflight checks failed with $($criticalFails.Count) fatal error(s)." -ForegroundColor Red
        if ($HaltOnError) {
            throw "Environment provisioning incomplete. Halting execution."
        }
        return $false
    }

    if ($console) { Write-Host "[+] All dependencies satisfied. Environment ready for deployment." -ForegroundColor Green}
    return $true
}

function New-DeployerCertificate {
    [CmdletBinding()]
    param(
        [Parameter()][securestring]$certPass = (ConvertTo-SecureString -AsPlainText -Force 'deployer'),
        [Parameter()][string]$outPath = $Script:Config.NfsHome
    )
    $c = New-SelfSignedCertificate -Subject 'CN=MobileDeployer' -Type DocumentEncryptionCert -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5)
    Export-PFXCertificate -Cert $c -FilePath (Join-Path $outPath "Deployer.pfx") -Password $certPass
    Export-Certificate -Cert $c -FilePath (Join-Path $outPath "Deployer.cer") 
    
}



# function Initialize-Ssh-Environment {
#     [CmdletBinding()]
#     param(
#         [string]$keyPath = $Script:Config.SSHKeyPath,
#         [string]$nfsHome = $Script:Config.NfsHome
#     )
#     # r = remote ; l = local
#     $nfsSSH = Join-Path  $nfsHome '.ssh'
#     $localSSh = Join-Path $env:UserProfile ".ssh"
#     $rAuthorized = Join-Path $nfsSSH 'authorized_keys'
#
#     @($nfsSSH, $localSSH) | Where-Object { -not (Test-Path $_ ) } | ForEach-Object {
#         New-Item -ItemType Directory -Path $_ -Force | Out-Null
#     }
#
#     if ([string]::IsNullOrWhiteSpace($keyPath) -or $keyPath.EndsWith('\')) {
#         throw "SSH KEY PATH IS INVALID! -- '$sshKeyPath'  -- CHECK SSH KEY"
#     }
#
#
#     icacls.exe $nfsSSH /inheritance:r /T |Out-Null
#     icacls.exe $nfsSSH /grant:r "$($env:USERNAME):(R)" /T |out-null
#
#
#     icacls.exe $localSSH /inheritance:r |Out-Null
#     icacls.exe $localSSH /grant:r "$($env:USERNAME):(R)" /T | Out-Null
#
#     if (-not (Test-Path $keyPath)) {
#         ssh-keygen -f "$keyPath" -C '""' -N '""' -t ecdsa -q
#
#     }
#
#     icacls.exe $keyPath /inheritance:r |Out-Null
#     icacls.exe $keyPath /grant:r "$($env:USERNAME):(R)"| Out-Null
#     $pubKey = ssh-keygen -yf $keyPath
#     if (-not (Test-Path $rAuthorized)) { New-Item -Type File -Path $rAuthorized -Force | Out-Null
#     }
#     if (-not (Select-String -Pattern $pubKey -Path $rAuthorized -ErrorAction SIlentlyContinue)) {
#         $pubKey | Add-Content -Encoding UTF8 -Path $rAuthorized
#         icacls.exe $rAuthorized /inheritance:r |Out-Null
#         icacls.exe $rAuthorized /grant:r "$($env:USERNAME):(R)"| Out-Null
#     }
#
#
# }
#
#
#
# function Initialize-Functionality {
#     [CmdletBinding()]
#     param(
#         [Parameter()]
#         [string]$sshKeyPath = $script:Config.SshKeyPath,
#         [string]$nfsHome = $script:Config.nfsHome,
#         [string]$adminRoot = $script:Config.AdminRoot,
#         [string]$certName = $script:Config.certName
#
#     )
#
#     Initialize-Ssh-Environment  -nfsHome $nfsHome -keyPath $sshKeyPath
#
#     # 2. Ensure Document Encryption Certificate Exists in CurrentUser\My
#     $existingCert = Get-ChildItem -Path Cert:\CurrentUser\My | 
#         Where-Object { $_.Subject -like '*CN=MobileDeployer*' -or $_.Subject -like "*$($certName)*" }
#
#     if (-not $existingCert) {
#         $pfxFileName = "$($certName).pfx"
#         $pfxFullPath = Join-Path $cfg.AdminRoot $pfxFileName
#         # $securePass  = ConvertTo-SecureString -AsPlainText -Force $cfg.DefaultPass
#         $securePass = Read-Host -AsSecureString -Prompt "[!] The decryption certificate isn't in your cert store. Please enter the administrative password to import it "
#
#         if (Test-Path $pfxFullPath) {
#             Import-PfxCertificate -FilePath $pfxFullPath -CertStoreLocation Cert:\CurrentUser\My -Password $securePass | Out-Null
#             Write-Host "[+] Imported existing deployer certificate from: $pfxFullPath" -ForegroundColor Green
#         } else {
#             # Generates PFX/CER in the target directory and automatically adds to Cert:\CurrentUser\My
#             New-DeployerCertificate -certPass $securePass -outPath $pfxFullPath
#             Write-Host "[+] Generated and installed new deployment certificate in: $($pfxFullPath)" -ForegroundColor Green
#         }
#     }
# }
function New-WindowsPostTask-SupportAcl {
    [CmdletBinding()]
    param(
        [string]$Path = 'C:\Support'
    )

    return @"
# Task: Support ACL

try {
    & icacls.exe '$Path' /inheritance:r /T /Q | Out-Null

    if (`$LASTEXITCODE -ne 0) {
        throw "inheritance command failed with `$LASTEXITCODE"
    }

    & icacls.exe '$Path' /grant Administrators:F ISSO:F /T /Q | Out-Null

    if (`$LASTEXITCODE -ne 0) {
        throw "grant command failed with `$LASTEXITCODE"
    }

    record_action 'SupportAcl' '$Path' 'Success'
}
catch {
    record_action 'SupportAcl' '$Path' 'Failed'
    record_failure "Support ACL: `$(`$_.Exception.Message)"
}
"@
}

function New-WindowsPostTask-NetworkSharing {
    [CmdletBinding()]
    param(
        [string[]]$DriveLetters
    )

    $driveInit = if ($DriveLetters) {
        '$driveList = @(' +
        (($DriveLetters | ForEach-Object { "'$_'" }) -join ',') +
        ')'
    } else {
        @'
$driveList = @(
    Get-PSDrive -PSProvider FileSystem |
        Select-Object -ExpandProperty Name
)
'@
    }

    return  $driveInit + @'
# Task: Network Sharing


try {
    Enable-NetFirewallRule `
        -DisplayGroup 'File and Printer Sharing' `
        -ErrorAction Stop

    $failedShares = @()

    foreach ($d in $driveList) {
        $path = "$d`:"

        if (-not (Test-Path $path)) {
            $failedShares += "$path does not exist"
            continue
        }

        if (-not (Get-SmbShare -Name $d -ErrorAction SilentlyContinue)) {
            try {
                New-SmbShare `
                    -Name $d `
                    -Path $path `
                    -FullAccess 'Authenticated Users','mobile-smb-access' `
                    -ErrorAction Stop |
                    Out-Null
            }
            catch {
                $failedShares += "$d : $($_.Exception.Message)"
            }
        }
    }

    if ($failedShares.Count -eq 0) {
        record_action 'NetworkSharing' 'SMB' 'Success'
    }
    else {
        record_action 'NetworkSharing' 'SMB' 'Failed'

        foreach ($failure in $failedShares) {
            record_failure "Network sharing: $failure"
        }
    }
}
catch {
    record_action 'NetworkSharing' 'SMB' 'Failed'
    record_failure "Network sharing failed: $($_.Exception.Message)"
}
'@
}

function New-WindowsPostTask-UserRights {
    [CmdletBinding()]
    param(
        [switch]$Sharing,
        [switch]$HasLinux
    )

    $sharingSetup = ''

    if ($Sharing -and $HasLinux) {
        $sharingSetup = @'
$smbPass = ConvertTo-SecureString 'SupeSecretSMBP@ssw0rd99' -AsPlainText -Force

if (-not (Get-LocalUser -Name 'mobile-smb-access' -ErrorAction SilentlyContinue)) {
    New-LocalUser `
        -Name 'mobile-smb-access' `
        -Password $smbPass |
        Out-Null
}

$sharingSid = (Get-LocalUser -Name 'mobile-smb-access').Sid.Value

'@
    }

    return $sharingSetup + @'
# Task: User Rights

$tmpSec = Join-Path $env:TEMP 'sec_export.inf'
$tmpDB  = Join-Path $env:TEMP 'sec_temp.sdb'

secedit /export /cfg $tmpSec /quiet

$objUser = New-Object System.Security.Principal.NTAccount('Authenticated Users')
$objSid = $objUser.Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value

$secSid = "*$objSid"

$rights = @(
    'SeInteractiveLogonRight',
    'SeRemoteInteractiveLogonRight',
    'SeNetworkLogonRight'
)

$denyRights = @(
    'SeDenyInteractiveLogonRight',
    'SeDenyRemoteInteractiveLogonRight',
    'SeDenyBatchLogonRight',
    'SeDenyServiceLogonRight'
)

$cfg = Get-Content -Raw -Encoding Unicode $tmpSec

foreach ($r in $rights) {
    $pattern = "(?m)^\s*$([regex]::Escape($r))\s*=[^\r\n]*"

    if ($cfg -notmatch $pattern) {
        $cfg += "`r`n$r = $secSid"
        continue
    }

    $line = [regex]::Match($cfg, $pattern).Value

    if ($line -notmatch [regex]::Escape($objSid)) {
        $cfg = $cfg -replace $pattern, "$0,$secSid"
    }
}

if ($sharingSid) {
    $shareSid = "*$sharingSid"

    foreach ($r in $denyRights) {
        $pattern = "(?m)^\s*$([regex]::Escape($r))\s*=[^\r\n]*"

        if ($cfg -notmatch $pattern) {
            $cfg += "`r`n$r = $shareSid"
            continue
        }

        $line = [regex]::Match($cfg, $pattern).Value

        if ($line -notmatch [regex]::Escape($sharingSid)) {
            $cfg = $cfg -replace $pattern, "$0,$shareSid"
        }
    }
}

$cfg | Set-Content -Path $tmpSec -Encoding Unicode

secedit /configure `
    /db $tmpDB `
    /cfg $tmpSec `
    /areas USER_RIGHTS `
    /quiet

if ($LASTEXITCODE -eq 0) {
    record_action 'UserRights' 'LocalSecurityPolicy' 'Success'
}
else {
    record_action 'UserRights' 'LocalSecurityPolicy' 'Failed'
    record_failure "User rights configuration failed: exit code $LASTEXITCODE"
}

Remove-Item $tmpSec, $tmpDB -Force -ErrorAction SilentlyContinue
'@
}

function Get-PostDeployScript {
    [CmdletBinding()]
    param(
        [switch]$UserRights,
        [switch]$Sharing,
        [switch]$HasLinux,

        [string[]]$DriveLetters
    )

    $tasks = [System.Collections.Generic.List[string]]::new()

    $tasks.Add(@'
# ==================
# Automated Post-Deployment
# ==================

$actions = [System.Collections.Generic.List[object]]::new()
$failures = [System.Collections.Generic.List[string]]::new()

function record_action {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Status,
        $Details = $null
    )

    $actions.Add([PSCustomObject]@{
        Category = $Category
        Name     = $Name
        Status   = $Status
        Details  = $Details
    })
}

function record_failure {
    param([string]$Message)

    $failures.Add($Message)
}
'@)

    if ($UserRights) { $tasks.Add( (New-WindowsPostTask-UserRights  -Sharing:$Sharing  -HasLinux:$HasLinux)) }

    if ($Sharing) { $tasks.Add( (New-WindowsPostTask-NetworkSharing  -DriveLetters $DriveLetters)) }

    $tasks.Add( (New-WindowsPostTask-SupportAcl))

    $tasks.Add(@'
"[ Post Deployment Ran - $(Get-Date) ]" |
    Out-File C:\Post-Deploy.info

[PSCustomObject]@{
    Platform = 'Windows'
    Success  = ($failures.Count -eq 0)
    Actions  = $actions.ToArray()
    Failures = $failures.ToArray()
} | Export-CLIXML C:\Post-Deployment.xml
'@)

    return ($tasks -join "`n`n")
}




function Get-UserFullName {
    [CmdletBinding()]
    param(
        [Parameter()][string]$UserName,
        [Parameter()][string]$FullName
    )

    if ([string]::IsNullOrWhiteSpace($FullName) -and -not [string]::IsNullOrWhiteSpace($UserName)) {
        $searcher = [System.DirectoryServices.DirectorySearcher]::new()
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$([System.Security.SecurityElement]::Escape($UserName))))"
        $searcher.PropertiesToLoad.AddRange(@('displayName', 'givenName', 'sn'))

        $result = $searcher.FindOne()
        if ($result) {
            $props = $result.Properties
            if ($props.Contains('displayName') -and -not [string]::IsNullOrWhiteSpace($props['displayName'][0])) {
                return $props['displayName'][0]
            }

            $first = if ($props.Contains('givenName')) {
                $props['givenName'][0] 
            } else { 
                '' 
            }
            $last  = if ($props.Contains('sn')) { 
                $props['sn'][0] 
            } else {
                '' 
            }
            $combined = "$first $last".Trim()

            if (-not [string]::IsNullOrWhiteSpace($combined)) {
                return $combined
            }
        }
    }

    return $FullName
}


function New-LinuxTask-CreateDirectory {
    [CmdletBinding()]
    param([string]$Path = '/mobiles/home')
    return @"
# Task: Create Directory: ($Path)
if dzdo mkdir -p '$Path' &> /dev/null; then
    record_action 'Directory' '$Path' 'Success'
else
    record_failure 'Directory: $Path failed to create'
fi
"@
}

function New-LinuxTask-AddLogService {
    [CmdletBinding()]
    param([string]$ExecPath = '/path/to-rotate')
    return @"
#Log rotation Unit Files

cat << 'EOF' | dzdo tee /etc/systemd/system/mobile-logrotate.timer >/dev/null
[Unit]
Description=Mobile Log Rotate Timer

[Timer]
OnCalendar=Sun 23:59
Persistent=True

[Install]
WantedBy=timers.target
EOF

cat << 'EOF' | dzdo tee /etc/systemd/system/mobile-logrotate.service >/dev/null
[Unit]
Description=Mobile Log Rotate Service

[Service]
Restart=on-failure
RemainAfterExit=no
ExecStart=$ExecPath

[Install]
WantedBy=multi-user.target
EOF

dzdo systemctl daemon-reload &>/dev/null

if dzdo systemctl enable --now mobile-logrotate.timer &>/dev/null; then
    record_action 'ScheduledTask' 'mobile-logrotate.timer' 'Success'
else
    record_action 'ScheduledTask' 'mobile-logrotate.timer' 'Failed'
    record_failure "Scheduled task 'mobile-logrotate.timer': failed to enable"
fi
"@
}

function New-LinuxTask-Luks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$CurrentPass,
        [Parameter(Mandatory)] [string]$NewPin
    )

    return @"
# Task: LUKS Enrollment
mapfile -t luks_devices < <(
    lsblk -prno NAME,FSTYPE 2>/dev/null | awk '`$2 == "crypto_LUKS" {print `$1}'
)

for dev in "`${luks_devices[@]}"; do
    if printf "%s\n%s\n" '$CurrentPass' '$NewPin' | dzdo cryptsetup luksAddKey --force --batch-mode "`$dev" &>/dev/null; then
        record_action 'DiskEncryption' "`$dev" 'Success'
    else
        record_action 'DiskEncryption' "`$dev" 'Failed'
        record_failure "Disk encryption `$dev: failed to add LUKS key"
    fi
done
"@
}


function New-LinuxTask-AddUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [array]$Users,
        [string]$HomeBase = '/mobiles/home'
    )

    $userBlocks = [System.Collections.Generic.List[string]]::new()

    foreach ($u in $Users) {
        $isWheel = $u.LinuxAccountType -eq [LinuxAccountType]::Wheel
        $name = $u.LinuxName
        $pwd  = $u.LinuxPassword
        $desc = $u.Description

        $block = @"
# Provisioning: $name
if id '$name' &>/dev/null; then
    if dzdo usermod -p '$pwd' '$name' &>/dev/null; then
        record_action 'User' '$name' 'Existed'
    else
        record_action 'User' '$name' 'Failed'
        record_failure 'User "$name": failed to update account'
    fi
else
    if dzdo useradd -m -b '$HomeBase' -c '$desc' -p '$pwd' '$name' &>/dev/null; then
        record_action 'User' '$name' 'Success'
    else
        record_action 'User' '$name' 'Failed'
        record_failure 'User "$name": failed to create account'
    fi
fi
"@
        if ($isWheel) {
            $block += @"

if id '$name' &>/dev/null; then
    if dzdo usermod -aG wheel '$name' &>/dev/null; then
        record_action 'Privilege' '${name}:wheel' 'Success'
    else
        record_action 'Privilege' '${name}:wheel' 'Failed'
        record_failure 'Privilege "${name}:wheel": failed to assign wheel'
    fi
else
    record_action 'Privilege' '${name}:wheel' 'Failed'
    record_failure 'Privilege "${name}:wheel": user does not exist'
fi
"@
        }

        if ($u.MustChangePassword) {
            $block += @"

if id '$name' &>/dev/null; then
    if dzdo chage -d 0 '$name' &>/dev/null; then
        record_action 'PasswordExpiry' '$name' 'Success'
    else
        record_action 'PasswordExpiry' '$name' 'Failed'
        record_failure 'Password expiry "$name": failed'
    fi
else
    record_action 'PasswordExpiry' '$name' 'Failed'
    record_failure 'Password expiry "$name": user does not exist'
fi
"@
        }

        $userBlocks.Add($block)
    }

    return ($userBlocks -join "`n`n")
}




function Get-LinuxDeployScript {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$AllUsers,

        [Parameter()]
        [switch]$SkipLuks,

        [Parameter()]
        [switch]$SkipLogrotate
    )

    # 1. Resolve users according to metadata priority
    $linuxUsers = foreach ($group in ($AllUsers | Group-Object BaseName)) {
        $group.Group |
            Where-Object { $null -ne $_.LinuxAccountType } |
            Sort-Object { $script:GroupMetadata[$_.GroupType].LinuxPriority } -Descending |
            Select-Object -First 1
    }

    # 2. Bash execution runtime + state logger
    $header = @'
#!/usr/bin/env bash
set -o pipefail

declare -a actions_json=()
declare -a failures=()

record_action() {
    local category="$1"
    local name="$2"
    local status="$3"
    local details="${4:-null}"

    actions_json+=( "$(jq -n \
        --arg cat "$category" \
        --arg name "$name" \
        --arg stat "$status" \
        --argjson det "$details" \
        '{
            Category: $cat,
             Name: $name,
             Status: $stat,
             Details: (if $det == "" then null else $det end)
             
        }'
        )" )
}

record_failure() {
    failures+=("$1")
}
array_to_json() {
    if (( $# == 0 )); then
        printf '[]'
    else
        printf '%s\n' "$@" | jq -R . | jq -s .
    fi
}
'@

    $footer = @'
# --- Result Serialization ---
final_actions="[$(IFS=,; echo "${actions_json[*]}")]"
if [[ ${#failures[@]} -eq 0 ]]; then
    final_failures="[]"
else
    final_failures="$(printf '%s\n' "${failures[@]}" | jq -R . | jq -s .)"
fi

jq -n \
    --arg hostname "$(hostname -s)" \
    --argjson success "$([[ ${#failures[@]} -eq 0 ]] && echo true || echo false)" \
    --argjson actions "$final_actions" \
    --argjson failures "$final_failures" \
    '{
        HostName: $hostname,
        Platform: "Linux",
        Success: $success,
        Actions: $actions,
        Failures: $failures
    }'
'@

    # 3. Assemble tasks pipeline dynamically
    $tasks = [System.Collections.Generic.List[string]]::new()
    $tasks.Add($header)

    $tasks.Add((New-LinuxTask-CreateDirectory -Path '/mobiles/home'))

    if (-not $SkipLogrotate) { $tasks.Add((New-LinuxTask-AddLogService )) }

    if (-not $SkipLuks) { $tasks.Add((New-LinuxTask-Luks  -CurrentPass $script:Config.curLuks  -NewPin $script:Config.encryptionPin)) }

    if ($linuxUsers) { $tasks.Add((New-LinuxTask-AddUsers -Users $linuxUsers -HomeBase '/mobiles/home')) }

    # 4. Standardized JSON Output emitter
    $tasks.Add($footer)

    return ($tasks -join "`n`n")
}

### END UTILS

function Get-EncryptedCredRSA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PassFile,
        [Parameter(Mandatory = $true)]
        [string]$DefaultPass,
        [Parameter(Mandatory = $true)]
        [string]$PfxPath
    )

    if (-not (Test-Path $PassFile) -or -not (Test-Path $PfxPath)) {
        return $DefaultPass
    }

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath)
    $rsa  = $cert.GetRSAPrivateKey()

    try {
        $eBytes  = [System.Convert]::FromBase64String((Get-Content $PassFile -Raw).Trim())
        $padding = [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1
        $dBytes  = $rsa.Decrypt($eBytes, $padding)
        return [System.Text.Encoding]::UTF8.GetString($dBytes)
    } catch {
        Write-Warning "Decryption failed for $PassFile. Returning default password."
        return $DefaultPass
    } finally {
        if ($rsa) { $rsa.Dispose() 
        }
        if ($cert) { $cert.Dispose() 
        }
    }
}

#### USER PASSWORD AND DERIVATION FUNCTIONS

function Get-UserCreds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MobileName,
        [Parameter(Mandatory = $true)][array]$AllUsers,
        [Parameter(Mandatory = $true)][string]$mobileDumpPath
    )
    foreach ($bName in ($allUsers.BaseName | Sort-Object -Unique)) {
        $PwFile = Join-Path  $mobileDumpPath $bName
        if ( ! (Test-Path $PwFile )) {
            continue
        }
        $content = Unprotect-CmsMessage -Content (Get-Content $PwFile)
        foreach ($line in ( $content -split '\r?\n')) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue 
            }
            $timestamp, $username, $pw = $line -split ':',3
            $uObject = $allUsers | Where-Object Name -eq $username | Select-Object -First 1
            if ($null -eq $uObject) {
                continue
            }
            $uObject.Password = ConvertTo-SecureString -AsPlainText -Force $pw
            $uObject.LinuxPassword = [Sha512Crypt]::Crypt($pw)
        }
    }
    

    $pw = $null
    [System.GC]::Collect()
    return $AllUsers
}


# --- Public Exported Functions ---







## MOBILE RETRIEVAL

function Get-MobileData {
    [CmdletBinding(DefaultParameterSetName = 'ExplicitPaths')]
    param(
        [Parameter(Position = 0)]
        [string]$MobileName,
        
        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [ValidateNotNullOrEmpty()]
        [string]$defaultUserpath = $Script:Config.mobileDefaultUsers,
        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [ValidateNotNullOrEmpty()]
        [string]$mobileEntriesPath = $Script:Config.MobileEntries,
        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [ValidateNotNullOrEmpty()]
        [string]$fallbackPass = $Script:Config.fallbackPass,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Config')]
        [PSCustomObject]$Config

    )




    if ($PSCmdlet.ParameterSetName -eq 'Config') {
        $cfg = Get-MobileConfig $Config
        $defaultUserpath = $cfg.mobileDefaultUsers
        $mobileEntriesPath = $cfg.MobileEntries
        $fallbackPass = $cfg.fallbackPass
    }

    $userPathExists = if (-not [string]::IsNullOrWhiteSpace($defaultUserpath)) { 
        Test-Path $defaultUserpath
    } else {
        $false
    }
    $mobileEntriesExist = if (-not [string]::IsNullOrWhiteSpace($mobileEntriesPath)) { 
        Test-Path $mobileEntriesPath
    } else {
        $false
    }

    Write-Debug "@
    =====
    Function = Get-MobileData
    [MobileName] = $mobileName
    [defaultUserPath] = $defaultUserpath  ; Path Exists = $($userPathExists)
    [MobileEntriesPath] = $mobileEntriesPath ; Path Exists = $ $mobileEntriesExist)
    [fallbackPass] = $fallbackPass  
    =====
 @" 

    if (-not $userPathExists -or -not $mobileEntriesExist) {
        Write-Error "[!] Ensure proper directory setup"
        Write-Warning "--- ${defaultUserPath}:${userPathExists}"
        Write-Warning "--- ${mobileEntriesPath}:${mobileEntriesExist}"
        exit 1
    }

    $result = [PsCustomObject]@{
        AllMobiles   = @()
        MobileUsers  = @()
        DefaultUsers = @()
        AllUsers     = @()
        Linux        = @()
        Windows      = @()
    }

    if (Test-Path $mobileEntriesPath) {
        $result.AllMobiles = Get-ChildItem -Path $mobileEntriesPath  |
            Select-Object -ExpandProperty BaseName -Unique
    }

    if ([string]::IsNullOrWhiteSpace($MobileName)) {
        return [PSCustomObject]$result
    }
    ## Default users
    $result.DefaultUsers = Get-ChildItem -Force -Path $defaultUserpath | Get-Content | ConvertFrom-CSV 
    Write-Debug " default user parsing: $($result.DefaultUsers)"


    ## Actual Mobile Data
    $path = Join-Path $mobileEntriesPath $MobileName

    $currentSection = $null
    $sections = @{}

    foreach ($line in Get-Content $path) {
        $trimmed = $line.Trim()

        if (
            [string]::IsNullOrWhiteSpace($trimmed) -or
            $trimmed.StartsWith('#') -or
            $trimmed.StartsWith(';')
        ) {
            continue
        }

        if ($trimmed -match '^\[(?<Header>.+)\]$') {
            $currentSection = $Matches.Header

            if (-not $sections.ContainsKey($currentSection)) {
                $sections[$currentSection] =
                [System.Collections.Generic.List[string]]::new()
            }

            continue
        }

        if ($null -ne $currentSection) {
            $sections[$currentSection].Add($trimmed)
        }
    }

    if ($sections.ContainsKey('users')) {
        $result.MobileUsers = @(
            $sections['users'] |
                ConvertFrom-Csv |
                ForEach-Object {
                    [PSCustomObject]@{
                        Username = $_.username
                        Groups   = if ($_.groups) {
                            $_.groups -split ';'
                        } else {
                            @()
                        }
                        Name = $_.name
                    }
                }
        )
    }

    if ($sections.ContainsKey('Windows')) {
        $result.Windows = @($sections['Windows'])
    }

    if ($sections.ContainsKey('Linux')) {
        $result.Linux = @($sections['Linux'])
    }
    $tmp = @($result.DefaultUsers) + @($result.MobileUsers)

    $allUsers = [System.Collections.Generic.List[object]]::new()

    foreach ($u in $tmp) {
        $grps = Set-Groups $u.Groups
        Write-Debug "$($u.Username) -- $($grps)"
        foreach ($grp in $grps) {
            $meta = $Script:GroupMetadata[$grp]
            $accountName = if ($meta.Suffix) {
                "$($u.Username).$($meta.Suffix)"
            } else {
                $u.Username
            }

            $uData = [PSCustomObject]@{
                BaseName = $u.UserName
                Name     = $accountName
                GroupType = $grp
                FullName = Get-UserFullName $u.Username $u.Name
                Password = (ConvertTo-SecureString -AsPlainText -Force $fallbackPass)
                Description = "$($meta.Description)"
                LinuxName = "$($u.UserName).local"
                LinuxPassword = [sha512Crypt]::Crypt($fallbackPass)
                LinuxAccountType = $meta.LinuxAccountType
                MustChangePassword = $true
            }

            $allUsers.Add($uData)
        }
    }
    $allUsers = $allUsers | Sort-Object Name -Unique

    $result.AllUsers = $allUsers

    [PSCustomObject]$result
}




function Get-TaskData {
    param(
        [string]$tasksPath,
        [bool]$hasLinux
    )

    $taskData = @()
    $disjoinData = Get-PostDeployScript -userRights -Sharing -hasLinux:$hasLinux
    # $disjoinB64 = ConvertTo-Base64 $disjoinData
    $bootTrigger = @{
        Type = [TaskTriggerType]::Boot
        Delay = 'PT1M'
    }
    $weeklyTrigger = @{
        Type = [TaskTriggerType]::Weekly
        DaysOfWeek = 1
        StartBoundary = (Get-Date "00:00:00").AddDays(1).ToString('s')
    }


    $domainDisjoinTask = New-TaskXML -Description 'Runs once after domain disjoin' `
        -Author '[Mobile Administration]' -Execute 'powershell.exe' `
        -ToEncode $disjoinData `
        -TriggerConfigs @($bootTrigger)
    # -Arguments "-NoProfile -ExecutionPolicyBypass -Encoded $disjoinB64" `


    $logCollect = New-TaskXML -Description 'Mobile Auto Log Collecot' `
        -Author '[Mobile Administration]' -Execute 'C:\Supportbin\logcollect' `
        -TriggerConfigs @($weeklyTrigger)

    $taskData += @([PsCustomObject]@{Taskname = "Mobile-LogCollect"; TaskXml = $logCollect})
    $taskData += @([PsCustomObject]@{Taskname = "Mobile-DisjoinTask"; TaskXml = $domainDisjoinTask})
    
    return $taskData
}

function Format-HostCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject
    )
    begin {
        $results = [System.Collections.Generic.List[object]]::new()
    }
    process {
        foreach ($item in $InputObject) {
            $results.Add($item)
        }
    }
    end {
        if ($results.Count -eq 0) {
            Write-Host "  No telemetry results returned." -ForegroundColor Yellow
            return
        }

        # Column definitions: header text + the property/logic used to derive each row's value
        $columns = @(
            @{ Header = 'HOST';    Getter = { param($r) $r.HostName.ToUpper() } }
            @{ Header = 'OS';      Getter = { param($r) $r.Platform } }
            @{ Header = 'KERNEL';  Getter = { param($r) if ($r.Success -and $r.Summary.Kernel) { $r.Summary.Kernel } else { '-' } } }
            @{ Header = 'AV DEFS'; Getter = { param($r) if ($r.Success -and $r.Summary.AVDefs) { $r.Summary.AVDefs } else { '-' } } }
            @{ Header = 'IVANTI';  Getter = { param($r) if ($r.Success -and $r.Summary.IvantiVersion) { $r.Summary.IvantiVersion } else { '-' } } }
            @{ Header = 'LICENSE'; Getter = { param($r) if ($r.Success -and $r.Summary.License) { $r.Summary.License } else { '-' } } }
            @{ Header = 'LAPS';    Getter = { param($r) if ($r.Success -and $r.Summary.AdminRotateVersion) { $r.Summary.AdminRotateVersion } else { '-' } } }
            @{ Header = 'PKGS';    Getter = { param($r) if ($r.Success -and $null -ne $r.Summary.PackageCount) { $r.Summary.PackageCount } else { '-' } } }
            # @{ Header = 'CPU';     Getter = { param($r) if ($r.Success -and $null -ne $r.Summary.Cores) { $r.Summary.Cores } else { '-' } } }
        )

        $sorted = $results | Sort-Object Platform, HostName

        # Pre-compute every cell value once, then derive each column's width from
        # the longest of: its header, or any value that will appear under it.
        $rows = foreach ($r in $sorted) {
            [PSCustomObject]@{
                Result = $r
                Cells  = $columns | ForEach-Object { & $_.Getter $r }
            }
        }

        $widths = for ($i = 0; $i -lt $columns.Count; $i++) {
            $maxCellLen = ($rows | ForEach-Object { "$($_.Cells[$i])".Length } | Measure-Object -Maximum).Maximum
            [Math]::Max($columns[$i].Header.Length, $maxCellLen)
        }

        # Build the format string dynamically: "  {0,-W0} {1,-W1} ... {N,-Wn}"
        $fmt = "  " + (
            (0..($columns.Count - 1) | ForEach-Object { "{$($_),-$($widths[$_])}" }) -join ' '
        )

        Write-Host ($fmt -f $columns.Header) -ForegroundColor DarkGray

        foreach ($row in $rows) {
            $r = $row.Result
            if ($r.Success) {
                Write-Host ($fmt -f $row.Cells)
            } else {
                $failCells = $row.Cells.Clone()
                $failCells[-1] = ''   # blank the last column so FAILED can be appended after
                Write-Host ($fmt -f $failCells) -NoNewline
                Write-Host 'FAILED' -ForegroundColor Red
            }
        }

        #
        # Failures beneath table
        #
        $failed = @($results | Where-Object { -not $_.Success })
        if ($failed.Count) {
            Write-Host ""
            Write-Host "  Failures:" -ForegroundColor DarkRed
            $hostWidth = [Math]::Max(
                10,
                [int](
                    $hosts |
                        ForEach-Object { $_.Length } |
                        Measure-Object -Maximum
                ).Maximum
            )
            foreach ($r in $failed) {
                foreach ($failure in @($r.Failures)) {
                    Write-Host ("    {0,-$hostWidth} {1}" -f $r.HostName, $failure) -ForegroundColor Red
                }
            }
        }
    }
}


function Get-MobileOverview {
    [CmdletBinding(DefaultParameterSetName = 'ExplicitPaths')]
    param(
        [Parameter(Position = 0)]
        [string]$MobileName,

        [Parameter(ParameterSetName = 'Config')]
        [AllowNull()]
        [object]$Config,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$defaultUsersPath = $Script:Config.mobileDefaultUsers,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$mobileEntriesPath = $Script:Config.MobileEntries,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$fallBackPass = $Script:Config.fallbackPass,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$nfsHome = $Script:Config.NfsHome,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$mobileDumpPath = $Script:Config.MobileDump,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$sshKeyPath = $Script:Config.SSHKeyPath,

        [Parameter()]
        [switch]$Full
    )

    # 1. Resolve Active Paths Based on Parameter Set
    if ($PSCmdlet.ParameterSetName -eq 'Config') {
        $cfg = Get-MobileConfig $Config
        $defaultUsersPath  = $cfg.mobileDefaultUsers
        $mobileEntriesPath = $cfg.MobileEntries
        $fallBackPass      = $cfg.fallbackPass
        $nfsHome           = $cfg.NfsHome
        $sshKeyPath        = $cfg.SSHKeyPath
        $mobileDumpPath    = $cfg.MobileDump

        $data = Get-MobileData -MobileName $MobileName -Config $cfg
    } else {
        $data = Get-MobileData -MobileName $MobileName `
            -defaultUserpath $defaultUsersPath `
            -mobileEntriesPath $mobileEntriesPath `
            -fallbackPass $fallBackPass
    }

    $width = 76

    function Write-CenteredHeader {
        param([string]$Text, [ConsoleColor]$Color = 'Cyan')
        $border  = '=' * $width
        $padding = [Math]::Max(0, [Math]::Floor(($width - $Text.Length) / 2))
        Write-Host $border -ForegroundColor $Color
        Write-Host (' ' * $padding + $Text) -ForegroundColor $Color
        Write-Host $border -ForegroundColor $Color
    }

    function Write-Section {
        param([string]$Text, [ConsoleColor]$Color = 'DarkYellow')
        Write-Host ""
        Write-Host ("[{0}]" -f $Text) -ForegroundColor $Color
        Write-Host ('-' * $width) -ForegroundColor DarkGray
    }

    if ($data.AllMobiles.Count -eq 0) {
        Write-Host "No available mobiles found." -ForegroundColor Yellow
        return
    }

    if ([string]::IsNullOrWhiteSpace($MobileName)) {
        Write-CenteredHeader -Text 'AVAILABLE MOBILES'
        foreach ($name in $data.AllMobiles) {
            Write-Host ("  {0,-30}" -f $name) -ForegroundColor Green
        }
        Write-Host ""
        return
    }

    Write-CenteredHeader -Text "MOBILE: $MobileName"

    # --- SECTION: Configured Users ---
    Write-Section -Text 'USERS' -Color DarkYellow
    Write-Host ("  {0,-18} {1,-18} {2,-24} {3}" -f 'USERNAME', 'GROUPS', 'FULL NAME', 'PASSWORD SET') -ForegroundColor DarkYellow

    foreach ($u in ($data.MobileUsers | Sort-Object Username)) {
        $hasPassword = $false
        if (-not [string]::IsNullOrWhiteSpace($mobileDumpPath) -and (Test-Path $mobileDumpPath)) {
            $passPath = Join-Path $mobileDumpPath $u.Username
            $hasPassword = Test-Path $passPath
        }

        $statusText  = if ($hasPassword) { "[+] SET" } else { "[-] PENDING" }
        $statusColor = if ($hasPassword) { 'Green' } else { 'DarkRed' }
        $groups      = $u.Groups -join ', '

        Write-Host ("  {0,-18} {1,-18} {2,-24} " -f $u.Username, $groups, $u.Name) -ForegroundColor Yellow -NoNewline
        Write-Host $statusText -ForegroundColor $statusColor
    }

    # --- SECTION: Windows Nodes ---
    if ($data.Windows.Count -gt 0) {
        Write-Section -Text 'WINDOWS ENDPOINTS' -Color DarkCyan
        foreach ($c in ($data.Windows | Sort-Object)) {
            Write-Host ("  [+] {0}" -f $c) -ForegroundColor Cyan
        }
    }

    # --- SECTION: Linux Nodes ---
    if ($data.Linux.Count -gt 0) {
        Write-Section -Text 'LINUX ENDPOINTS' -Color DarkRed
        foreach ($c in ($data.Linux | Sort-Object)) {
            Write-Host ("  [+] {0}" -f $c) -ForegroundColor Red
        }
    }

    # --- SECTION: Role Expansion ---
    Write-Section -Text 'SIMULATED DEPLOYMENT ACCOUNTS' -Color DarkGreen
    Write-Host ("  {0,-24} {1,-22} {2}" -f 'ACCOUNT NAME', 'FULL NAME', 'ROLE DESCRIPTION') -ForegroundColor DarkGreen
    foreach ($u in $data.AllUsers) {
        Write-Host ("  {0,-24} {1,-22} {2}" -f $u.Name, $u.FullName, $u.Description) -ForegroundColor Green
    }

    # --- SECTION: Deep Telemetry (-Full) ---
    if ($Full) {
        Write-Section -Text 'HOST TELEMETRY AUDIT' -Color Magenta

        if (-not [string]::IsNullOrWhiteSpace($nfsHome) -and -not [string]::IsNullOrWhiteSpace($sshKeyPath)) {
            $keyName = Split-Path $sshKeyPath -Leaf
            # Test-AndFixSshEnvironment -KeyPath $SshKeyPath -NfsHome $NfsHome -quiet
            if (-not (Initialize-Environment)) {
                Write-Warning "[!] -- Fix Environment"
                exit 1
            }
        }

        $computerData = Invoke-InformationCollector `
            -winComputers $data.Windows `
            -linComputers $data.Linux `
            -sshKeyPath $sshKeyPath

        if (Get-Command Format-HostCollector -ErrorAction SilentlyContinue) {
            $computerData | Format-HostCollector
        } else {
            $computerData | Format-Table -AutoSize
        }
    }

    Write-Host "`n"
}



function Set-MobileGpoPermission {
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
    $cleanGuid = if ($GpoID -match '^{[0-9a-fA-F-]+}$') { $GpoID 
    } else { "{$GpoID}" 
    }

    # Bind to GPO container in AD
    $rootDSE       = [ADSI]"LDAP://RootDSE"
    $namingContext = $rootDSE.defaultNamingContext
    $gpoPath       = "LDAP://CN=$cleanGuid,CN=Policies,CN=System,$namingContext"
    
    $gpoEntry = [System.DirectoryServices.DirectoryEntry]::new($gpoPath)
    if (-not $gpoEntry.Path) {
        Write-Error "Could not bind to GPO ($cleanGuid) in Active Directory."
        return
    }

    $secDesc      = $gpoEntry.ObjectSecurity
    $applyGpoGuid = [Guid]"edacfc86-b327-11d2-9701-00c04fd91ab0"

    if ($Force -and $Remove) {
        # Get only explicit Access Control Entries (exclude inherited container ACLs)
        $rules = $secDesc.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
        $removedCount = 0

        # Protected well-known administrative SIDs (Domain Admins, Enterprise Admins, SYSTEM, etc.)
        # Domain Admins ends in -512, Enterprise Admins in -519, Domain Controllers in -516
        $adminRids = @(512, 516, 519)

        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference.Value
            
            # Skip well-known built-in/service identities (NT AUTHORITY, SYSTEM, etc.)
            if ($sid -match '^S-1-5-(18|19|20|32-544)') {
                continue
            }

            # Check if this rule is a domain administrative group by RID
            $isProtectedAdmin = $false
            foreach ($rid in $adminRids) {
                if ($sid -match "-$rid$") {
                    $isProtectedAdmin = $true
                    break
                }
            }

            if ($isProtectedAdmin) {
                continue
            }

            # Target only GpoRead (GenericRead) or ExtendedRight (Apply Group Policy)
            $isReadOrApply = ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericRead) -or
            ($rule.ObjectType -eq $applyGpoGuid)

            if ($isReadOrApply) {
                $secDesc.RemoveAccessRuleSpecific($rule) | Out-Null
                $removedCount++
            }
        }

        $gpoEntry.CommitChanges()
        Write-Host "[+] Force removed $removedCount GpoRead / Apply ACEs from GPO ($cleanGuid)" -ForegroundColor Yellow
        return
    }

    $mobileData  = Get-MobileData -MobileName $MobileName -Config $cfg
    $targetUsers = if ($Add) { $mobileData.AllUsers 
    } else { $mobileData.MobileUsers 
    }

    foreach ($u in $targetUsers) {
        try {
            $account = [System.Security.Principal.NTAccount]::new($u.Name)
            $sid     = $account.Translate([System.Security.Principal.SecurityIdentifier])
        } catch {
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

        if ($Add) {
            $secDesc.AddAccessRule($ruleRead)
            $secDesc.AddAccessRule($ruleApply)
        } else {
            $secDesc.RemoveAccessRule($ruleRead)
            $secDesc.RemoveAccessRule($ruleApply)
        }
    }

    $gpoEntry.CommitChanges()

    $actionText = if ($Add) { "Added" 
    } else { "Removed" 
    }
    Write-Host "[+] $actionText users from '$MobileName' on GPO ($cleanGuid)" -ForegroundColor Green
}


function Format-DeploymentResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Results,

        [Parameter(Mandatory)]
        [array]$AllUsers
    )

    if (-not $Results) {
        Write-Warning "No deployment results returned."
        return
    }

    function Get-ShortHostName {
        param([string]$Name)

        if ([string]::IsNullOrWhiteSpace($Name)) {
            return '-'
        }

        return ($Name -split '\.')[0]
    }

    function Get-AggregateStatus {
        param(
            [Parameter(Mandatory)]
            $Result,

            [Parameter(Mandatory)]
            [string]$Category
        )

        $actions = @( $Result.Actions | Where-Object Category -eq $Category)

        if (-not $actions) { return '-' }

        if ($actions.Status -contains 'Failed') { return 'FAILED' }

        return 'OK'
    }

    #
    # USERS
    #
    $userRows = foreach ($result in $Results) {

        $host = Get-ShortHostName $result.HostName

        foreach ($baseName in ($AllUsers.BaseName | Sort-Object -Unique)) {

            $userDefs = @( $AllUsers | Where-Object BaseName -eq $baseName)

            #
            # Canonical roles come directly from the user model.
            #
            $roles = @( $userDefs | Select-Object -ExpandProperty GroupType -Unique | ForEach-Object { $_.ToString() })

            #
            # Determine the account names actually deployed
            # on this platform.
            #
            $accountNames = if ($result.Platform -eq 'Linux') { 
                @( $userDefs.LinuxName | Where-Object { $_ } | Sort-Object -Unique)
            } else {
                @( $userDefs.Name | Where-Object { $_ } | Sort-Object -Unique)
            }

            $accountActions = @( $result.Actions | Where-Object { $_.Category -eq 'User' -and $_.Name -in $accountNames }
            )

            #
            # We're intentionally collapsing Created/Existing
            # because deployment reporting only cares whether
            # the desired account state succeeded.
            #
            $status = if (-not $accountActions) {
                '-'
            } elseif ($accountActions.Status -contains 'Failed') { 'FAILED' } else { 'OK' }

            $password = if ($userDefs.MustChangePassword -contains $true) { 'Default' } else { 'UserSet' }

            [PSCustomObject]@{
                Host     = $host
                User     = $baseName
                Groups   = $roles -join ', '
                Status   = $status
                Password = $password
            }
        }
    }

    Write-Host ""
    Write-Host "[USERS]" -ForegroundColor Cyan

    $userRows | Sort-Object Host, User | Format-Table Host, User, Groups, Status, Password -AutoSize

    #
    # DEPLOYMENT TASKS
    #
    $taskRows = foreach ($result in $Results) {

        $host = Get-ShortHostName $result.HostName

        [PSCustomObject]@{
            Host = $host

            # Privileges = Get-AggregateStatus  -Result $result  -Category 'Privilege'
            NetworkSharing = Get-AggregateStatus -Result $result -Category 'NetworkSharing'

            ScheduledTasks = Get-AggregateStatus  -Result $result  -Category 'ScheduledTask'

            Encryption = Get-AggregateStatus  -Result $result  -Category 'DiskEncryption'

            DomainDisjoin = if ($result.Platform -eq 'Windows') {
                Get-AggregateStatus -Result $result -Category 'Domain'
            } else {
                'N/A'
            }

            PostDisjoin = if ($result.Platform -eq 'Windows') {
                Get-AggregateStatus  -Result $result  -Category 'PostDisjoin'
            } else {
                'N/A'
            }
        }
    }

    Write-Host ""
    Write-Host "[DEPLOYMENT TASKS]" -ForegroundColor Cyan

    $taskRows | Sort-Object Host | Format-Table `
        Host,
    NetworkSharing,
    ScheduledTasks,
    Encryption,
    DomainDisjoin,
    PostDisjoin `
        -AutoSize

    #
    # FAILURES
    #
    $failureRows = foreach ($result in $Results) {

        foreach ($failure in @($result.Failures)) {
            [PSCustomObject]@{
                Host    = Get-ShortHostName $result.HostName
                Failure = $failure
            }
        }
    }

    if ($failureRows) {
        Write-Host ""
        Write-Host "[FAILURES]" -ForegroundColor Red

        $failureRows | Format-Table Host, Failure -AutoSize
    }
}


function Start-MobileDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$MobileName,
        [Parameter()]
        [string]$sshKeyName    = $Script:Config.sshKeyName,
        [string]$sshKeyPath    = $Script:Config.SSHKeyPath,
        [string]$certName      = $Script:Config.certName,
        [string]$adminRoot     = $Script:Config.adminRoot,
        [string]$defaultPass   = $Script:Config.defaultPass,
        [string]$defaultPin    = $Script:Config.encryptionPin,
        [string]$oldEncryption = $Script:Config.curLuks,
        [string]$mobileDump    = $Script:Config.mobileDump,
        [string]$nfsHome       = $Script:Config.NfsHome
    )

    # $cfg = Get-MobileConfig $Config
    # Initialize-Functionality -sshKeyPath $sshKeyPath -nfsHome $nfsHome -adminRoot $adminRoot  -certName $certName
    Initialize-Environment
    $mobileData = Get-MobileData -MobileName $MobileName 
    $mobileData.AllUsers  = Get-UserCreds -MobileName $MobileName -AllUsers $mobileData.AllUsers -mobileDumpPath $mobileDump 
    $taskData = Get-TaskData -hasLinux:$($mobileData.Linux.Count -gt 0)
    $disJoin = $false

    $windowsPayload = [PSCustomObject]@{
        allUsers = @($mobileData.AllUsers)
        taskData = @($taskData)
        MobileName = $MobileName
        Disjoin = $disJoin
        Bitlocker = $defaultPin

    }

    $winErrors = [System.Collections.Generic.List[object]]::new()
    $rawWindows = Invoke-Command `
        -ComputerName $mobileData.Windows `
        -ScriptBlock $Script:WindowsDeployBlock `
        -ArgumentList $windowsPayload `
        -ErrorVariable winErrors `
        -ErrorAction SilentlyContinue


    $winResults = @(
        foreach ($r in $rawWindows) {
            [PSCustomObject]@{
                HostName = $r.PSComputerName
                Platform = 'Windows'
                Success  = [bool]$r.Success
                Actions  = @($r.Actions)
                Failures = @($r.Failures)
            }
        }
    )


    foreach ($computer in $mobileData.Windows) {
        $alreadyReturned = $winResults |
            Where-Object HostName -eq $computer

        if ($alreadyReturned) {
            continue
        }

        $hostErrors = @(
            $winErrors |
                Where-Object {
                    $_.TargetObject -eq $computer -or
                    $_.OriginInfo.PSComputerName -eq $computer
                }
        )

        $messages = if ($hostErrors) {
            @($hostErrors | ForEach-Object {
                    $_.Exception.Message
                })
        } else {
            @('No result returned from remote host.')
        }

        $winResults += [PSCustomObject]@{
            HostName = $computer
            Platform = 'Windows'
            Success  = $false
            Actions  = @()
            Failures = $messages
        }
    }

    # Need the linux computers and the linux computers there for easy processing
    # $mobileData.AllUsers | Out-File -Encoding UTF8 (Join-Path $cfg['netAppHome'] "${env:Username}/")
    
    $linRes = @()
    $linResults = @()
    if ($mobileData.Linux.Count -gt 0) {
        Write-Host "[-] Starting Linux Deployment"
        $linuxDeploy = Get-LinuxDeployScript -allUsers $mobileData.AllUsers
        $linRes = Invoke-Linux -Computers $mobileData.Linux -Script $linuxDeploy -KeyPath $sshKeyPath
    
        $linResults = foreach ($r in $linRes) {
            if ($r.ExitCode -eq 0 -and $r.StdOut) {
                try {
                    $r.StdOut | ConvertFrom-Json
                } catch {
                    [PSCustomObject]@{
                        HostName = $r.Target
                        Platform = 'Linux'
                        Success  = $false
                        Actions  = @()
                        Failures = @(
                            "Invalid JSON response: $($_.Exception.Message)"
                            "STDOUT: $($r.StdOut)"
                            "STDERR: $($r.StdErr)"
                        )
                    }
                }
            } else {
                [PSCustomObject]@{
                    HostName = $r.Target
                    Platform = 'Linux'
                    Success  = $false
                    Actions  = @()
                    Failures = @($r.StdErr)
                }
            }
        }


    }
    $results = @($winResults) + @($linResults)
    Format-DeploymentResults -results $results -allUsers $mobileData.AllUsers
}

function Get-WindowsCollector-DiskSpace {
    [CmdletBinding()]
    param()

    return @'
function Get-DiskSpace {
    param([int]$MinimumFreeGB = 20, [int]$MinimumFreePercent = 10)

    $volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3' -ErrorAction Stop | ForEach-Object {
        $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($_.Size / 1GB, 2)
        $freePercent = if ($_.Size -gt 0) { [math]::Round(100 * $_.FreeSpace / $_.Size, 1) } else { 0 }

        [PSCustomObject]@{
            Drive       = $_.DeviceID
            TotalGB     = $totalGB
            FreeGB      = $freeGB
            FreePercent = $freePercent
            LowSpace    = ($freeGB -lt $MinimumFreeGB -or $freePercent -lt $MinimumFreePercent)
        }
    })

    return [PSCustomObject]@{
        Volumes = $volumes
        LowSpace = @($volumes | Where-Object LowSpace).Count -gt 0
    }
}
'@

}

function Get-WindowsCollector-Ivanti {
    [CmdletBinding()]
    param()

    return @'
function Get-IvantiInformation {
    $paths = @(
        'HKLM:\SOFTWARE\LANDesk\ManagementSuite\WinClient'
        'HKLM:\SOFTWARE\WOW6432Node\LANDesk\ManagementSuite\WinClient'
        'HKLM:\SOFTWARE\Wow6432Node\LANDesk\Inventory'
        'HKLM:\SOFTWARE\Ivanti\Endpoint Manager'
    )

    $registrations = @(foreach ($path in $paths) {
        $item = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($item) {
            [PSCustomObject]@{
                Path    = $path
                Version = $item.Version
            }
        }
    })

    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
        $_.Name -match '^(?:LANDesk|Ivanti)' -or $_.DisplayName -match 'Ivanti|LANDesk'
    } | Select-Object Name, DisplayName, State, StartMode)

    $version = @($registrations | Where-Object Version | Select-Object -First 1 -ExpandProperty Version)
    $automatic = @($services | Where-Object StartMode -eq 'Auto')
    $stopped = @($automatic | Where-Object State -ne 'Running')

    [PSCustomObject]@{
        Installed              = ($registrations.Count -gt 0 -or $services.Count -gt 0)
        Version                = if ($version.Count) { $version[0] } else { $null }
        Services               = $services
        AutomaticServicesReady = if (-not $services.Count) { $null } else { $stopped.Count -eq 0 }
        PolicyStatus           = $null
        LastPolicySync         = $null
        LastSecurityScan       = $null
        Registrations          = $registrations
    }
}
'@
}

function Get-WindowsCollector-SecurityUpdates {
    [CmdletBinding()]
    param()

    return @'
function Get-SecurityUpdateInformation {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $count = $searcher.GetTotalHistoryCount()

    $history = if ($count -gt 0) {
        @($searcher.QueryHistory(0, [math]::Min($count, 100)) |
            Where-Object { $_.ResultCode -eq 2 -and $_.Title -match 'Security|Cumulative|KB\d+' } |
            Select-Object Title, Date, ResultCode)
    } else {
        @()
    }

    $hotfixes = @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending |
        Select-Object HotFixID, Description, InstalledOn)

    [PSCustomObject]@{
        LastRelevantUpdate = $history | Sort-Object Date -Descending | Select-Object -First 1
        UpdateHistory = $history
        InstalledHotfixes = $hotfixes
        IvantiPatchCompliance = 'Unknown'
    }
}
'@
}


function Get-WindowsInformationBlock {
    [CmdletBinding()]
    param()

    $parts = [System.Collections.Generic.List[string]]::new()

    # 1. Inject Child Functions
    $parts.Add((Get-WindowsCollector-DiskSpace))
    $parts.Add((Get-WindowsCollector-Ivanti))
    $parts.Add((Get-WindowsCollector-SecurityUpdates))

    # 2. Add System Baseline & Aggregator Script
    $parts.Add(@'
# OS Build to Friendly Name Mapping
$osInfo = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'
$kernelString = "$($osInfo.LCUVer)"

function Get-WinVersion {
    param([int]$buildNumber)
    $map = @{
        2600  = "WINXP";    3790  = "WINXP64"; 6002  = "WINVISTA"; 7601  = "WIN7"
        9200  = "WIN8";     9600  = "WIN8.1";  10240 = "WIN10-1507"; 10586 = "WIN10-1511"
        14393 = "WIN10-1607"; 15063 = "WIN10-1703"; 16299 = "WIN10-1709"; 17134 = "WIN10-1803"
        17763 = "WIN10-1809"; 18362 = "WIN10-1903"; 18363 = "WIN10-1909"; 19041 = "WIN10-2004"
        19042 = "WIN10-20H2"; 19043 = "WIN10-21H1"; 19044 = "WIN10-21H2"; 19045 = "WIN10-22H2"
        22000 = "WIN11-21H2"; 22621 = "WIN11-22H2"; 22631 = "WIN11-23H2"; 26100 = "WIN11-24H2"
        26200 = "WIN11-25H2"; 28000 = "WIN11-26H1"; 26300 = "WIN11-26H2"
    }
    if ($map.ContainsKey($buildNumber)) { "$($map[$buildNumber])-$buildNumber" } else { "WIN-UNK-$buildNumber" }
}

$osString = Get-WinVersion ([int]$osInfo.CurrentBuildNumber)
$cores = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property NumberOfCores -Sum).Sum

# Software Inventory
$packages = @(
    Get-ItemProperty @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    ) -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName -Unique
)

# Symantec AV Definitions
$symantecAvDefs = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Storages\Definitions\VirusDefs' -ErrorAction SilentlyContinue).DefSetVersion

# LAPS Scheduled Task Check
$adminRotateScriptVersion = $null
if (Get-ScheduledTask -TaskName 'ADMIN-LAPS' -ErrorAction SilentlyContinue) {
    $xml = schtasks /query /tn ADMIN-LAPS /xml 2>$null
    $versionMatch = ($xml | Select-String -Pattern '<Version>(.*?)</Version>').Matches
    if ($versionMatch.Count) {
        $adminRotateScriptVersion = $versionMatch[0].Groups[1].Value
    } else {
        $adminRotateScriptVersion = "Present"
    }
}

# License Activation Check
$activation = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" -ErrorAction SilentlyContinue |
    Where-Object PartialProductKey |
    Select-Object -First 1 -ExpandProperty LicenseStatus

$licenseStatusMap = @{
    0 = 'Unlicensed'; 1 = 'Licensed'; 2 = 'OOB Grace'; 3 = 'OOT Grace'
    4 = 'Non-Genuine Grace'; 5 = 'Notification'; 6 = 'Extended Grace'
}
$activationStatus = if ($null -ne $activation) { $licenseStatusMap[[int]$activation] } else { 'Unknown' }

# Execute Modular Collectors
$diskInfo    = Get-DiskSpace
$ivantiInfo  = Get-IvantiInformation
$updateInfo  = Get-SecurityUpdateInformation

$systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
$systemDisk  = $diskInfo.Volumes | Where-Object Drive -eq $systemDrive | Select-Object -First 1

[PSCustomObject]@{
    HostName = $env:COMPUTERNAME
    Platform = $osString

    Summary = [PSCustomObject]@{
        Kernel              = $kernelString
        Cores               = $cores
        PackageCount        = $packages.Count
        AdminRotateVersion  = $adminRotateScriptVersion
        AVDefs              = $symantecAvDefs
        IvantiVersion       = $ivantiInfo.Version
        IvantiServicesReady = $ivantiInfo.AutomaticServicesReady
        License             = $activationStatus
        LastUpdate          = $updateInfo.LastUpdate
        DiskFreeGB          = $systemDisk.FreeGB
        DiskLow             = $diskInfo.LowSpace
    }

    Details = [PSCustomObject]@{
        Packages = $packages
        Updates  = $updateInfo.UpdateHistory
        Disks    = $diskInfo.Volumes
        Ivanti   = $ivantiInfo
    }
}
'@)

    return [scriptblock]::Create($parts -join "`n`n")
}


function Get-LinuxCollector-DiskSpace {
    [CmdletBinding()]
    param()

    return @'
# Task: Disk Space

disk_paths=('/')

if [[ -d /mobiles/home ]]; then
    disk_paths+=('/mobiles/home')
fi

disk_json="$(
    df -Pk "${disk_paths[@]}" 2>/dev/null |
        awk 'NR > 1 && !seen[$1]++ {
            printf "%s|%s|%s|%s\n", $1, $2, $4, $6
        }' |
        jq -R -s '
            split("\n") |
            map(select(length > 0) | split("|") | {
                Device: .[0],
                TotalGB: ((.[1] | tonumber) / 1048576 * 100 | round / 100),
                FreeGB: ((.[2] | tonumber) / 1048576 * 100 | round / 100),
                MountPoint: .[3],
                FreePercent: (if (.[1] | tonumber) > 0 then
                    ((.[2] | tonumber) / (.[1] | tonumber) * 1000 | round / 10)
                else 0 end)
            })
        '
)"
'@
}


function Get-LinuxInformationScript {
    [CmdletBinding()]
    param()

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add('#!/usr/bin/env bash')
    $parts.Add((Get-LinuxCollector-DiskSpace))

    $parts.Add(@'
hostname_value="$(hostname -s)"
cores_value="$(nproc)"
os=$(. /etc/os-release && echo "${ID^^}-${VERSION_ID}")
kernel_value="$(uname -r)"

clamav_value="$(clamscan -V 2>/dev/null | awk -F'/' '{print $NF}' | xargs -I{} date -d "{}" +'%d/%m/%Y' 2>/dev/null)"

last_update_value="$(
    (yum history list 2>/dev/null || dnf history list 2>/dev/null) |
        awk -F'|' '
            tolower($0) ~ /(update|upgrade)/ {
                gsub(/^[ \t]+|[ \t]+$/, "", $0)
                print
                exit
            }
        '
)"

laps_path="$(find /etc/systemd -iname '*laps*' -type f 2>/dev/null | head -n 1)"
laps_version=$([[ -n "$laps_path" ]] && echo "Present" || echo "")

# Filter RPM packages installed after system baseline cutoff
base_epoch=$(rpm -q --qf '%{INSTALLTIME}' basesystem 2>/dev/null || rpm -q --qf '%{INSTALLTIME}' setup 2>/dev/null)
cutoff=$(( ${base_epoch:-0} + 1800 ))

packages_json="$(
    rpm -qa --qf '%{INSTALLTIME}|%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n' 2>/dev/null |
    awk -F'|' -v cutoff="$cutoff" '$1 > cutoff { print $2 "|" $3 "|" $4 }' |
    jq -R -s '
        split("\n") | map(select(length > 0)) | map(
            split("|") | {Name: .[0], Version: .[1], Arch: .[2]}
        )
    '
)"
package_count="$(jq 'length' <<< "$packages_json")"

jq -n \
    --arg hostname "$hostname_value" \
    --arg os "$os" \
    --arg kernel "$kernel_value" \
    --argjson cores "$cores_value" \
    --argjson packageCount "$package_count" \
    --arg laps "$laps_version" \
    --arg avDefs "$clamav_value" \
    --arg lastUpdate "$last_update_value" \
    --argjson packages "$packages_json" \
    --argjson disks "$disk_json" \
'
{
    HostName: $hostname,
    Platform: $os,

    Summary: {
        Kernel: $kernel,
        Cores: $cores,
        PackageCount: $packageCount,
        AdminRotateVersion: $laps,
        AVDefs: $avDefs,
        IvantiVersion: null,
        IvantiServicesReady: null,
        License: null,
        LastUpdate: $lastUpdate,
        DiskFreeGB: ($disks | map(select(.MountPoint == "/")) | first | .FreeGB),
        DiskLow: ($disks | any(.LowSpace == true))
    },

    Details: {
        Packages: $packages,
        Updates: [],
        Disks: $disks,
        Ivanti: null
    }
}
'
'@)

    return $parts -join "`n`n"
}

# =====================================================================
# Main Multi-Platform Remote Orchestrator
# =====================================================================

function Invoke-InformationCollector {
    [CmdletBinding()]
    param(
        [Parameter()][array]$winComputers,
        [Parameter()][array]$linComputers,
        [Parameter()][string]$sshKeyPath
    )

    $winResult = @()
    $linResult = @()

    # --- Windows Node Processing ---
    if (@($winComputers).Count -gt 0) {
        $winFails = [System.Collections.Generic.List[object]]::new()
        $winScriptBlock = Get-WindowsInformationBlock

        $rawWindows = Invoke-Command `
            -ComputerName $winComputers `
            -ScriptBlock $winScriptBlock `
            -ErrorAction SilentlyContinue `
            -ErrorVariable winFails

        $winResult = @(
            foreach ($r in $rawWindows) {
                [PSCustomObject]@{
                    HostName = $r.HostName
                    Platform = $r.Platform
                    Success  = $true
                    Summary  = $r.Summary
                    Details  = $r.Details
                    Failures = @()
                }
            }
        )

        foreach ($computer in $winComputers) {
            if ($winResult.HostName -contains $computer) { continue }

            $hostErrors = @($winFails | Where-Object { $_.TargetObject -eq $computer -or $_.OriginInfo.PSComputerName -eq $computer })
            $winResult += [PSCustomObject]@{
                HostName = $computer
                Platform = 'Windows'
                Success  = $false
                Summary  = $null
                Details  = $null
                Failures = if ($hostErrors) { @($hostErrors.Exception.Message) } else { @('No result returned from remote host.') }
            }
        }
    }

    # --- Linux Node Processing ---
    if (@($linComputers).Count -gt 0) {
        $bashScript = Get-LinuxInformationScript

        $rawLinux = Invoke-Linux `
            -Computers $linComputers `
            -Script $bashScript `
            -KeyPath $sshKeyPath

        $linResult = @(
            foreach ($r in $rawLinux) {
                if ($r.ExitCode -ne 0) {
                    [PSCustomObject]@{
                        HostName = $r.Target
                        Platform = 'Linux'
                        Success  = $false
                        Summary  = $null
                        Details  = $null
                        Failures = @(if ($r.StdErr) { $r.StdErr } else { "SSH exited with code $($r.ExitCode)" })
                    }
                    continue
                }

                try {
                    $p = $r.StdOut | ConvertFrom-Json
                    [PSCustomObject]@{
                        HostName = $p.HostName
                        Platform = $p.Platform
                        Success  = $true
                        Summary  = $p.Summary
                        Details  = $p.Details
                        Failures = @()
                    }
                } catch {
                    [PSCustomObject]@{
                        HostName = $r.Target
                        Platform = 'Linux'
                        Success  = $false
                        Summary  = $null
                        Details  = $null
                        Failures = @("Invalid JSON response: $($_.Exception.Message)")
                    }
                }
            }
        )
    }

    return @($winResult) + @($linResult)
}


function Invoke-InformationCollectorOld {
    [CmdletBinding()]
    param([Parameter()][array]$winComputers, [array]$linComputers, [string]$sshKeyPath)

    $bashScript = @'
#!/usr/bin/env bash

hostname_value="$(hostname -s)"
cores_value="$(nproc)"
os=$(. /etc/os-release && echo "${ID^^}-${VERSION_ID}")
kernel_value="$(uname -r)"

clamav_value="$(clamscan -V 2>/dev/null | awk -F'/' '{print $NF}' | xargs -I{} date -d "{}" +'%d/%m/%Y')"

last_update_value="$(
    (yum history list 2>/dev/null || dnf history list 2>/dev/null) |
        awk -F'|' '
            tolower($0) ~ /(update|upgrade)/ {
                gsub(/^[ \t]+|[ \t]+$/, "", $0)
                print
                exit
            }
        '
)"

laps_path="$(
    find /etc/systemd \
        -iname '*laps*' \
        -type f \
        2>/dev/null |
        head -n 1
)"

#
# Eventually replace this with actual version extraction
# if your LAPS unit/script contains one.
#
if [[ -n "$laps_path" ]]; then
    laps_version="Present"
else
    laps_version=""
fi

#
# RHEL-family package inventory.
#
# packages_json="$(
#     rpm -qa \
#         --qf '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n' \
#         2>/dev/null |
#     jq -R -s '
#         split("\n") | map(select(length > 0)) | map(
#             split("|") | {Name: .[0], Version: .[1], Arch: .[2]}
#         )
#     '
# )"
packages_json="$(
    # 1. Grab initial OS baseline epoch from basesystem (or setup), add 30m buffer
    base_epoch=$(rpm -q --qf '%{INSTALLTIME}' basesystem 2>/dev/null || rpm -q --qf '%{INSTALLTIME}' setup 2>/dev/null)
    cutoff=$(( ${base_epoch:-0} + 1800 ))

    # 2. Query RPMs, filter by timestamp, and shape to JSON
    rpm -qa --qf '%{INSTALLTIME}|%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n' 2>/dev/null |
    awk -F'|' -v cutoff="$cutoff" '$1 > cutoff { print $2 "|" $3 "|" $4 }' |
    jq -R -s '
        split("\n") | map(select(length > 0)) | map(
            split("|") | {Name: .[0], Version: .[1], Arch: .[2]}
        )
    '
)"

package_count="$(
    jq 'length' <<< "$packages_json"
)"

jq -n \
    --arg hostname "$hostname_value" \
    --arg os "$os" \
    --arg kernel "$kernel_value" \
    --argjson cores "$cores_value" \
    --argjson packageCount "$package_count" \
    --arg laps "$laps_version" \
    --arg avDefs "$clamav_value" \
    --arg lastUpdate "$last_update_value" \
    --argjson packages "$packages_json" \
'
{
    HostName: $hostname,
    Platform: $os,

    Summary: {
        Kernel: $kernel,
        Cores: $cores,
        PackageCount: $packageCount,
        AdminRotateVersion: $laps,
        AVDefs: $avDefs,
        IvantiVersion: null,
        License: null,
        LastUpdate: $lastUpdate
    },

    Details: {
        Packages: $packages,
        Updates: []
    }
}
'
'@

    $windowsInformationBlock = {

        # $os = Get-CimInstance Win32_OperatingSystem
        $osInfo = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'
        $KernelString = "$($osInfo.LCUVer)"
        function Get-WinVersion {
            param($buildNumber)

            $map = @{
                2600  = "WINXP"
                3790  = "WINXP64"
                6002  = "WINVISTA"
                7601  = "WIN7"
                9200  = "WIN8"
                9600  = "WIN8.1"

                10240 = "WIN10-1507"
                10586 = "WIN10-1511"
                14393 = "WIN10-1607"
                15063 = "WIN10-1703"
                16299 = "WIN10-1709"
                17134 = "WIN10-1803"
                17763 = "WIN10-1809"
                18362 = "WIN10-1903"
                18363 = "WIN10-1909"
                19041 = "WIN10-2004"
                19042 = "WIN10-20H2"
                19043 = "WIN10-21H1"
                19044 = "WIN10-21H2"
                19045 = "WIN10-22H2"

                22000 = "WIN11-21H2"
                22621 = "WIN11-22H2"
                22631 = "WIN11-23H2"
                26100 = "WIN11-24H2"
                26200 = "WIN11-25H2"
                28000 = "WIN11-26H1"
                26300 = "WIN11-26H2"
            }

            if ($map.ContainsKey($buildNumber)) {
                "$($map[$buildNumber])-$buildNumber"
            } else {
                "WIN-UNK-$buildNumber"
            }
        }
        $osString = "$(Get-WinVersion ([int]$osInfo.currentBuildNumber))"

        $cores = ( Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum

        $packages = @(
            Get-ItemProperty @(
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            ) -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
                Select-Object `
                    DisplayName,
                DisplayVersion,
                Publisher,
                InstallDate |
                Sort-Object DisplayName -Unique
        )

        $ivantiVersion = (
            Get-ItemProperty -Path @(
                'HKLM:\SOFTWARE\LANDesk\ManagementSuite\WinClient'
                'HKLM:\SOFTWARE\WOW6432Node\LANDesk\ManagementSuite\WinClient'
                'HKLM:\SOFTWARE\Wow6432Node\LANDesk\Inventory'
                'HKLM:\SOFTWARE\Ivanti\Endpoint Manager'
            ) -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty Version -ErrorAction SilentlyContinue
        )

        $symantecAvDefs = ( Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Storages\Definitions\VirusDefs' -ErrorAction SilentlyContinue).DefSetVersion

        $adminRotateScriptVersion = $null

        $adminScriptExists = Get-ScheduledTask  -TaskName 'ADMIN-LAPS'  -ErrorAction SilentlyContinue

        if ($adminScriptExists) {
            $xml = schtasks /query /tn ADMIN-LAPS /xml

            $versionMatch = ( $xml | Select-String -Pattern '<Version>(.*?)</Version>').Matches

            if ($versionMatch.Count) {
                $adminRotateScriptVersion =
                $versionMatch[0].Groups[1].Value
            }
        }

        $activation = Get-CimInstance `
            -ClassName SoftwareLicensingProduct `
            -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" `
            -ErrorAction SilentlyContinue |
            Where-Object PartialProductKey |
            Select-Object -First 1 -ExpandProperty LicenseStatus

        $licenseStatusMap = @{
            0 = 'Unlicensed'
            1 = 'Licensed'
            2 = 'OOB Grace'
            3 = 'OOT Grace'
            4 = 'Non-Genuine Grace'
            5 = 'Notification'
            6 = 'Extended Grace'
        }

        $activationStatus = if ($null -ne $activation) {
            $licenseStatusMap[[int]$activation]
        } else {
            'Unknown'
        }

        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()

        $latestUpdates = @(
            $searcher.QueryHistory(0, 10) |
                Select-Object `
                    Title,
                Date,
                @{
                    Name = 'Status'
                    Expression = {
                        switch ($_.ResultCode) {
                            2 { 'Succeeded' }
                            3 { 'Succeeded With Errors' }
                            4 { 'Failed' }
                            5 { 'Aborted' }
                            default { "Other: $($_.ResultCode)" }
                        }
                    }
                }
        )

        $lastUpdate = $latestUpdates | Where-Object Status -like 'Succeeded*' | Sort-Object Date -Descending | Select-Object -First 1 -ExpandProperty Date

        [PSCustomObject]@{
            HostName = $env:COMPUTERNAME
            Platform = $osString

            Summary = [PSCustomObject]@{
                Kernel             = $KernelString
                Cores              = $cores
                PackageCount       = $packages.Count
                AdminRotateVersion = $adminRotateScriptVersion
                AVDefs             = $symantecAvDefs
                IvantiVersion      = $ivantiVersion
                License            = $activationStatus
                LastUpdate         = $lastUpdate
            }

            Details = [PSCustomObject]@{
                Packages = $packages
                Updates  = $latestUpdates
            }
        }
    }
    $winResult = @()
    $linResult = @()

    if (@($winComputers).Count -gt 0) {
        $winFails = [System.Collections.Generic.List[object]]::new()

        $rawWindows = Invoke-Command `
            -ComputerName $winComputers `
            -ScriptBlock $windowsInformationBlock `
            -ErrorAction SilentlyContinue `
            -ErrorVariable winFails

        $winResult = @(
            foreach ($r in $rawWindows) {
                [PSCustomObject]@{
                    HostName = $r.HostName
                    Platform = $r.Platform
                    Success  = $true
                    Summary  = $r.Summary
                    Details  = $r.Details
                    Failures = @()
                }
            }
        )

        foreach ($computer in $winComputers) {
            if ($winResult.HostName -contains $computer) {
                continue
            }

            $hostErrors = @( $winFails | Where-Object { $_.TargetObject -eq $computer -or $_.OriginInfo.PSComputerName -eq $computer }
            )

            $winResult += [PSCustomObject]@{
                HostName = $computer
                Platform = 'Windows'
                Success  = $false
                Summary  = $null
                Details  = $null
                Failures = if ($hostErrors) {
                    @($hostErrors.Exception.Message)
                } else {
                    @('No result returned from remote host.')
                }
            }
        }
    }

    if (@($linComputers).Count -gt 0) {
        $rawLinux = Invoke-Linux `
            -Computers $linComputers `
            -Script $bashScript `
            -KeyPath $sshKeyPath

        $linResult = @(
            foreach ($r in $rawLinux) {
                if ($r.ExitCode -ne 0) {
                    [PSCustomObject]@{
                        HostName = $r.Target
                        Platform = 'Linux'
                        Success  = $false
                        Summary  = $null
                        Details  = $null
                        Failures = @(
                            if ($r.StdErr) {
                                $r.StdErr
                            } else {
                                "SSH exited with code $($r.ExitCode)"
                            }
                        )
                    }

                    continue
                }

                try {
                    $p = $r.StdOut | ConvertFrom-Json

                    [PSCustomObject]@{
                        HostName = $p.HostName
                        Platform = $p.Platform
                        Success  = $true
                        Summary  = $p.Summary
                        Details  = $p.Details
                        Failures = @()
                    }
                } catch {
                    [PSCustomObject]@{
                        HostName = $r.Target
                        Platform = 'Linux'
                        Success  = $false
                        Summary  = $null
                        Details  = $null
                        Failures = @(
                            "Invalid JSON response: $($_.Exception.Message)"
                        )
                    }
                }
            }
        )
    }

    return @($winResult) + @($linResult)
}


function Show-TerminalMultiPicker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string[]]$Options
    )

    $esc = [char]27
    $selectedIndices = [System.Collections.Generic.HashSet[int]]::new()
    $currentIndex = 0
    $total = $Options.Count

    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
    Write-Host "[Up/Down] Navigate | [Space] Toggle | [A] All | [C] Clear | [Enter] Confirm" -ForegroundColor DarkGray

    # Pre-allocate buffer lines
    1..$total | ForEach-Object { [Console]::WriteLine("") }

    [Console]::CursorVisible = $false

    try {
        while ($true) {
            [Console]::Write("$esc[${total}A")

            for ($i = 0; $i -lt $total; $i++) {
                $isChecked = if ($selectedIndices.Contains($i)) { "[*]" 
                } else { "[ ]" 
                }
                $pointer   = if ($i -eq $currentIndex) { " > " 
                } else { "   " 
                }

                [Console]::Write("$esc[2K`r")

                if ($i -eq $currentIndex) {
                    Write-Host "$pointer$isChecked $($Options[$i])" -ForegroundColor Black -BackgroundColor White
                } elseif ($selectedIndices.Contains($i)) {
                    Write-Host "$pointer$isChecked $($Options[$i])" -ForegroundColor Green
                } else {
                    Write-Host "$pointer$isChecked $($Options[$i])" -ForegroundColor Gray
                }
            }

            $key = [Console]::ReadKey($true)

            switch ($key.Key) {
                'UpArrow' {
                    $currentIndex = ($currentIndex - 1 + $total) % $total
                }
                'DownArrow' {
                    $currentIndex = ($currentIndex + 1) % $total
                }
                'Spacebar' {
                    if ($selectedIndices.Contains($currentIndex)) {
                        [void]$selectedIndices.Remove($currentIndex)
                    } else {
                        [void]$selectedIndices.Add($currentIndex)
                    }
                }
                'A' {
                    0..($total - 1) | ForEach-Object { [void]$selectedIndices.Add($_) }
                }
                'C' {
                    $selectedIndices.Clear()
                }
                'Enter' {
                    # Wipe interactive menu
                    [Console]::Write("$esc[${total}A")
                    for ($i = 0; $i -lt $total; $i++) {
                        [Console]::Write("$esc[2K`r`n")
                    }
                    [Console]::Write("$esc[${total}A$esc[2K`r")

                    $picked = @($selectedIndices | Sort-Object | ForEach-Object { $Options[$_] })
                    $summary = if ($picked.Count -gt 0) { $picked -join ';' 
                    } else { "(none)" 
                    }
                    Write-Host "Selected Groups: $summary" -ForegroundColor Green
                    return $picked
                }
            }
        }
    } finally {
        [Console]::CursorVisible = $true
    }
}

function Show-TerminalSinglePicker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][array]$Options,
        [Parameter(Mandatory = $true)][string]$DisplayProperty
    )

    $esc = [char]27
    $currentIndex = 0
    $total = $Options.Count

    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
    Write-Host "[Up/Down] Navigate | [Enter] Select Match" -ForegroundColor DarkGray

    # Pre-allocate buffer lines
    1..$total | ForEach-Object { [Console]::WriteLine("") }

    [Console]::CursorVisible = $false

    try {
        while ($true) {
            [Console]::Write("$esc[${total}A")

            for ($i = 0; $i -lt $total; $i++) {
                $pointer = if ($i -eq $currentIndex) { " > " 
                } else { "   " 
                }
                $label   = $Options[$i].$DisplayProperty

                [Console]::Write("$esc[2K`r")

                if ($i -eq $currentIndex) {
                    Write-Host "$pointer$label" -ForegroundColor Black -BackgroundColor White
                } else {
                    Write-Host "$pointer$label" -ForegroundColor Gray
                }
            }

            $key = [Console]::ReadKey($true)

            switch ($key.Key) {
                'UpArrow' {
                    $currentIndex = ($currentIndex - 1 + $total) % $total
                }
                'DownArrow' {
                    $currentIndex = ($currentIndex + 1) % $total
                }
                'Enter' {
                    # Wipe interactive menu
                    [Console]::Write("$esc[${total}A")
                    for ($i = 0; $i -lt $total; $i++) {
                        [Console]::Write("$esc[2K`r`n")
                    }
                    [Console]::Write("$esc[${total}A$esc[2K`r")

                    $choice = $Options[$currentIndex]
                    Write-Host "Resolved Match: $($choice.$DisplayProperty)" -ForegroundColor Green
                    return $choice
                }
            }
        }
    } finally {
        [Console]::CursorVisible = $true
    }
}

function Find-ADComputerMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SearchTerm
    )

    $searcher = [System.DirectoryServices.DirectorySearcher]::new()
    $cleanTerm = [System.Security.SecurityElement]::Escape($SearchTerm.Trim())
    $searcher.Filter = "(&(objectCategory=computer)(|(name=$cleanTerm)(sAMAccountName=$cleanTerm*)(name=*$cleanTerm*)))"
    $searcher.PropertiesToLoad.AddRange(@('name', 'dNSHostName', 'operatingSystem'))

    $results = @($searcher.FindAll())
    $pMatches = foreach ($res in $results) {
        $props = $res.Properties
        [PSCustomObject]@{
            Name            = if ($props.Contains('name')) { $props['name'][0] 
            } else { '' 
            }
            DnsHostName     = if ($props.Contains('dnshostname')) { $props['dnshostname'][0] 
            } else { '' 
            }
            OperatingSystem = if ($props.Contains('operatingsystem')) { $props['operatingsystem'][0] 
            } else { '' 
            }
            DisplayText     = "$($props['name'][0]) ($($props['operatingsystem'][0]))"
        }
    }

    return $pMatches
}

function Find-ADUserMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SearchTerm
    )

    $searcher = [System.DirectoryServices.DirectorySearcher]::new()
    $cleanTerm = [System.Security.SecurityElement]::Escape($SearchTerm.Trim())
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$cleanTerm)(sAMAccountName=*$cleanTerm*)(displayName=*$cleanTerm*)(mail=*$cleanTerm*)))"
    $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'displayName', 'givenName', 'sn', 'mail'))

    $results = @($searcher.FindAll())
    $pMatches = foreach ($res in $results) {
        $props = $res.Properties
        $first = if ($props.Contains('givenName')) { $props['givenName'][0] 
        } else { '' 
        }
        $last  = if ($props.Contains('sn')) { $props['sn'][0] 
        } else { '' 
        }
        $combined = "$first $last".Trim()

        $resolvedName = if ($props.Contains('displayName') -and -not [string]::IsNullOrWhiteSpace($props['displayName'][0])) {
            $props['displayName'][0]
        } elseif (-not [string]::IsNullOrWhiteSpace($combined)) {
            $combined
        } else {
            ''
        }

        $sam = if ($props.Contains('samaccountname')) { $props['samaccountname'][0] 
        } else { '' 
        }

        [PSCustomObject]@{
            UserName    = $sam
            FullName    = $resolvedName
            Email       = if ($props.Contains('mail')) { $props['mail'][0] 
            } else { '' 
            }
            DisplayText = "$sam - $resolvedName"
        }
    }

    return $pMatches
}

function New-MobileDeployment {
    [CmdletBinding()]
    param(
        [string]$mobilePath = $Script:Config.MobileEntries

    )
    $mobileName = Read-Host -Prompt "Enter a Mobile Name"
    if ([string]::IsNullOrWhiteSpace($mobileName)) {
        Write-Warning "Mobile Name cannot be empty."
        return
    }

    # Available group tags for terminal multi-select
    
    $availableGroups = $script:GroupMetadata.Keys | Where-Object {$Script:GroupMetadata[$_].Selectable} | ForEach-Object { $_.ToString() }

    # Computer Entry & Disambiguation
    $ResolveComputerInput = {
        param([string]$PlatformLabel)
        
        $collected = [System.Collections.Generic.List[string]]::new()
        Write-Host "`n=== Enter $PlatformLabel Computers ===" -ForegroundColor Cyan
        
        do {
            $raw = (Read-Host -Prompt "Enter $PlatformLabel host name (Enter to finish)").Trim()
            if ([string]::IsNullOrWhiteSpace($raw)) { break 
            }

            $pMatches = @(Find-ADComputerMatch -SearchTerm $raw)

            # 1. Exact match
            $exact = $pMatches | Where-Object { $_.Name -ieq $raw }
            if ($exact) {
                Write-Host "Found AD Computer: $($exact.Name)" -ForegroundColor Green
                $collected.Add($exact.Name)
                continue
            }

            # 2. Ambiguous match -> Terminal single-select picker
            if ($pMatches.Count -gt 1) {
                $picked = Show-TerminalSinglePicker `
                    -Title "Multiple $PlatformLabel AD Matches for '$raw'" `
                    -Options $pMatches `
                    -DisplayProperty "DisplayText"
                
                if ($picked) {
                    $collected.Add($picked.Name)
                    continue
                }
            } elseif ($pMatches.Count -eq 1) {
                $confirmMatch = Read-Host -Prompt "Did you mean '$($matches[0].Name)'? (y/n)"
                if ($confirmMatch -match '^(y|yes)$') {
                    $collected.Add($pMatches[0].Name)
                    continue
                }
            }

            # 3. Not found in AD -> Manual confirmation
            Write-Warning "Host '$raw' was not found in Active Directory."
            $confirm = Read-Host -Prompt "Add '$raw' as unjoined $PlatformLabel host? (y/n)"
            if ($confirm -match '^(y|yes)$') {
                $collected.Add($raw.ToUpper())
            } else {
                Write-Host "Skipping '$raw'." -ForegroundColor Yellow
            }

        } while ($true)

        return $collected.ToArray()
    }

    # Collect Computers
    $windowsComputers = & $ResolveComputerInput -PlatformLabel "Windows"
    $linuxComputers   = & $ResolveComputerInput -PlatformLabel "Linux"

    # Collect Users
    $users = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "`n=== Enter Users ===" -ForegroundColor Cyan

    do {
        $rawUser = (Read-Host -Prompt "Enter username/search term (Enter to finish)").Trim()
        if ([string]::IsNullOrWhiteSpace($rawUser)) { break 
        }

        $resolvedUsername = $rawUser
        $resolvedFullName = ''
        $isDomainUser = $false

        $userMatches = @(Find-ADUserMatch -SearchTerm $rawUser)

        # 1. Exact match
        $exactUser = $userMatches | Where-Object { $_.UserName -ieq $rawUser }
        if ($exactUser) {
            $resolvedUsername = $exactUser.UserName
            $resolvedFullName = $exactUser.FullName
            $isDomainUser = $true
            Write-Host "Found AD User: $resolvedFullName ($resolvedUsername)" -ForegroundColor Green
        }
        # 2. Ambiguous matches -> Terminal single-select picker
        elseif ($userMatches.Count -gt 1) {
            $pickedUser = Show-TerminalSinglePicker `
                -Title "Multiple User Matches for '$rawUser'" `
                -Options $userMatches `
                -DisplayProperty "DisplayText"

            if ($pickedUser) {
                $resolvedUsername = $pickedUser.UserName
                $resolvedFullName = $pickedUser.FullName
                $isDomainUser = $true
            }
        }
        # 3. Single partial match
        elseif ($userMatches.Count -eq 1) {
            $confirmCandidate = Read-Host -Prompt "Did you mean '$($userMatches[0].FullName)' ($($userMatches[0].UserName))? (y/n)"
            if ($confirmCandidate -match '^(y|yes)$') {
                $resolvedUsername = $userMatches[0].UserName
                $resolvedFullName = $userMatches[0].FullName
                $isDomainUser = $true
            }
        }

        # 4. Non-domain fallback
        if (-not $isDomainUser) {
            Write-Warning "User '$rawUser' was not found in Active Directory."
            $confirmNonDomain = Read-Host -Prompt "Add '$rawUser' as a non-domain user? (y/n)"
            if ($confirmNonDomain -notmatch '^(y|yes)$') {
                Write-Host "Skipping '$rawUser'." -ForegroundColor Yellow
                continue
            }
            $manualFull = Read-Host -Prompt "Enter Full Name for '$rawUser' (leave blank if none)"
            $resolvedFullName = if (-not [string]::IsNullOrWhiteSpace($manualFull)) { $manualFull.Trim() 
            } else { '' 
            }
        }

        # Terminal Multi-Select Checklist for Groups
        $pickedGroups = Show-TerminalMultiPicker `
            -Title "Select Group Tags for '$resolvedUsername' ($resolvedFullName) (local is always made)" `
            -Options $availableGroups


        $groupString = $pickedGroups -join ';'

        $users.Add([PSCustomObject]@{
                username = $resolvedUsername
                groups   = $groupString
                fullname = $resolvedFullName
            })

    } while ($true)

    $mobile = [PSCustomObject]@{ 
        MobileName = $mobileName
        WindowsComputers = $windowsComputers
        LinuxComputers = $linuxComputers
        Users = $users.ToArray()

    }
    # Output Structured Deployment Object
    Write-MobileFile  -NewMobile  $mobile -mobilesPath $mobilePath
}


function Write-MobileFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$newMobile,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$mobilesPath   = $script:Config.MobileEntries
    )

    Write-Host $Script:Config.Keys
    Write-Host $newMobile.MobileName
    Write-Host $mobilesPath
    $outPath = Join-Path $Script:Config.MobileEntries $newMobile.MobileName
    Write-Host "[+] Mobile getting written to $outpath"
    $lines = [System.Collections.Generic.List[string]]::new()

    # [windows]
    $lines.Add('[windows]')
    foreach ($c in $newMobile.WindowsComputers) {
        if (-not [string]::IsNullOrWhiteSpace($c)) {
            $lines.Add($c)
        }
    }

    # [linux]
    $lines.Add('[linux]')
    foreach ($c in $newMobile.LinuxComputers) {
        if (-not [string]::IsNullOrWhiteSpace($c)) {
            $lines.Add($c)
        }
    }

    # [users]
    $lines.Add('[users]')
    $lines.Add('username,groups,fullname')
    foreach ($u in $newMobile.Users) {
        $lines.Add("$($u.username),$($u.groups),$($u.fullname)")
    }

    # Write out without BOM issues or extra blank lines
    [System.IO.File]::WriteAllLines($outPath, $lines)
}


function New-LinuxUnregisterTask-LogService {
    [CmdletBinding()]
    param()

    return @'
# Task: Remove Log Rotation Service

mobile_units=(
    'mobile-logrotate.timer'
    'mobile-logrotate.service'
)

unitFailure=false

for unit in "${mobile_units[@]}"; do

    unitPath="/etc/systemd/system/$unit"

    #
    # Already absent satisfies desired state.
    #
    if [[ ! -e "$unitPath" ]]; then
        continue
    fi

    dzdo systemctl disable --now "$unit" &>/dev/null

    if dzdo rm -f "$unitPath" &>/dev/null; then
        :
    else
        unitFailure=true
        record_failure "Scheduled task '$unit': failed to remove unit file"
    fi
done

if dzdo systemctl daemon-reload &>/dev/null; then
    :
else
    unitFailure=true
    record_failure 'Systemd: daemon-reload failed'
fi

if [[ "$unitFailure" == false ]]; then
    record_action 'ScheduledTask' 'mobile-logrotate' 'Success'
else
    record_action 'ScheduledTask' 'mobile-logrotate' 'Failed'
fi
'@
}

function New-LinuxUnregisterTask-Users {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Users,

        [bool]$Archive = $true,

        [string]$HomeBase = '/mobiles/home',

        [string]$ArchiveRoot = '/mobiles/archive'
    )

    $blocks = [System.Collections.Generic.List[string]]::new()

    $archiveValue = $Archive.ToString().ToLowerInvariant()

    $blocks.Add(@"
archive=$archiveValue
mobileHome='$HomeBase'
archiveRoot='$ArchiveRoot'

monthYear=`$(date '+%m-%Y')
timeStamp=`$(date '+%Y%m%d')
archivePath="`$archiveRoot/`$monthYear"

if [[ "`$archive" == true ]]; then
    if dzdo mkdir -p "`$archivePath" &>/dev/null; then
        record_action 'ArchiveDirectory' "`$archivePath" 'Success'
    else
        record_action 'ArchiveDirectory' "`$archivePath" 'Failed'
        record_failure "Archive directory '`$archivePath': failed to create"
    fi
fi
"@)

    foreach ($u in $Users) {
        $name = $u.LinuxName

        $blocks.Add(@"
# Task: Remove User: $name

username='$name'
homePath="`$mobileHome/`$username"
canRemove=true

#
# Archive the profile first, if requested.
#
if [[ "`$archive" == true && -d "`$homePath" ]]; then
    archiveFile="`$archivePath/`$username-`$timeStamp.tar.gz"

    if dzdo tar -czf "`$archiveFile" -C "`$(dirname "`$homePath")" "`$(basename "`$homePath")" &>/dev/null; then
        record_action 'ProfileArchive' "`$username" 'Success'
    else
        record_action 'ProfileArchive' "`$username" 'Failed'
        record_failure "Profile archive '`$username': failed"
        canRemove=false
    fi
fi

#
# Remove the account.
#
if id "`$username" &>/dev/null; then
    if [[ "`$canRemove" == true ]]; then
        if dzdo userdel -r "`$username" &>/dev/null; then
            record_action 'UserRemoval' "`$username" 'Success'
        else
            record_action 'UserRemoval' "`$username" 'Failed'
            record_failure "User removal '`$username': failed"
        fi
    fi
else
    record_action 'UserRemoval' "`$username" 'Success'

    #
    # userdel can't clean an orphaned home.
    #
    if [[ -d "`$homePath" && "`$canRemove" == true ]]; then
        if dzdo rm -rf -- "`$homePath" &>/dev/null; then
            record_action 'ProfileRemoval' "`$username" 'Success'
        else
            record_action 'ProfileRemoval' "`$username" 'Failed'
            record_failure "Profile removal '`$username': failed"
        fi
    fi
fi
"@)
    }

    return ($blocks -join "`n`n")
}

function Get-LinuxUnregisterScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$AllUsers,

        [bool]$Archive = $true,

        [switch]$SkipLogrotate
    )

    #
    # Resolve canonical Linux account for each user.
    #
    $linuxUsers = foreach ($group in ($AllUsers | Group-Object BaseName)) {
        $group.Group |
            Where-Object { $null -ne $_.LinuxAccountType } |
            Sort-Object {
                $script:GroupMetadata[$_.GroupType].LinuxPriority
            } -Descending |
            Select-Object -First 1
    }

    $header = @'
#!/usr/bin/env bash
set -o pipefail

declare -a actions_json=()
declare -a failures=()

record_action() {
    local category="$1"
    local name="$2"
    local status="$3"
    local details="${4:-}"

    actions_json+=( "$(jq -cn \
        --arg cat "$category" \
        --arg name "$name" \
        --arg stat "$status" \
        --arg det "$details" \
        '{
            Category: $cat,
            Name: $name,
            Status: $stat,
            Details: (if $det == "" then null else $det end)
        }')" )
}

record_failure() {
    failures+=("$1")
}

array_to_json() {
    if (( $# == 0 )); then
        printf '[]'
    else
        printf '%s\n' "$@" | jq -R . | jq -s .
    fi
}
'@

    $tasks = [System.Collections.Generic.List[string]]::new()
    $tasks.Add($header)

    if ($linuxUsers) {
        $tasks.Add(
            (New-LinuxUnregisterTask-Users `
                -Users $linuxUsers `
                -Archive $Archive)
        )
    }

    if (-not $SkipLogrotate) {
        $tasks.Add(
            (New-LinuxUnregisterTask-LogService)
        )
    }

    $footer = @'
# --- Result Serialization ---

final_actions="[$(IFS=,; echo "${actions_json[*]}")]"
final_failures="$(array_to_json "${failures[@]}")"

jq -n \
    --arg hostname "$(hostname -s)" \
    --argjson success "$([[ ${#failures[@]} -eq 0 ]] && echo true || echo false)" \
    --argjson actions "$final_actions" \
    --argjson failures "$final_failures" \
    '{
        HostName: $hostname,
        Platform: "Linux",
        Success: $success,
        Actions: $actions,
        Failures: $failures
    }'
'@

    $tasks.Add($footer)

    return ($tasks -join "`n`n")
}

function Unregister-Deployment {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$MobileName,
        [Parameter()]
        [string]$sshKeyName = $Script:Config.sshKeyName,
        [string]$sshKeyPath = $Script:Config.SSHKeyPath,
        [string]$certName = $Script:Config.certName,
        [string]$adminRoot = $Script:Config.adminRoot,
        [string]$defaultPass = $Script:Config.defaultPass, 
        [string]$defaultPin = $Script:Config.encryptionPin,
        [string]$oldEncryption = $Script:Config.curLuks,
        [string]$mobileDump = $Script:Config.mobileDump,
        [bool]$archive = $false
    )
    $mobileData = Get-MobileData -MobileName $MobileName 
    $taskData = Get-TaskData -hasLinux:$($mobileData.Linux.Length -gt 0)
    $winErrors = [System.Collections.Generic.List[object]]::new()

    $winResults = @()
    $linResults = @()

    if (@($mobileData.Windows).Count -gt 0) {
        $winErrors = [System.Collections.Generic.List[object]]::new()
        
        $payload = [PSCustomObject]@{
            MobileName = $MobileName
            TaskData = $taskData
            Archive =  $archive
            AllUsers = $mobileData.AllUsers
            Bitlocker = $oldEncryption
        }
        Write-Host $payload

        $rawWindows = Invoke-Command `
            -ComputerName $mobileData.Windows `
            -ScriptBlock $script:WindowsUnregisterBlock `
            -ArgumentList $payload `
            -ErrorAction SilentlyContinue `
            -ErrorVariable winErrors

        $winResults = @(
            foreach ($r in $rawWindows) {
                [PSCustomObject]@{
                    HostName = $r.PSComputerName
                    Platform = 'Windows'
                    Success  = [bool]$r.Success
                    Actions  = @($r.Actions)
                    Failures = @($r.Failures)
                }
            }
        )

        foreach ($computer in $mobileData.Windows) {
            $alreadyReturned = $winResults |
                Where-Object HostName -eq $computer

            if ($alreadyReturned) {
                continue
            }

            $hostErrors = @(
                $winErrors |
                    Where-Object {
                        $_.TargetObject -eq $computer -or
                        $_.OriginInfo.PSComputerName -eq $computer
                    }
            )

            $messages = if ($hostErrors) {
                @(
                    $hostErrors |
                        ForEach-Object { $_.Exception.Message }
                )
            } else {
                @('No result returned from remote host.')
            }

            $winResults += [PSCustomObject]@{
                HostName = $computer
                Platform = 'Windows'
                Success  = $false
                Actions  = @()
                Failures = $messages
            }
        }
    }

    if (@($mobileData.Linux).Count -gt 0) {
        $linuxUnregister = Get-LinuxUnregisterScript `
            -AllUsers $mobileData.AllUsers `
            -Archive:$archive

        $rawLinux = Invoke-Linux `
            -Computers $mobileData.Linux `
            -Script $linuxUnregister `
            -KeyPath $sshKeyPath

        $linResults = @(
            foreach ($r in $rawLinux) {
                if ($r.ExitCode -eq 0 -and $r.StdOut) {
                    try {
                        $r.StdOut | ConvertFrom-Json
                    } catch {
                        [PSCustomObject]@{
                            HostName = $r.Target
                            Platform = 'Linux'
                            Success  = $false
                            Actions  = @()
                            Failures = @(
                                "Invalid JSON response: $($_.Exception.Message)"
                            )
                        }
                    }
                } else {
                    [PSCustomObject]@{
                        HostName = $r.Target
                        Platform = 'Linux'
                        Success  = $false
                        Actions  = @()
                        Failures = @(
                            if ($r.StdErr) {
                                $r.StdErr
                            } else {
                                "SSH exited with code $($r.ExitCode)"
                            }
                        )
                    }
                }
            }
        )
    }

    Format-DeploymentResults (@($winResults) + @($linResults)) -AllUsers $mobileData.AllUsers


}





$bashScript = @'
#!/usr/bin/env bash
collect_hostname()   { printf "hostname\t%s\n" "$(hostname)"; }
collect_cores()      { printf "cores\t%s\n"    "$(nproc)"; }
collect_kernel()     { printf "kernel\t%s\n"   "$(uname -r)"; }
collect_clamAVDefs() { printf "ClamAV\t%s\n" "$(clamscan --version | awk -F'/' '{print $NF}')"; }
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
