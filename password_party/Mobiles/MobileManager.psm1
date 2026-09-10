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

        $existing = Get-LocalUser `
            -Name $u.Name `
            -ErrorAction SilentlyContinue

        if ($existing) {
            Add-Action `
                -Category 'User' `
                -Name $u.Name `
                -Status 'Existed'
        } else {
            $uParams = @{
                Name        = $u.Name
                FullName    = $u.FullName
                Password    = $u.Password
                Description = $u.Description
                ErrorAction = 'Stop'
            }

            if (
                Invoke-Step `
                    -Context "User '$($u.Name)'" `
                    -Action {
                    New-LocalUser @uParams
                }
            ) {
                Add-Action `
                    -Category 'User' `
                    -Name $u.Name `
                    -Status 'Created'
            } else {
                Add-Action `
                    -Category 'User' `
                    -Name $u.Name `
                    -Status 'Failed'
            }
        }

        #
        # Password expiration
        #
        if ($u.MustChangePassword) {

            $success = Invoke-Step `
                -Context "Password expiry '$($u.Name)'" `
                -Action {
                $adsiUser = [ADSI]"WinNT://./$($u.Name),user"
                $adsiUser.PasswordExpired = 1
                $adsiUser.SetInfo()
            }

            Add-Action `
                -Category 'PasswordExpiry' `
                -Name $u.Name `
                -Status $(if ($success) { 'Changed' 
                } else { 'Failed' 
                })
        }

        #
        # Groups
        #
        foreach ($g in $u.WindowsGroups) {

            $alreadyMember = $false

            try {
                $alreadyMember = [bool](
                    Get-LocalGroupMember `
                        -Group $g `
                        -Member $u.Name `
                        -ErrorAction Stop
                )
            } catch {
                # Absence is expected here.
            }

            if ($alreadyMember) {
                Add-Action `
                    -Category 'Privilege' `
                    -Name "$($u.Name):$g" `
                    -Status 'Existing'

                continue
            }

            $success = Invoke-Step `
                -Context "Group '$g' for '$($u.Name)'" `
                -Action {
                Add-LocalGroupMember `
                    -Group $g `
                    -Member $u.Name `
                    -ErrorAction Stop
            }

            Add-Action `
                -Category 'Privilege' `
                -Name "$($u.Name):$g" `
                -Status $(if ($success) { 'Changed' 
                } else { 'Failed' 
                })
        }
    }

    #
    # Scheduled tasks
    #
    foreach ($t in $payload.TaskData) {

        $success = Invoke-Step `
            -Context "Scheduled task '$($t.TaskName)'" `
            -Action {
            Register-ScheduledTask `
                -TaskName $t.TaskName `
                -Xml $t.TaskXML `
                -User System `
                -Force `
                -ErrorAction Stop
        }

        Add-Action `
            -Category 'ScheduledTask' `
            -Name $t.TaskName `
            -Status $(if ($success) { 'Changed' 
            } else { 'Failed' 
            })
    }

    #
    # BitLocker
    #
    $drives = @(
        Get-BitLockerVolume |
            Where-Object VolumeType -eq 'OperatingSystem'
    )

    $tpm = Get-Tpm

    foreach ($drive in $drives) {

        $bitLockerParams = @{
            MountPoint  = $drive.MountPoint
            ErrorAction = 'Stop'
        }

        if ($tpm.IsPresent -and $tpm.IsEnabled) {
            $bitLockerParams.TpmAndPinProtector = $true
            $bitLockerParams.Pin = ConvertTo-SecureString `
                -String $payload.Bitlocker `
                -AsPlainText `
                -Force
        } else {
            $bitLockerParams.PasswordProtector = $true
            $bitLockerParams.Password = ConvertTo-SecureString `
                -String $payload.Bitlocker `
                -AsPlainText `
                -Force
        }

        $success = Invoke-Step `
            -Context "BitLocker '$($drive.MountPoint)'" `
            -Action {
            Enable-BitLocker @bitLockerParams
        }

        Add-Action `
            -Category 'DiskEncryption' `
            -Name $drive.MountPoint `
            -Status $(if ($success) { 'Changed' 
            } else { 'Failed' 
            })
    }

    #
    # Domain
    #
    if ($payload.DisJoin) {

        $success = Invoke-Step `
            -Context 'Domain Disjoin' `
            -Action {
            Remove-Computer `
                -WorkGroupName $payload.MobileName `
                -Force `
                -Restart:$false `
                -ErrorAction Stop
        }

        Add-Action `
            -Category 'Domain' `
            -Name 'Disjoin' `
            -Status $(if ($success) { 'Changed' 
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
    param([PsCustomObject]$payload)

    $timeStamp   = (Get-Date).ToString('yyyyMMdd')
    $monthYear   = (Get-Date).ToString('MM-yyyy')
    $archivePath = "C:\Mobiles\Archive\$monthYear"

    $actions  = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()

    # Generic step wrapper ensuring uniform action logging and failure capture
    function Invoke-Step {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][scriptblock]$ScriptBlock,
            [string]$Context = ""
        )

        try {
            $result = & $ScriptBlock
            if ($null -ne $result) {
                $actions.Add([PSCustomObject]@{
                        Name    = $Name
                        Status  = if ($result.Status)  { $result.Status 
                        } else { 'Changed' 
                        }
                        Details = if ($result.Details) { @($result.Details) 
                        } else { @($result) 
                        }
                    })
            }
            return $true
        } catch {
            $label = if ($Context) { "$Name [$Context]" 
            } else { $Name 
            }
            $failures.Add("${label}: $($_.Exception.Message)")
            return $false
        }
    }

    # 1. Archive Directory Setup
    if ($payload.archive) {
        Invoke-Step -Name 'ArchiveDirectory' -Context $archivePath -ScriptBlock {
            if (-not (Test-Path $archivePath)) {
                New-Item -ItemType Directory -Force -Path $archivePath -ErrorAction Stop | Out-Null
                return @{ Status = 'Changed'; Details = "Created archive directory '$archivePath'" }
            }
            return @{ Status = 'Ok'; Details = "Archive directory exists '$archivePath'" }
        } | Out-Null
    }

    # 2. User Cleanup Pipeline (Archive -> Profile Removal -> Account Removal)
    $removedUsers  = [System.Collections.Generic.List[string]]::new()
    $missingUsers  = [System.Collections.Generic.List[string]]::new()
    $archivedFiles = [System.Collections.Generic.List[string]]::new()

    foreach ($u in $payload.AllUsers) {
        $profilePath = "C:\Users\$($u.Name)"
        $localUser   = Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue
        $sid         = if ($localUser) { $localUser.SID.Value 
        } else { $null 
        }

        # Step 2a: Archive profile if enabled
        if ($archive -and (Test-Path $profilePath)) {
            $archiveFile = Join-Path $archivePath "$($u.Name)-$timeStamp.zip"
            $archiveOk   = Invoke-Step -Name 'ArchiveProfile' -Context $u.Name -ScriptBlock {
                Compress-Archive `
                    -Path $profilePath `
                    -DestinationPath $archiveFile `
                    -CompressionLevel Optimal `
                    -Force `
                    -ErrorAction Stop

                $archivedFiles.Add($archiveFile)
                return $null # Aggregated at the end
            }

            # If archive failed, skip removal to avoid data loss
            if (-not $archiveOk) { continue 
            }
        }

        # Step 2b: Remove Profile (CIM + Directory)
        $profileOk = Invoke-Step -Name 'ProfileRemoval' -Context $u.Name -ScriptBlock {
            $profileObject = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
                Where-Object {
                    ($sid -and $_.SID -eq $sid) -or $_.LocalPath -ieq $profilePath
                }

            if ($profileObject) {
                $profileObject | Remove-CimInstance -ErrorAction Stop
            }

            if (Test-Path $profilePath) {
                Remove-Item -Path $profilePath -Force -Recurse -ErrorAction Stop
            }
            return $null
        }

        # Preserve local account if profile removal failed
        if (-not $profileOk) { continue 
        }

        # Step 2c: Remove Local User Account
        if ($localUser) {
            Invoke-Step -Name 'UserRemoval' -Context $u.Name -ScriptBlock {
                Remove-LocalUser -Name $u.Name -ErrorAction Stop
                $removedUsers.Add($u.Name)
                return $null
            } | Out-Null
        } else {
            $missingUsers.Add($u.Name)
        }
    }

    # Aggregate User Actions
    if ($archivedFiles.Count) {
        $actions.Add([PSCustomObject]@{
                Name    = 'ProfilesArchived'
                Status  = 'Changed'
                Details = $archivedFiles.ToArray()
            })
    }

    if ($removedUsers.Count) {
        $actions.Add([PSCustomObject]@{
                Name    = 'UsersRemoved'
                Status  = 'Changed'
                Details = $removedUsers.ToArray()
            })
    }

    if ($missingUsers.Count) {
        $actions.Add([PSCustomObject]@{
                Name    = 'UsersAbsent'
                Status  = 'Ok'
                Details = $missingUsers.ToArray()
            })
    }

    # 3. Scheduled Tasks Cleanup
    $tasksRemoved = [System.Collections.Generic.List[string]]::new()
    $tasksMissing = [System.Collections.Generic.List[string]]::new()

    foreach ($t in $payload.TaskData) {
        $existingTask = Get-ScheduledTask -TaskName $t.TaskName -ErrorAction SilentlyContinue

        if (-not $existingTask) {
            $tasksMissing.Add($t.TaskName)
            continue
        }

        Invoke-Step -Name 'ScheduledTaskRemoval' -Context $t.TaskName -ScriptBlock {
            Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false -ErrorAction Stop
            $tasksRemoved.Add($t.TaskName)
            return $null
        } | Out-Null
    }

    if ($tasksRemoved.Count) {
        $actions.Add([PSCustomObject]@{
                Name    = 'ScheduledTasks'
                Status  = 'Changed'
                Details = $tasksRemoved.ToArray()
            })
    }

    if ($tasksMissing.Count) {
        $actions.Add([PSCustomObject]@{
                Name    = 'TasksAbsent'
                Status  = 'Ok'
                Details = $tasksMissing.ToArray()
            })
    }

    # 4. Re-enable BitLocker via TPM
    Invoke-Step -Name 'BitLockerProtector' -ScriptBlock {
        $tpm = Get-Tpm -ErrorAction Stop

        if ($tpm.TpmPresent -and $tpm.TpmEnabled) {
            Enable-BitLocker -MountPoint 'C:' -TpmProtector -ErrorAction Stop | Out-Null
            return @{
                Status  = 'Changed'
                Details = @('Restored TPM-only unlock')
            }
        }

        return @{
            Status  = 'Ok'
            Details = @('TPM unavailable or disabled')
        }
    } | Out-Null

    # Result Contract
    [PSCustomObject]@{
        Platform = 'Windows'
        Success  = ($failures.Count -eq 0)
        Actions  = $actions.ToArray()
        Failures = $failures.ToArray()
    }
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
    $encoded = if (-not ([string]::IsNullOrWhiteSpace())) { "-Encoded $(ConvertTo-Base64 $ToEncode)"
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



function New-LogonGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$targetOUFriendlyName
    )

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $ScriptName = "logon.ps1"

    # PowerShell payload
    $ScriptBody = @'
$LogFile = "$env:TEMP\ad_ps_logon.log"
$TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
"[$TimeStamp] Executed PowerShell logon script for $env:USERNAME on $env:COMPUTERNAME" | Out-File -FilePath $LogFile -Append
New-Item -Type File -Force -Path C:\Temp\RanLogonScript
'@

    $gpoName = "Mobile Logon Script"
    $RootDSE = [ADSI]"LDAP://RootDSE"
    $ctx = $RootDSE.DefaultNamingContext
    $PolicyContainer = "CN=Policies,CN=System,$ctx"
    $gpoID = "{00000000-7E5A-C0DE-7E5A-000000000000}" # Ensure standard uppercase hex
    $targetOU_DN = "OU=$targetOUFriendlyName,$ctx"
    $gpoLdapPath = "[LDAP://CN=$gpoID,$PolicyContainer;0]"
    $userVersion = 65536

    # PowerShell Scripts CSE GUID
    # [{Scripts-CSE}{Legacy-Tool-GUID}][{Scripts-CSE}{PowerShell-Tool-GUID}]
    # $PsCseGuid = "[{42B5FAAE-6536-11D2-A45A-0000F87571E3}{40B66649-4972-11D1-A7CA-00AA00A72F28}][{42B5FAAE-6536-11D2-A45A-0000F87571E3}{40B66650-4972-11D1-A7CA-00AA00A72F28}]"
    # $PsCSEGuid = "[{42B5FAAE-6536-11D2-A45A-0000F87571E3}{40B66649-4972-11D1-A7CA-00AA00A72F28}][{40B66650-4972-11D1-A7CA-00AA00A72F28}{42B5FAAE-6536-11D2-A45A-0000F87571E3}]"
    $PSCSEGuid = "[{42B5FAAE-6536-11D2-A45A-0000F87571E3}{40B66649-4972-11D1-A7CA-00AA00A72F28}][{40B66650-4972-11D1-A7CA-00AA00A72F28}{42B5FAAE-6536-11D2-A45A-0000F87571E3}][{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]"
    $gpoPath = "\\$domain\sysvol\$domain\policies\$gpoID"

    # 1. Check or Create GPC object cleanly
    $gpoLdapUri = "LDAP://CN=$gpoID,$PolicyContainer"
    if ([System.DirectoryServices.DirectoryEntry]::Exists($gpoLdapUri)) {
        $newGPO = [ADSI]$gpoLdapUri
    } else {
        $polEntry = [ADSI]"LDAP://$PolicyContainer"
        $newGPO = $polEntry.Create("groupPolicyContainer", "CN=$gpoID")
    }

    $newGPO.Put("displayName", $gpoName)
    $newGPO.Put("flags", 2)
    $newGPO.Put("gPCFileSysPath", $gpoPath)
    $newGPO.Put("gPCUserExtensionNames", $PsCseGuid)
    $newGPO.Put("versionNumber", $userVersion)
    $newGPO.SetInfo()

    # 2. Build SYSVOL Directory Structure
    $logonPath = Join-Path $gpoPath "User\Scripts\Logon"
    New-Item -Path $logonPath -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $gpoPath "Machine\Scripts") -ItemType Directory -Force | Out-Null

    # 3. Write Configuration Files
    $gptIniContent = @"
[General]
Version=$userVersion
displayName=$gpoName
"@
    Set-Content -Path (Join-Path $gpoPath "gpt.ini") -Value $gptIniContent -Encoding Ascii

    $PsScriptsIniContent = @"

[ScriptsConfig]
StartExecutePSFirst=true
[Logon]
0CmdLine=$ScriptName
0Parameters=-ExecutionPolicy Bypass -WindowStyle Hidden
"@
    $ScriptsIniContent = @"

[Logon]
"@
    # Note: -Encoding Unicode is required for Group Policy parsing
    $utf16 = New-Object System.Text.UnicodeEncoding($false,$true)
    [System.IO.File]::WriteAllText((Join-Path $gpoPath "User\Scripts\scripts.ini"),$ScriptsIniContent, $utf16)
    [System.IO.File]::WriteAllText((Join-Path $gpoPath "User\Scripts\psscripts.ini"),$PsScriptsIniContent, $utf16)
    # Set-Content -Path (Join-Path $gpoPath "User\Scripts\scripts.ini") -Value $ScriptsIniContent -Encoding Unicode
    # Set-Content -Path (Join-Path $gpoPath "User\Scripts\psscripts.ini") -Value $PsScriptsIniContent -Encoding Unicode
    Set-Content -Path (Join-Path $logonPath $ScriptName) -Value $ScriptBody -Encoding UTF8

    # 4. Link GPO to target OU (Safe attribute access)
    $targetOU = [ADSI]"LDAP://$targetOU_DN"
    if (-not [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$targetOU_DN")) {
        throw "Target OU '$targetOU_DN' does not exist."
    }

    $existingLinks = $targetOU.Properties['gPLink'].Value
    if ($existingLinks) {
        if ($existingLinks -notlike "*$gpoID*") {
            $targetOU.Properties['gPLink'].Value = "$gpoLdapPath$existingLinks"
        }
    } else {
        $targetOU.Properties['gPLink'].Value = $gpoLdapPath
    }

    if (-not $targetOU.Properties['gPOptions'].Value) {
        $targetOU.Properties['gPOptions'].Value = 0
    }

    $targetOU.SetInfo()
    Write-Host "[+] Successfully created and linked GPO $gpoID to $targetOUFriendlyName" -ForegroundColor Green
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



function Initialize-Ssh-Environment {
    [CmdletBinding()]
    param(
        [string]$keyPath = $Script:Config.SSHKeyPath,
        [string]$nfsHome = $Script:Config.NfsHome
    )
    # r = remote ; l = local
    $nfsSSH = Join-Path  $nfsHome '.ssh'
    $localSSh = Join-Path $env:UserProfile ".ssh"
    $rAuthorized = Join-Path $nfsSSH 'authorized_keys'

    @($nfsSSH, $localSSH) | Where-Object { -not (Test-Path $_ ) } | ForEach-Object {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($keyPath) -or $keyPath.EndsWith('\')) {
        throw "SSH KEY PATH IS INVALID! -- '$sshKeyPath'  -- CHECK SSH KEY"
    }

    
    icacls.exe $nfsSSH /inheritance:r /T |Out-Null
    icacls.exe $nfsSSH /grant:r "$($env:USERNAME):(R)" /T |out-null


    icacls.exe $localSSH /inheritance:r |Out-Null
    icacls.exe $localSSH /grant:r "$($env:USERNAME):(R)" /T | Out-Null

    if (-not (Test-Path $keyPath)) {
        ssh-keygen -f "$keyPath" -C '""' -N '""' -t ecdsa -q

    }

    icacls.exe $keyPath /inheritance:r |Out-Null
    icacls.exe $keyPath /grant:r "$($env:USERNAME):(R)"| Out-Null
    $pubKey = ssh-keygen -yf $keyPath
    if (-not (Test-Path $rAuthorized)) { New-Item -Type File -Path $rAuthorized -Force | Out-Null
    }
    if (-not (Select-String -Pattern $pubKey -Path $rAuthorized -ErrorAction SIlentlyContinue)) {
        $pubKey | Add-Content -Encoding UTF8 -Path $rAuthorized
        icacls.exe $rAuthorized /inheritance:r |Out-Null
        icacls.exe $rAuthorized /grant:r "$($env:USERNAME):(R)"| Out-Null
    }


}

function Initialize-Functionality {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$sshKeyPath = $script:Config.SshKeyPath,
        [string]$nfsHome = $script:Config.nfsHome,
        [string]$adminRoot = $script:Config.AdminRoot,
        [string]$certName = $script:Config.certName

    )

    Initialize-Ssh-Environment  -nfsHome $nfsHome -keyPath $sshKeyPath

    # 2. Ensure Document Encryption Certificate Exists in CurrentUser\My
    $existingCert = Get-ChildItem -Path Cert:\CurrentUser\My | 
        Where-Object { $_.Subject -like '*CN=MobileDeployer*' -or $_.Subject -like "*$($certName)*" }

    if (-not $existingCert) {
        $pfxFileName = "$($certName).pfx"
        $pfxFullPath = Join-Path $cfg.AdminRoot $pfxFileName
        # $securePass  = ConvertTo-SecureString -AsPlainText -Force $cfg.DefaultPass
        $securePass = Read-Host -AsSecureString -Prompt "[!] The decryption certificate isn't in your cert store. Please enter the administrative password to import it "

        if (Test-Path $pfxFullPath) {
            Import-PfxCertificate -FilePath $pfxFullPath -CertStoreLocation Cert:\CurrentUser\My -Password $securePass | Out-Null
            Write-Host "[+] Imported existing deployer certificate from: $pfxFullPath" -ForegroundColor Green
        } else {
            # Generates PFX/CER in the target directory and automatically adds to Cert:\CurrentUser\My
            New-DeployerCertificate -certPass $securePass -outPath $pfxFullPath
            Write-Host "[+] Generated and installed new deployment certificate in: $($pfxFullPath)" -ForegroundColor Green
        }
    }
}

function Get-PostDeployScript {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$userRights,
        [switch]$Sharing,
        [switch]$hasLinux,

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
    if ($userRights) {
        if ($sharing -and $hasLinux) {
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

    if ($Sharing) {
        if ($null -ne  $driveLetters) {
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

    $s.Add(@'
icacls.exe C:\Support /inheritance:r /T /Q
icacls.exe C:\Support /grant Administrators:F ISSO:F /T /Q

'@)

    $s.Add('"[ Post Deployment Ran - $(Get-Date)]" | Out-File C:\Post-Deploy.info ')
    return ($s -join "`n`n")
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



function Get-LinuxDeployScript {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$allUsers
    )

    $scriptArray = [System.Collections.Generic.List[string]]::new()

    #
    # Static header
    #
    $scriptArray.Add(@'
#!/usr/bin/env bash

mHome='/mobiles/home'

declare -a created_users=()
declare -a existing_users=()
declare -a failed_users=()

declare -a wheel_users=()
declare -a failed_wheel_users=()

declare -a expired_users=()
declare -a failed_expiry_users=()

declare -a luks_updated=()
declare -a failed_luks=()

declare -a systemd_timers=()
declare -a failed_timers=()

declare -a failures=()

array_to_json() {
    if [[ $# -eq 0 ]]; then
        echo '[]'
    else
        printf '%s\n' "$@" | jq -R . | jq -s .
    fi
}

#
# Mobile home
#
if ! dzdo mkdir -p "$mHome" &>/dev/null; then
    failures+=("Mobile home: failed to create $mHome")
fi

#
# Logrotate timer/service
#
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
ExecStart=/path-to-logrotate

[Install]
WantedBy=multi-user.target
EOF

dzdo systemctl daemon-reload &>/dev/null

if dzdo systemctl enable --now mobile-logrotate.timer &>/dev/null; then
    systemd_timers+=("mobile-logrotate.timer")
else
    failed_timers+=("mobile-logrotate.timer")
    failures+=("Scheduled task 'mobile-logrotate.timer': failed to enable")
fi

#
# Locate LUKS devices
#
mapfile -t luks_devices < <(
    lsblk -rno NAME,FSTYPE 2>/dev/null |
        awk '$2 == "crypto_LUKS" {print $1}'
)

for dev in "${luks_devices[@]}"; do
'@)

    #
    # LUKS credentials
    #
    $scriptArray.Add(@"
    if printf "%s\n%s\n"  "$($script:Config.curLuks)"  "$($script:Config.encryptionPin)" | dzdo cryptsetup luksAddKey  --force  --batch-mode  "$dev" &>/dev/null
    then
        luks_updated+=("`$dev")
    else
        failed_luks+=("`$dev")
        failures+=("Disk encryption '`$dev': failed to add LUKS key")
    fi
done
"@)

    #
    # Pick one Linux deployment representation per base user
    #
    $linuxUsers = foreach ($group in ($allUsers | Group-Object BaseName)) {
        $group.Group |
            Where-Object { $null -ne $_.LinuxAccountType } |
            Sort-Object {
                $script:GroupMetadata[$_.GroupType].LinuxPriority
            } -Descending |
            Select-Object -First 1
    }

    #
    # User provisioning
    #
    foreach ($u in $linuxUsers) {
        $isWheel = $u.LinuxAccountType -eq [LinuxAccountType]::Wheel

        $scriptArray.Add(@"
#
# User: $($u.LinuxName)
#
if id '$($u.LinuxName)' &>/dev/null; then

    if dzdo usermod  -p '$($u.LinuxPassword)'  '$($u.LinuxName)' &>/dev/null
    then
        existing_users+=('$($u.LinuxName)')
    else
        failed_users+=('$($u.LinuxName)')
        failures+=('User "$($u.LinuxName)": failed to update account')
    fi

else

    if dzdo useradd  -m  -b "$mHome"  -c '$($u.Description)'  -p '$($u.LinuxPassword)'  '$($u.LinuxName)' &>/dev/null
    then
        created_users+=('$($u.LinuxName)')
    else
        failed_users+=('$($u.LinuxName)')
        failures+=('User "$($u.LinuxName)": failed to create account')
    fi

fi
"@)

        #
        # Wheel membership
        #
        if ($isWheel) {
            $scriptArray.Add(@"
if id '$($u.LinuxName)' &>/dev/null; then
    if dzdo usermod -aG wheel '$($u.LinuxName)' &>/dev/null; then
        wheel_users+=('$($u.LinuxName)')
    else
        failed_wheel_users+=('$($u.LinuxName)')
        failures+=('Privilege "$($u.LinuxName):wheel": failed to assign wheel')
    fi
else
    failed_wheel_users+=('$($u.LinuxName)')
    failures+=('Privilege "$($u.LinuxName):wheel": user does not exist')
fi
"@)
        }

        #
        # Password expiration
        #
        if ($u.MustChangePassword) {
            $scriptArray.Add(@"
if id '$($u.LinuxName)' &>/dev/null; then
    if dzdo chage -d 0 '$($u.LinuxName)' &>/dev/null; then
        expired_users+=('$($u.LinuxName)')
    else
        failed_expiry_users+=('$($u.LinuxName)')
        failures+=('Password expiry "$($u.LinuxName)": failed')
    fi
else
    failed_expiry_users+=('$($u.LinuxName)')
    failures+=('Password expiry "$($u.LinuxName)": user does not exist')
fi
"@)
        }
    }

    #
    # JSON output
    #
    $scriptArray.Add(@'
#
# Build normalized action array.
#
actions="$(
    jq -n \
        --argjson created       "$(array_to_json "${created_users[@]}")" \
        --argjson existing      "$(array_to_json "${existing_users[@]}")" \
        --argjson failedUsers   "$(array_to_json "${failed_users[@]}")" \
        --argjson wheel         "$(array_to_json "${wheel_users[@]}")" \
        --argjson failedWheel   "$(array_to_json "${failed_wheel_users[@]}")" \
        --argjson expired       "$(array_to_json "${expired_users[@]}")" \
        --argjson failedExpiry  "$(array_to_json "${failed_expiry_users[@]}")" \
        --argjson luks          "$(array_to_json "${luks_updated[@]}")" \
        --argjson failedLuks    "$(array_to_json "${failed_luks[@]}")" \
        --argjson timers        "$(array_to_json "${systemd_timers[@]}")" \
        --argjson failedTimers  "$(array_to_json "${failed_timers[@]}")" \
        '
        [
            (
                $created[] |
                {
                    Category: "User",
                    Name: .,
                    Status: "Created",
                    Details: null
                }
            ),

            (
                $existing[] |
                {
                    Category: "User",
                    Name: .,
                    Status: "Existed",
                    Details: null
                }
            ),

            (
                $failedUsers[] |
                {
                    Category: "User",
                    Name: .,
                    Status: "Failed",
                    Details: null
                }
            ),

            (
                $wheel[] |
                {
                    Category: "Privilege",
                    Name: (. + ":wheel"),
                    Status: "Success",
                    Details: null
                }
            ),

            (
                $failedWheel[] |
                {
                    Category: "Privilege",
                    Name: (. + ":wheel"),
                    Status: "Failed",
                    Details: null
                }
            ),

            (
                $expired[] |
                {
                    Category: "PasswordExpiry",
                    Name: .,
                    Status: "Success",
                    Details: null
                }
            ),

            (
                $failedExpiry[] |
                {
                    Category: "PasswordExpiry",
                    Name: .,
                    Status: "Failed",
                    Details: null
                }
            ),

            (
                $luks[] |
                {
                    Category: "DiskEncryption",
                    Name: .,
                    Status: "Success",
                    Details: null
                }
            ),

            (
                $failedLuks[] |
                {
                    Category: "DiskEncryption",
                    Name: .,
                    Status: "Failed",
                    Details: null
                }
            ),

            (
                $timers[] |
                {
                    Category: "ScheduledTask",
                    Name: .,
                    Status: "Success",
                    Details: null
                }
            ),

            (
                $failedTimers[] |
                {
                    Category: "ScheduledTask",
                    Name: .,
                    Status: "Failed",
                    Details: null
                }
            )
        ]
        '
)"

jq -n \
    --arg hostname "$(hostname -s)" \
    --argjson success "$([[ ${#failures[@]} -eq 0 ]] && echo true || echo false)" \
    --argjson actions "$actions" \
    --argjson failures "$(array_to_json "${failures[@]}")" \
    '{
        HostName: $hostname,
        Platform: "Linux",
        Success: $success,
        Actions: $actions,
        Failures: $failures
    }'
'@)

    return ($scriptArray -join "`n`n")
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
    $disjoinB64 = ConvertTo-Base64 $disjoinData
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
        -Arguments "-NoProfile -ExecutionPolicyBypass -Encoded $disjoinB64" `
        -TriggerConfigs @($bootTrigger)


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
            @{ Header = 'KERNEL';  Getter = { param($r) if ($r.Success -and $r.Summary.Kernel) { $r.Summary.Kernel 
                    } else { '-' 
                    } } 
            }
            @{ Header = 'AV DEFS'; Getter = { param($r) if ($r.Success -and $r.Summary.AVDefs) { $r.Summary.AVDefs 
                    } else { '-' 
                    } } 
            }
            @{ Header = 'IVANTI';  Getter = { param($r) if ($r.Success -and $r.Summary.IvantiVersion) { $r.Summary.IvantiVersion 
                    } else { '-' 
                    } } 
            }
            @{ Header = 'LICENSE'; Getter = { param($r) if ($r.Success -and $r.Summary.License) { $r.Summary.License 
                    } else { '-' 
                    } } 
            }
            @{ Header = 'LAPS';    Getter = { param($r) if ($r.Success -and $r.Summary.AdminRotateVersion) { $r.Summary.AdminRotateVersion 
                    } else { '-' 
                    } } 
            }
            @{ Header = 'PKGS';    Getter = { param($r) if ($r.Success -and $null -ne $r.Summary.PackageCount) { $r.Summary.PackageCount 
                    } else { '-' 
                    } } 
            }
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
        [PSCustomObject]$Config,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$defaultUsersPath = $Script:Config.mobileDefaultUsers,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$mobileEntriesPath = $Script:Config.mobileEntries ,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$fallBackPass = $Script:Config.fallbackPass,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$nfsHome = $Script:Config.nfsHome,


        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$mobileDumpPath = $Script:Config.mobileDump,

        [Parameter(ParameterSetName = 'ExplicitPaths')]
        [string]$sshKeyPath = $Script:Config.sshKeyPath,

        [Parameter()]
        [switch]$Full
    )

    if ($PSCmdlet.ParameterSetName -eq 'Config') {
        $cfg = Get-MobileConfig $config
        $defaultUsersPath  = $cfg.mobileDefaultUsers
        $mobileEntriesPath = $cfg.MobileEntries
        $fallBackPass      = $cfg.fallbackPass
        $nfsHome           = $cfg.NfsHome
        $sshKeyPath        = $cfg.sshKeyPath
        $mobileDumpPath    = $cfg.MobileDump
    }

    $data = Get-MobileData -MobileName $MobileName -defaultUserpath $defaultUsersPath -mobileEntriesPath $mobileEntriesPath -fallbackPass $fallBackPass

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
        $passPath    = Join-Path $mobileDumpPath $u.Username
        $hasPassword = Test-Path $passPath

        $statusText  = if ($hasPassword) { "[+] SET" 
        } else { "[-] PENDING" 
        }
        $statusColor = if ($hasPassword) { 'Green' 
        } else { 'DarkRed' 
        }
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
            Initialize-Ssh-Environment -keyPath $sshKeyPath -nfsHome $nfsHome 
        }

        $computerData = Invoke-InformationCollector `
            -winComputers $data.Windows `
            -linComputers $data.Linux `
            -sshKeyPath $sshKeyPath

        $computerData | Format-HostCollector

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
        [array]$allUsers

    )

    if (-not $Results) {
        Write-Host "No deployment results returned." -ForegroundColor Yellow
        return
    }

    function Get-ShortHostName {
        param([string]$Name)

        if ([string]::IsNullOrWhiteSpace($Name)) {
            return '-'
        }

        ($Name -split '\.')[0]
    }

    function Get-StatusColor {
        param([string]$Status)

        switch -Regex ($Status) {
            'Failed'   { 'Red' 
            }
            'Created'  { 'Yellow' 
            }
            'Existed' { 'Green' 
            }
            'Success'  { 'Green' 
            }
            'Change'   { 'Yellow' 
            }
            'N/A'      { 'DarkGray' 
            }
            '^-$'      { 'DarkGray' 
            }
            default    { 'Gray' 
            }
        }
    }

    function Get-AggregateStatus {
        param(
            [Parameter(Mandatory)]
            $Result,

            [Parameter(Mandatory)]
            [string]$Category
        )

        $actions = @(
            $Result.Actions |
                Where-Object Category -eq $Category
        )

        if (-not $actions) {
            return '-'
        }

        if ($actions.Status -contains 'Failed') {
            return 'Failed'
        }

        return 'Success'
    }

    #
    # Host lookup
    #
    $hostMap = @{}

    foreach ($r in $Results) {
        $host = Get-ShortHostName $r.HostName
        $hostMap[$host] = $r
    }

    $hosts = @($hostMap.Keys | Sort-Object)

    #
    # Collapse users down to LinuxName/BaseName style.
    #
    # Prefer .local as the canonical displayed user.
    #
    $canonicalUsers = @(
        $Results.Actions |
            Where-Object Category -eq 'User' |
            ForEach-Object {
                ($_.Name -split '\.')[0] + '.local'
            } |
            Sort-Object -Unique
    )

    #
    # USER MATRIX
    #
    Write-Host ""
    Write-Host "[USERS]" -ForegroundColor Cyan

    foreach ($host in $hosts) {
        $result = $hostMap[$host]

        Write-Host ""
        Write-Host $host -ForegroundColor Cyan

        $baseNames = @(
            $AllUsers.BaseName |
                Sort-Object -Unique
        )

        foreach ($baseName in $baseNames) {

            $userDefs = @(
                $AllUsers |
                    Where-Object BaseName -eq $baseName
            )

            #
            # Metadata-backed roles
            #
            $roles = @(
                $userDefs |
                    Select-Object -ExpandProperty GroupType -Unique |
                    ForEach-Object {
                        $_.ToString()
                    }
            )

            #
            # Deployment actions for this user
            #
            #
            # Get the account name(s) actually deployed on this platform.
            #
            $accountNames = if ($result.Platform -eq 'Linux') {
                @(
                    $userDefs.LinuxName |
                        Where-Object { $_ } |
                        Sort-Object -Unique
                )
            } else {
                @(
                    $userDefs.Name |
                        Where-Object { $_ } |
                        Sort-Object -Unique
                )
            }

            #
            # Find deployment results for those accounts.
            #
            $accountActions = @(
                $result.Actions |
                    Where-Object {
                        $_.Category -eq 'User' -and
                        $_.Name -in $accountNames
                    }
            )

            #
            # Account state
            #
            $accountStatus = if ($accountActions.Status -contains 'Failed') {
                'Failed'
            } elseif ($accountActions.Status -contains 'Created') {
                'Created'
            } elseif ($accountActions.Status -contains 'Existed') {
                'Existed'
            } else {
                '-'
            }

            #
            # Password state comes from canonical user data too
            #
            $mustChange = $userDefs.MustChangePassword -contains $true

            $passwordStatus = if ($mustChange) {
                '[~Default]'
            } else {
                '[~Good]'
            }

            $roleText = $roles -join ', '

            $color = switch ($accountStatus) {
                'Failed'   { 'Red' 
                }
                'Created'  { 'Yellow' 
                }
                'Existed' { 'Green' 
                }
                default    { 'Gray' 
                }
            }

            Write-Host (
                "  {0,-12}: {1,-24} - {2,-9} - {3}" -f
                $baseName,
                $roleText,
                $accountStatus,
                $passwordStatus
            ) -ForegroundColor $color
        }
    }

    #
    # TASK MATRIX
    #
    Write-Host ""
    Write-Host "[DEPLOYMENT TASKS]" -ForegroundColor Cyan

    $taskColumns = @(
        'Privileges',
        'ScheduledTasks',
        'Encryption',
        'DomainDisjoin',
        'PostDisjoin'
    )

    $taskWidth = 18

    Write-Host ("{0,-$hostWidth}" -f 'HOST') -NoNewline -ForegroundColor DarkGray

    foreach ($task in $taskColumns) {
        Write-Host (" {0,-$taskWidth}" -f $task) -NoNewline -ForegroundColor DarkGray
    }

    Write-Host ""

    foreach ($host in $hosts) {
        $result = $hostMap[$host]

        Write-Host ("{0,-$hostWidth}" -f $host) -NoNewline

        $statuses = [ordered]@{
            Privileges = Get-AggregateStatus `
                -Result $result `
                -Category 'Privilege'

            ScheduledTasks = Get-AggregateStatus `
                -Result $result `
                -Category 'ScheduledTask'

            Encryption = Get-AggregateStatus `
                -Result $result `
                -Category 'DiskEncryption'

            DomainDisjoin = if ($result.Platform -eq 'Windows') {
                Get-AggregateStatus `
                    -Result $result `
                    -Category 'Domain'
            } else {
                'N/A'
            }

            PostDisjoin = if ($result.Platform -eq 'Windows') {
                Get-AggregateStatus `
                    -Result $result `
                    -Category 'PostDisjoin'
            } else {
                'N/A'
            }
        }

        foreach ($task in $taskColumns) {
            $status = $statuses[$task]
            $color = Get-StatusColor $status

            Write-Host (" {0,-$taskWidth}" -f $status) `
                -NoNewline `
                -ForegroundColor $color
        }

        Write-Host ""
    }

    #
    # FAILURES
    #
    $failed = @(
        $Results |
            Where-Object {
                @($_.Failures).Count -gt 0
            }
    )

    if ($failed.Count) {
        Write-Host ""
        Write-Host "[FAILURES]" -ForegroundColor Red

        foreach ($r in $failed) {
            $host = Get-ShortHostName $r.HostName

            foreach ($failure in @($r.Failures)) {
                Write-Host (
                    "  {0,-12} {1}" -f $host, $failure
                ) -ForegroundColor Red
            }
        }
    }
}


function Start-MobileDeployment {
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
        [string]$nfsHome   = $Script:Config.NfsHome
    )

    # $cfg = Get-MobileConfig $Config
    Initialize-Functionality -sshKeyPath $sshKeyPath -nfsHome $nfsHome -adminRoot $adminRoot  -certName $certName
    $mobileData = Get-MobileData -MobileName $MobileName 
    $mobileData.AllUsers  = Get-UserCreds -MobileName $MobileName -AllUsers $mobileData.AllUsers -mobileDumpPath $mobileDump 
    $taskData = Get-TaskData -hasLinux:$($mobileData.Linux.Count -gt 0)
    $disJoin = $false
    Write-Host "---Deployment Started---"

    $windowsPayload = [PSCustomObject]@{
        allUsers = @($mobileData.AllUsers)
        taskData = @($taskData)
        MobileName = $MobileName
        Disjoin = $disJoin
        Bitlocker = $defaultPin

    }
    Write-Host $windowsPayload

    $winErrors = [System.Collections.Generic.List[object]]::new()
    $rawWindows = Invoke-Command `
        -ComputerName $mobileData.Windows `
        -ScriptBlock $Script:WindowsDeployBlock `
        -ArgumentList $windowsPayload `
        -ErrorVariable winErrors `
        -ErrorAction SilentlyContinue

    Write-Host "[+] Windows Finished"
    Write-Host "`t Fotmatting Output"
    $rawWindows | Format-List *

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


function Invoke-InformationCollector {
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

        $cores = (
            Get-CimInstance Win32_Processor |
                Measure-Object -Property NumberOfCores -Sum
        ).Sum

        $packages = @(
            Get-ItemProperty @(
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            ) -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.DisplayName -and
                    -not $_.SystemComponent
                } |
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

        $symantecAvDefs = (
            Get-ItemProperty `
                -Path 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Storages\Definitions\VirusDefs' `
                -ErrorAction SilentlyContinue
        ).DefSetVersion

        $adminRotateScriptVersion = $null

        $adminScriptExists = Get-ScheduledTask `
            -TaskName 'ADMIN-LAPS' `
            -ErrorAction SilentlyContinue

        if ($adminScriptExists) {
            $xml = schtasks /query /tn ADMIN-LAPS /xml

            $versionMatch = (
                $xml |
                    Select-String -Pattern '<Version>(.*?)</Version>'
            ).Matches

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
                            2 { 'Succeeded' 
                            }
                            3 { 'Succeeded With Errors' 
                            }
                            4 { 'Failed' 
                            }
                            5 { 'Aborted' 
                            }
                            default { "Other: $($_.ResultCode)" 
                            }
                        }
                    }
                }
        )

        $lastUpdate = $latestUpdates |
            Where-Object Status -like 'Succeeded*' |
            Sort-Object Date -Descending |
            Select-Object -First 1 -ExpandProperty Date

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

            $hostErrors = @(
                $winFails |
                    Where-Object {
                        $_.TargetObject -eq $computer -or
                        $_.OriginInfo.PSComputerName -eq $computer
                    }
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


function Get-LinuxUnregisterScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$AllUsers,

        [Parameter()]
        [bool]$Archive = $true
    )

    $scriptArray = [System.Collections.Generic.List[string]]::new()

    $archiveValue = if ($Archive) { 'true' 
    } else { 'false' 
    }

    $scriptArray.Add(@"
#!/usr/bin/env bash

archive=$archiveValue

monthYear=`$(date '+%m-%Y')
timeStamp=`$(date '+%Y%m%d')

mobileHome='/mobiles/home'
archiveRoot='/mobiles/archive'
archivePath="`$archiveRoot/`$monthYear"

declare -a removed_users=()
declare -a missing_users=()
declare -a archived_users=()
declare -a removed_tasks=()
declare -a missing_tasks=()
declare -a failures=()

if [[ "`$archive" == true ]]; then
    if ! dzdo mkdir -p "`$archivePath"; then
        failures+=("archive-directory:`$archivePath")
    fi
fi

"@)

    $linuxUsers = foreach ($group in ($AllUsers | Group-Object BaseName)) {
        $group.Group |
            Where-Object { $null -ne $_.LinuxAccountType } |
            Sort-Object {
                $script:GroupMetadata[$_.GroupType].LinuxPriority
            } -Descending |
            Select-Object -First 1
    }


    foreach ($u in $linuxUsers) {
        $scriptArray.Add(@"
username='$($u.LinuxName)'
homePath="`$mobileHome/`$username"

if id "`$username" &>/dev/null; then

    #
    # Archive before destructive cleanup
    #
    if [[ "`$archive" == true && -d "`$homePath" ]]; then
        archiveFile="`$archivePath/`$username-`$timeStamp.tar.gz"

        if dzdo tar -czf "`$archiveFile" -C "`$(dirname "`$homePath")" "`$(basename "`$homePath")"; then
            archived_users+=("`$username")
        else
            failures+=("archive:`$username")
            continue
        fi
    fi

    #
    # Remove account and home
    #
    if dzdo userdel -r "`$username"; then
        removed_users+=("`$username")
    else
        failures+=("user:`$username")
    fi

else
    missing_users+=("`$username")

    #
    # Account may already be gone while home remains.
    # Preserve/archive it before cleanup.
    #
    if [[ -d "`$homePath" ]]; then

        if [[ "`$archive" == true ]]; then
            archiveFile="`$archivePath/`$username-`$timeStamp.tar.gz"

            if dzdo tar -czf "`$archiveFile" -C "`$(dirname "`$homePath")" "`$(basename "`$homePath")"; then
                archived_users+=("`$username")
            else
                failures+=("archive:`$username")
                continue
            fi
        fi

        if ! dzdo rm -rf -- "`$homePath"; then
            failures+=("profile:`$username")
        fi
    fi
fi

"@)
    }

    $scriptArray.Add(@'
#
# Remove mobile-specific systemd units.
#
mobile_units=(
    "mobile-logrotate.timer"
    "mobile-logrotate.service"
)

for unit in "${mobile_units[@]}"; do
    if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "^$unit"; then

        if dzdo systemctl disable --now "$unit" >/dev/null 2>&1; then
            if dzdo rm -f "/etc/systemd/system/$unit"; then
                removed_tasks+=("$unit")
            else
                failures+=("unit-file:$unit")
            fi
        else
            failures+=("unit:$unit")
        fi

    else
        missing_tasks+=("$unit")
    fi
done

dzdo systemctl daemon-reload >/dev/null 2>&1 || failures+=("systemd:daemon-reload")


#
# Emit structured result.
#
to_json_array()
{
    if (($# == 0)); then
        printf '[]'
    else
        printf '%s\n' "$@" |
            jq -Rsc 'split("\n")[:-1]'
    fi
}

created_json=$(to_json_array "${removed_users[@]}")
missing_json=$(to_json_array "${missing_users[@]}")
archive_json=$(to_json_array "${archived_users[@]}")
tasks_json=$(to_json_array "${removed_tasks[@]}")
missing_tasks_json=$(to_json_array "${missing_tasks[@]}")
failures_json=$(to_json_array "${failures[@]}")

jq -n \
    --arg hostname "$(hostname)" \
    --argjson removed "$created_json" \
    --argjson missing "$missing_json" \
    --argjson archived "$archive_json" \
    --argjson tasks "$tasks_json" \
    --argjson missingTasks "$missing_tasks_json" \
    --argjson failures "$failures_json" \
'
{
    HostName: $hostname,
    Platform: "Linux",
    Success: (($failures | length) == 0),

    Actions: [
        {
            Name: "ProfilesArchived",
            Status: (
                if ($archived | length) > 0
                then "Changed"
                else "Ok"
                end
            ),
            Details: $archived
        },
        {
            Name: "UsersRemoved",
            Status: (
                if ($removed | length) > 0
                then "Changed"
                else "Ok"
                end
            ),
            Details: $removed
        },
        {
            Name: "UsersAbsent",
            Status: "Ok",
            Details: $missing
        },
        {
            Name: "SystemdUnits",
            Status: (
                if ($tasks | length) > 0
                then "Changed"
                else "Ok"
                end
            ),
            Details: $tasks
        },
        {
            Name: "UnitsAbsent",
            Status: "Ok",
            Details: $missingTasks
        }
    ],

    Failures: $failures
}
'
'@)

    return $scriptArray -join "`n"
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

    Format-DeploymentResults (@($winResults) + @($linResults))


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
