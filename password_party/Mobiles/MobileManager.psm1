# Module layout: configuration defaults, types, shared utilities, credentials,
# GPO/environment setup, definitions, platform provisioning, collectors, reporting, commands.

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

$adminRoot = if ($manifestCfg.adminRoot) { $manifestCfg.adminRoot } else { $PSScriptRoot }
$nfsRoot   = if ($manifestCfg.nfsHomeRoot) {
    $manifestCfg.nfsHomeRoot
} else {
    "C:\Temp\Mobiles"
} # Or appropriate fallback path
$mobileRoot = Join-Path $nfsRoot ".mobiles"
$sshName = if ($manifestCfg.sshKeyName) { $manifestCfg.sshKeyName } else { "deployer" }
$script:Config = [PSCustomObject]@{
    nfsHomeRoot        = $nfsRoot
    AdminRoot          = $adminRoot
    MobileRoot         = $mobileRoot
    GpoID              = $manifestCfg.GpoID
    SshKeyName         = $sshName
    CertName           = $manifestCfg.CertName
    fallbackPass       = $manifestCfg.fallbackPass
    curLuks            = $manifestCfg.curLuks
    encryptionPin      = $manifestCfg.encryptionPin
    mobileOU           = $manifestCfg.MobileOU
    DeploymentTasks    = $manifestCfg.DeploymentTasks
    Preflight          = $manifestCfg.Preflight
    SMBUser            = $manifestCfg.SMBUser
    SMBLinuxGroup      = $manifestCfg.SMBLinuxGroup
    NfsHome            = (Join-Path $nfsRoot $env:USERNAME)
    MobileEntries      = (Join-Path $mobileRoot 'entries')
    mobileDefaultUsers = (Join-Path $mobileRoot '.default')
    MobileDump         = (Join-Path $mobileRoot '.dump')
    MobileDeployments  = (Join-Path $mobileRoot '.deployments')
    SSHKeyPath         = Join-Path (Join-Path (Join-Path $nfsRoot $env:USERNAME) ".ssh") $sshName
}

#region Types and account role metadata

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

enum TaskTriggerType {
    Time         = 1
    Daily        = 2
    Weekly       = 3
    Registration = 7
    Boot         = 8
    Logon        = 9
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

#endregion

#region Shared utilities

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

if (-not ([System.Management.Automation.PSTypeName]'Sha512Crypt').Type) {
    Add-Type -TypeDefinition $Sha512CryptSource
}

function ConvertTo-Base64 {
    param (
        [string]$text
    )

    return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($text))
}

function ConvertTo-BashArgument {
    param([string]$v)
    "'" + $v.Replace("'","'\''") + "'"
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
            $psi.Arguments = "-i `"$key`" -o UpdateHostKeys=no -o BatchMode=yes -o StrictHostKeyChecking=no -q $target `"bash -s --`""
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

function Show-TerminalSinglePicker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][array]$Options,
        [Parameter(Mandatory = $true)][string]$DisplayProperty
    )

    if (-not $Options.Count) { return }
    if ([Console]::IsInputRedirected) { throw 'Selection requires an interactive terminal. Supply valid explicit selections when running unattended.' }

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
                'Escape' { return }
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

function Show-TerminalMultiPicker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string[]]$Options,
        [string[]]$SelectedOptions = @()
    )

    if (-not $Options.Count) { return }
    if ([Console]::IsInputRedirected) { throw 'Selection requires an interactive terminal. Supply valid explicit selections when running unattended.' }

    $esc = [char]27
    $selectedIndices = [System.Collections.Generic.HashSet[int]]::new()
    for ($i = 0; $i -lt $Options.Count; $i++) { if ($Options[$i] -in $SelectedOptions) { [void]$selectedIndices.Add($i) } }
    $currentIndex = 0
    $total = $Options.Count

    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
    Write-Host "[Up/Down] Navigate | [Space] Toggle | [A] All | [C] Clear | [Enter] Confirm | [Esc] Cancel" -ForegroundColor DarkGray

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
                'Escape' { return @() }
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
                    Write-Host "Selected: $summary" -ForegroundColor Green
                    return $picked
                }
            }
        }
    } finally {
        [Console]::CursorVisible = $true
    }
}

#endregion

#region Account and Active Directory utilities

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
            Name            = if ($props.Contains('name')) { $props['name'][0] } else { '' }
            DnsHostName     = if ($props.Contains('dnshostname')) { $props['dnshostname'][0] } else { '' }
            OperatingSystem = if ($props.Contains('operatingsystem')) { $props['operatingsystem'][0] } else { '' }
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

#endregion

#region Runtime configuration

# Supported names are mapped to existing implementations, never invoked as arbitrary commands.
$script:DeploymentTaskCatalog = @{
    Windows = @{
        Provisioning = @('Users', 'PasswordExpiry', 'Groups', 'BitLocker')
        Scheduled = @('LogArchiver', 'PostDeploy')
        PostDeployment = @('UserRights', 'NetworkSharing')
    }
    Linux = @{ Provisioning = @('CreateDirectory', 'LogService', 'Luks', 'AddUsers') }
}

function Test-DeploymentTaskPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Plan)
    foreach ($platform in $Plan.Keys) {
        if (-not $script:DeploymentTaskCatalog.ContainsKey($platform)) { throw "Unknown deployment platform '$platform'." }
    }
    foreach ($platform in $script:DeploymentTaskCatalog.Keys) {
        if (-not $Plan.Contains($platform) -or $Plan[$platform] -isnot [System.Collections.IDictionary]) {
            throw "DeploymentTasks.$platform must be a task-phase dictionary."
        }
        foreach ($phase in $Plan[$platform].Keys) {
            if (-not $script:DeploymentTaskCatalog[$platform].ContainsKey($phase)) { throw "Unknown deployment phase '$platform.$phase'." }
        }
        foreach ($phase in $script:DeploymentTaskCatalog[$platform].Keys) {
            if (-not $Plan[$platform].Contains($phase) -or $null -eq $Plan[$platform][$phase]) {
                throw "DeploymentTasks.$platform.$phase must be a list (use @() to disable all tasks)."
            }
            $seen = @{}
            foreach ($task in @($Plan[$platform][$phase])) {
                if ($task -isnot [string] -or $task -notin $script:DeploymentTaskCatalog[$platform][$phase]) {
                    throw "Unknown deployment task '$task' in $platform.$phase."
                }
                if ($seen.ContainsKey($task)) { throw "Duplicate deployment task '$task' in $platform.$phase." }
                $seen[$task] = $true
            }
        }
    }
}

function Get-DeploymentTaskSelection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Platform, [Parameter(Mandatory)][string]$Phase)
    Test-DeploymentTaskPlan -Plan $script:Config.DeploymentTasks
    if (-not $script:DeploymentTaskCatalog.ContainsKey($Platform) -or
        -not $script:DeploymentTaskCatalog[$Platform].ContainsKey($Phase)) {
        throw "Unknown deployment phase '$Platform.$Phase'."
    }
    # Keep dependency order stable while allowing any supported task to be omitted.
    $script:DeploymentTaskCatalog[$Platform][$Phase] |
        Where-Object { $_ -in @($script:Config.DeploymentTasks[$Platform][$Phase]) }
}

function Set-MobileConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$Overrides)

    $merged = @{}
    foreach ($property in $script:Config.PSObject.Properties) {
        $merged[$property.Name] = $property.Value
    }
    foreach ($key in $Overrides.Keys) {
        if (-not $merged.ContainsKey($key)) { throw "Unknown mobile configuration key '$key'." }
        if ($key -eq 'DeploymentTasks') {
            Test-DeploymentTaskPlan -Plan $Overrides[$key]
        } elseif ([string]::IsNullOrWhiteSpace([string]$Overrides[$key])) {
            throw "Mobile configuration '$key' cannot be empty."
        }
        $merged[$key] = $Overrides[$key]
    }

    # Recompute descendants only when their parent changed; explicit paths win.
    if ($Overrides.ContainsKey('nfsHomeRoot')) {
        if (-not $Overrides.ContainsKey('NfsHome')) {
            $merged.NfsHome = Join-Path $merged.nfsHomeRoot $env:USERNAME
        }
        if (-not $Overrides.ContainsKey('MobileRoot')) {
            $merged.MobileRoot = Join-Path $merged.nfsHomeRoot '.mobiles'
        }
    }
    if ($Overrides.ContainsKey('nfsHomeRoot') -or $Overrides.ContainsKey('MobileRoot')) {
        foreach ($child in @{ MobileEntries = 'entries'; mobileDefaultUsers = '.default'; MobileDump = '.dump'; MobileDeployments = '.deployments' }.GetEnumerator()) {
            if (-not $Overrides.ContainsKey($child.Key)) {
                $merged[$child.Key] = Join-Path $merged.MobileRoot $child.Value
            }
        }
    }
    if ($Overrides.ContainsKey('nfsHomeRoot') -or $Overrides.ContainsKey('NfsHome') -or $Overrides.ContainsKey('SshKeyName')) {
        if (-not $Overrides.ContainsKey('SSHKeyPath')) {
            $merged.SSHKeyPath = Join-Path (Join-Path $merged.NfsHome '.ssh') $merged.SshKeyName
        }
    }
    $parsedGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$merged.GpoID, [ref]$parsedGuid)) {
        throw 'GpoID must be a valid GUID.'
    }
    $script:Config = [PSCustomObject]$merged
}

#endregion

#region Credential collection and keytabs

function Get-UserCreds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MobileName,
        [Parameter(Mandatory = $true)][array]$AllUsers,
        [Parameter(Mandatory = $true)][string]$mobileDumpPath
    )
    foreach ($bName in ($allUsers.BaseName | Sort-Object -Unique)) {
        $PwFile = Join-Path  $mobileDumpPath $bName
        if ( ! (Test-Path $PwFile )) {  continue }

        $content = Unprotect-CmsMessage -Path  $PwFile
        foreach ($line in ( $content -split '\r?\n')) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $timestamp, $username, $pw = $line -split ':',3
            $uObject = $allUsers | Where-Object Name -eq $username | Select-Object -First 1
            if ($null -eq $uObject) { Write-Warning "[!] No matching user for $username with user: $bName" ; continue }
            $uObject.Password = ConvertTo-SecureString -AsPlainText -Force $pw
            $uObject.LinuxPassword = [Sha512Crypt]::Crypt($pw)
            $uObject.MustChangePassword = $false
        }
    }


    $pw = $null
    [System.GC]::Collect()
    return $AllUsers
}

function Resolve-LinuxDisjoinKeytab {
    [CmdletBinding()]
    param(
        [string]$Keytab,
        [string]$DomainController,
        [string]$Principal,
        [int]$Kvno = 0
    )
    if (-not [string]::IsNullOrWhiteSpace($Keytab)) {
        if ($Keytab -notmatch '^[A-Za-z0-9+/]+={0,2}$') { throw 'Invalid base64 keytab.' }
        return $Keytab
    }
    if ([string]::IsNullOrWhiteSpace($Principal)) {
        $Principal = Read-Host -Prompt 'Domain departure principal (user@KERBEROS.REALM)'
    }
    if ($Principal -notmatch '^[A-Za-z0-9._/-]+@[A-Za-z0-9.-]+$') {
        throw 'Supply a Kerberos principal in user@REALM form, using its actual account/realm casing.'
    }
    if ($Kvno -eq 0) {
        $versionInput = Read-Host -Prompt 'Current key version number (msDS-KeyVersionNumber) for this account'
        if (-not [int]::TryParse($versionInput, [ref]$Kvno)) { throw 'Key version number must be a positive integer.' }
    }
    if ($Kvno -lt 1) { throw 'Key version number must be a positive integer.' }
    if ([string]::IsNullOrWhiteSpace($DomainController)) {
        $DomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
    }

    $secretPass = Read-Host -AsSecureString -Prompt "Domain password for $Principal"
    try {
        if (-not $secretPass -or $secretPass.Length -eq 0) { throw 'Domain password cannot be empty.' }
        $generated = New-RemoteKeytabBase64 -DomainController $DomainController `
            -Principal $Principal -Kvno $Kvno -SecurePassword $secretPass
        if ($generated -notmatch '^[A-Za-z0-9+/]+={0,2}$') { throw 'Keytab generation did not return valid base64.' }
        return $generated
    } finally {
        if ($secretPass) { $secretPass.Dispose() }
        $secretPass = $null
    }
}

function New-RemoteKeytabBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DomainController,
        [Parameter(Mandatory)][System.Security.SecureString]$SecurePassword,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._/-]+@[A-Za-z0-9.-]+$')][string]$Principal,
        [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$Kvno,
        [ValidateSet('AES256-SHA1', 'AES128-SHA1')][string]$Crypto = 'AES256-SHA1'
    )

    # Pass SecureString via WinRM; plaintext conversion happens only inside the remote process wrapper.
    $b64Result = Invoke-Command -ComputerName $DomainController -ErrorAction Stop -ArgumentList $SecurePassword, $Principal, $Kvno, $Crypto -ScriptBlock {
        param($SecPass,$Princ, $KeyVer,$EncType)

        $tempKeytab = [System.IO.Path]::GetTempFileName()
        $bstr = [IntPtr]::Zero
        $p = $null

        try {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecPass)
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName = 'ktpass.exe'
            # /pass * requests a prompt. Redirected-input behavior needs live ktpass validation.
            # No /mapuser or /mapop: do not remap the account; reject reset prompts.
            $psi.Arguments = "/princ $Princ /pass * /kvno $KeyVer /crypto $EncType /ptype KRB5_NT_PRINCIPAL /answer - /out `"$tempKeytab`""
            $psi.UseShellExecute =$false
            $psi.RedirectStandardInput =$true
            $psi.RedirectStandardOutput =$true
            $psi.RedirectStandardError =$true
            $psi.CreateNoWindow =$true

            $p = [System.Diagnostics.Process]::Start($psi)
            $stdout = $p.StandardOutput.ReadToEndAsync()
            $stderr = $p.StandardError.ReadToEndAsync()
            $p.StandardInput.WriteLine($plain)
            $p.StandardInput.Close()
            $plain = $null
            if (-not $p.WaitForExit(30000)) {
                $p.Kill()
                throw 'ktpass timed out; check whether the installed version accepts redirected password input.'
            }
            # Do not include native output in errors: it may contain sensitive data.
            if ($p.ExitCode -ne 0 -or (Get-Item -LiteralPath $tempKeytab -ErrorAction Stop).Length -eq 0) {
                throw "ktpass did not generate a keytab (exit code $($p.ExitCode))."
            }

            $bytes = [System.IO.File]::ReadAllBytes($tempKeytab)
            return [System.Convert]::ToBase64String($bytes)
        } finally {
            if (Test-Path $tempKeytab) {
                [System.IO.File]::WriteAllBytes($tempKeytab, [byte[]]::new(0))
                Remove-Item -Path $tempKeytab -Force -ErrorAction SilentlyContinue
            }
            if ($bstr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
            $plain = $null
            if ($p) { $p.Dispose() }
        }
    }

    return $b64Result
}

#endregion

#region Group Policy

function New-ShortcutGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetOUFriendlyName,

        [Parameter()]
        [string]$GpoID = $script:Config.GpoID,

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

    try {
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

            if (-not $targetOU.Properties['gPOptions'].Value) { $targetOU.Properties['gPOptions'].Value = 0 }

            $targetOU.SetInfo()
        } else {
            Write-Warning "Target OU '$TargetOUFriendlyName' not found. Link skipped."
        }

        return (New-InitResult -Component 'GPO' -Status 'CREATED' -Details "'$gpoName' : $($gpoID) -> '$TargetOUFriendlyName'")
    } catch {
        return (New-InitResult -Component 'GPO' -Status 'FAILED' -Details "Creation failed: $($_.Exception.Message)" -Fatal)
    }

}

function Set-MobileGpoPermission {
    [CmdletBinding(DefaultParameterSetName = 'Add')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$MobileName,

        [Parameter()]
        [string]$GpoID = $script:Config.GpoID,

        [Parameter(Mandatory = $true, ParameterSetName = 'Add')]
        [switch]$Add,

        [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
        [switch]$Remove,

        [Parameter(ParameterSetName = 'Remove')]
        [switch]$Force
    )

    # Standardize GPO GUID format
    $cleanGuid = if ($GpoID -match '^\{[0-9a-fA-F-]+\}$') { $GpoID } else { "{$GpoID}" }

    # Bind to GPO container in AD
    $rootDSE       = [ADSI]"LDAP://RootDSE"
    $namingContext = $rootDSE.defaultNamingContext
    $gpoPath       = "LDAP://CN=$cleanGuid,CN=Policies,CN=System,$namingContext"
    $currentDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name

    $gpoEntry = [System.DirectoryServices.DirectoryEntry]::new($gpoPath)
    if (-not $gpoEntry.Path) {
        Write-Error "Could not bind to GPO ($cleanGuid) in Active Directory."
        return
    }

    $secDesc      = $gpoEntry.ObjectSecurity
    $applyGpoGuid = [Guid]"edacfc86-b327-11d2-9701-00c04fd91ab0"

    # Common read flag in AD (AD maps GenericRead to ReadProperty (16) + ListContents (4))
    $readRightsMask = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor
    [System.DirectoryServices.ActiveDirectoryRights]::GenericRead

    # -------------------------------------------------------------
    # FORCE REMOVE: Strip all non-admin Apply/Read ACEs
    # -------------------------------------------------------------
    if ($Force -and $Remove) {
        $rules = $secDesc.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
        $removedCount = 0
        $adminRids    = @(512, 516, 519) # Domain Admins, DCs, Enterprise Admins

        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference.Value

            # Skip well-known built-in/service identities (NT AUTHORITY, SYSTEM, etc.)
            if ($sid -match '^S-1-5-(18|19|20|32-544)') { continue }

            # Skip Domain Administrative groups
            $isProtectedAdmin = $false
            foreach ($rid in $adminRids) {
                if ($sid -match "-$rid$") {
                    $isProtectedAdmin = $true
                    break
                }
            }
            if ($isProtectedAdmin) { continue }

            # Check if ACE grants Read or Apply GPO
            $isRead  = ($rule.ActiveDirectoryRights.value__ -band $readRightsMask.value__) -ne 0
            $isApply = ($rule.ObjectType -eq $applyGpoGuid)

            if ($isRead -or $isApply) {
                $secDesc.RemoveAccessRuleSpecific($rule) | Out-Null
                $removedCount++
            }
        }

        $gpoEntry.ObjectSecurity = $secDesc
        $gpoEntry.CommitChanges()
        Write-Host "[+] Force removed $removedCount GpoRead / Apply ACEs from GPO ($cleanGuid)" -ForegroundColor Yellow
        return
    }

    # -------------------------------------------------------------
    # STANDARD ADD / REMOVE
    # -------------------------------------------------------------
    $mobileData  = Get-MobileData -MobileName $MobileName
    $targetUsers = if ($Add ) { $mobileData.AllUsers | Select-Object -ExpandProperty BaseName } else { $mobileData.MobileUsers | Select-Object -ExpandProperty UserName }
    $targetUsers = @($targetUsers | Sort-Object -Unique)

    foreach ($u in $targetUsers) {
        try {
            $account = [System.Security.Principal.NTAccount]::new($currentDomain, $u)
            $sid     = $account.Translate([System.Security.Principal.SecurityIdentifier])
        } catch {
            Write-Warning "Could not resolve SID for user: $($u)"
            continue
        }

        if ($Add) {
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

            $secDesc.AddAccessRule($ruleRead)
            $secDesc.AddAccessRule($ruleApply)
        } else {
            # Find and remove any ACE belonging to this SID that grants Read or Apply
            $rules = $secDesc.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
            $matchingRules = @($rules | Where-Object {
                    $_.IdentityReference.Value -eq $sid.Value -and
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    (
                        (($_.ActiveDirectoryRights.value__ -band $readRightsMask.value__) -ne 0) -or
                        ($_.ObjectType -eq $applyGpoGuid)
                    )
                })

            foreach ($rule in $matchingRules) {
                # RemoveAccessRuleSpecific reliably handles exact ACE matching
                $secDesc.RemoveAccessRuleSpecific($rule) | Out-Null
            }

            Write-Verbose "Removed $($matchingRules.Count) ACE(s) for '$u'."
        }
    }

    # Commit DACL updates
    $gpoEntry.ObjectSecurity = $secDesc
    $gpoEntry.CommitChanges()
    $gpoEntry.RefreshCache(@('nTSecurityDescriptor'))

    # -------------------------------------------------------------
    # VERIFICATION
    # -------------------------------------------------------------
    $rules = $gpoEntry.ObjectSecurity.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

    $r = foreach ($name in $targetUsers) {
        try {
            $sid = ([System.Security.Principal.NTAccount]::new($currentDomain, $name)).Translate(
                [System.Security.Principal.SecurityIdentifier]
            )
        } catch {
            continue
        }

        $userRules = @($rules | Where-Object { $_.IdentityReference.Value -eq $sid.Value })

        [PSCustomObject]@{
            User  = $name
            Read  = [bool]@($userRules | Where-Object {
                    $_.AccessControlType -eq 'Allow' -and
                    (($_.ActiveDirectoryRights.value__ -band $readRightsMask.value__) -ne 0)
                }).Count
            Apply = [bool]@($userRules | Where-Object {
                    $_.AccessControlType -eq 'Allow' -and
                    $_.ObjectType -eq $applyGpoGuid
                }).Count
        }
    }

    if ($Add) {
        $failed = @($r | Where-Object { -not $_.Read -or -not $_.Apply })
    } else {
        $failed = @($r | Where-Object { $_.Read -or $_.Apply })
    }

    if ($failed.Count) {
        Write-Warning "GPO permission operation incomplete or failed for $($failed.Count) user(s)."
        $failed | Format-Table -AutoSize
    } else {
        Write-Host "[+] GPO permissions verified successfully for operation ($($PSCmdlet.ParameterSetName))." -ForegroundColor Green
    }
}

#endregion

#region Environment initialization

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

function Test-AndFixDeployerCert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CertName,
        [Parameter(Mandatory)][string]$PfxStoragePath,
        [securestring]$CertPassword
    )

    # Keep the provisioning ledger separate from the public certificate payload.
    # Export directly from the resolved certificate, including the store-only case.
    try {
        $cert = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction Stop |
            Where-Object { $_.Subject -like "*$CertName*" } |
            Select-Object -First 1

        if ($cert) {
            $status = 'OK'
            $details = "Thumbprint: $($cert.Thumbprint)"
        } else {
            $pfxFile = Join-Path $PfxStoragePath "$CertName.pfx"
            $cerFile = Join-Path $PfxStoragePath "$CertName.cer"
            if (Test-Path -LiteralPath $pfxFile) {
                if (-not $CertPassword) {
                    $CertPassword = Read-Host -AsSecureString -Prompt "[!] Certificate password required to import '$pfxFile'"
                }
                $cert = Import-PfxCertificate -FilePath $pfxFile -CertStoreLocation Cert:\CurrentUser\My `
                    -Password $CertPassword -ErrorAction Stop |
                    Where-Object HasPrivateKey | Select-Object -First 1
                if (-not $cert) { throw 'PFX import did not return a certificate with a private key.' }
                $status = 'REPAIRED'
                $details = "Imported $pfxFile"
            } else {
                if (-not $CertPassword) {
                    $CertPassword = ConvertTo-SecureString -AsPlainText -Force 'deployer'
                }
                $cert = New-SelfSignedCertificate `
                    -Subject "CN=$CertName" `
                    -Type DocumentEncryptionCert `
                    -CertStoreLocation 'Cert:\CurrentUser\My' `
                    -KeyExportPolicy Exportable `
                    -NotAfter (Get-Date).AddYears(5) `
                    -ErrorAction Stop
                Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $CertPassword -ErrorAction Stop | Out-Null
                Export-Certificate -Cert $cert -FilePath $cerFile -ErrorAction Stop | Out-Null
                $status = 'CREATED'
                $details = "Minted new cert and stored to $pfxFile"
            }
        }

        $base64 = [Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        [PSCustomObject]@{
            Result = New-InitResult -Component 'Cert:Store' -Status $status -Details $details
            CertificateBase64 = $base64
        }
    } catch {
        [PSCustomObject]@{
            Result = New-InitResult -Component 'Cert:Store' -Status 'FAILED' `
                -Details "Certificate provisioning failed: $($_.Exception.Message)" -Fatal
            CertificateBase64 = $null
        }
    }
}

function Initialize-Environment {
    [CmdletBinding()]
    param(
        [Parameter()][string]$SshKeyPath    = $Script:Config.SSHKeyPath,
        [Parameter()][string]$NfsHome       = $Script:Config.NfsHome,
        [Parameter()][string]$AdminRoot     = $Script:Config.AdminRoot,
        [Parameter()][string]$MobileDump    = $Script:Config.MobileDump,
        [Parameter()][string]$MobileEntries = $Script:Config.MobileEntries,
        [Parameter()][string]$OUPath        = $Script:Config.MobileOU,
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
    $certProvision = Test-AndFixDeployerCert -CertName $CertName -PfxStoragePath $AdminRoot
    $results.Add($certProvision.Result)

    # Do not publish a logon script when certificate or other preflight checks failed.
    if (-not @($results | Where-Object { $_.Fatal -and $_.Status -eq 'FAILED' }).Count) {
        $LogOnScript = (Get-Content (Join-Path $PSScriptRoot 'MobileLogon.ps1') -ErrorAction Stop) `
            -replace 'PASTE_YOUR_BASE64_CERT_BLOB_HERE', $certProvision.CertificateBase64

        $GpoID = $script:Config.GpoID
        $cleanGpoID = if ($GpoID -match '^\{[0-9a-fA-F-]+\}$') { $GpoID.ToUpper() } else { "{$($GpoID.ToUpper())}" }
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $gpoSysvolPath = "\\$domain\sysvol\$domain\policies\$cleanGpoID"
        $outPath = Join-Path $gpoSysvolPath "CreateLocalAccounts.ps1"
        $actualRunFile = Join-Path $gpoSysvolPath "Run.ps1"

        $results.Add((New-ShortcutGPO -TargetOUFriendlyName "$OUPath" -quiet -Arguments "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$actualRunFile`""))
        $runContent = @"
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "$outPath" -MobileDumpPath $($Script:Config.MobileDump) -MobileEntriesPath $($Script:Config.MobileEntries)
"@
        $LogonScript | Set-Content -Path $outPath
        $runContent | Set-Content -Path $actualRunFile

    }

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
            Write-Host ("{0,-8}" -f "[ $($r.Status) ]") -ForegroundColor $color -NoNewline
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

#endregion

#region Mobile definitions

function Get-MobileData {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$MobileName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$defaultUserpath = $Script:Config.mobileDefaultUsers,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$mobileEntriesPath = $Script:Config.MobileEntries,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$fallbackPass = $Script:Config.fallbackPass

    )




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
    =====
 @"

    if (-not $userPathExists -or -not $mobileEntriesExist) {
        Write-Error "[!] Ensure proper directory setup"
        Write-Warning "--- ${defaultUserPath}:${userPathExists}"
        Write-Warning "--- ${mobileEntriesPath}:${mobileEntriesExist}"
        throw "Mobile definition directories are unavailable."
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
    if ($MobileName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$' -or $MobileName.EndsWith('.')) {
        throw 'Mobile name must be a simple filename using letters, digits, dots, underscores, or hyphens.'
    }
    ## Default users
    $result.DefaultUsers = @(Get-ChildItem -File -Force -LiteralPath $defaultUserpath | Get-Content | ConvertFrom-Csv)
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
                        Name = if ($_.fullname) { $_.fullname } else { $_.name }
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
        if ([string]::IsNullOrWhiteSpace($u.Username)) { throw 'Mobile user rows require a username.' }
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
                WindowsGroups = $meta.WindowsGroups
            }

            $allUsers.Add($uData)
        }
    }
    $allUsers = $allUsers | Sort-Object Name -Unique

    $result.AllUsers = $allUsers

    [PSCustomObject]$result
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

    if ($newMobile.MobileName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$' -or
        $newMobile.MobileName.EndsWith('.')) {
        throw 'Mobile name must be a simple filename using letters, digits, dots, underscores, or hyphens.'
    }
    $outPath = Join-Path $mobilesPath $newMobile.MobileName
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
    if (@($newMobile.Users).Count -gt 0) {
        foreach ($row in ($newMobile.Users | Select-Object username, groups, fullname | ConvertTo-Csv -NoTypeInformation)) {
            $lines.Add($row)
        }
    } else {
        $lines.Add('username,groups,fullname')
    }

    # Write out without BOM issues or extra blank lines
    [System.IO.File]::WriteAllLines($outPath, $lines)
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

#endregion

#region Procedure hooks and audit logs

function Get-MobileProcedureHooks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Check-in', 'Check-out')][string]$Procedure,
        [string]$ScriptsRoot = (Join-Path $PSScriptRoot 'Scripts')
    )
    $path = Join-Path $ScriptsRoot $Procedure
    if (-not (Test-Path -LiteralPath $path)) { return }
    foreach ($file in (Get-ChildItem -LiteralPath $path -File -ErrorAction Stop | Sort-Object Name)) {
        if ($file.Extension -notin @('.ps1', '.sh')) { continue }
        $content = [IO.File]::ReadAllText($file.FullName).TrimStart([char]0xFEFF)
        if ($file.Extension -eq '.sh') { $content = $content.Replace("`r`n", "`n") }
        if ($file.Extension -eq '.ps1') {
            $tokens = $null; $errors = $null
            [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$errors) | Out-Null
            if ($errors.Count) { throw "Hook '$($file.Name)' is invalid PowerShell: $($errors.Message -join '; ')" }
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes($content)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        [PSCustomObject]@{
            Name = $file.Name
            Platform = if ($file.Extension -eq '.ps1') { 'Windows' } else { 'Linux' }
            Sha256 = $hash
            ContentBase64 = [Convert]::ToBase64String($bytes)
        }
    }
}

function ConvertTo-MobileLogLines {
    [CmdletBinding()]
    param([AllowNull()]$Value, [string]$Prefix = '')
    if ($null -eq $Value) { return "$($Prefix): (none)" }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        $text = if ($Value -is [datetime]) { $Value.ToString('o') } else { [string]$Value }
        $parts = @($text -split '\r?\n')
        if ($parts.Count -eq 1) { return "$($Prefix): $text" }
        "$($Prefix):"
        foreach ($line in $parts) { "    $line" }
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Count -eq 0) { return "$($Prefix): (none)" }
        foreach ($key in ($Value.Keys | Sort-Object)) {
            $name = if ($Prefix) { "$Prefix.$key" } else { [string]$key }
            ConvertTo-MobileLogLines -Value $Value[$key] -Prefix $name
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
        if ($items.Count -eq 0) { return "$($Prefix): (none)" }
        if (@($items | Where-Object { $_ -isnot [string] -and $_ -isnot [ValueType] }).Count -eq 0) {
            return "$($Prefix): $($items -join ', ')"
        }
        for ($i = 0; $i -lt $items.Count; $i++) {
            ConvertTo-MobileLogLines -Value $items[$i] -Prefix "$Prefix[$i]"
        }
        return
    }
    $properties = @($Value.PSObject.Properties | Where-Object MemberType -in @('Property', 'NoteProperty', 'AliasProperty', 'ScriptProperty'))
    if ($properties.Count -eq 0) { return "$($Prefix): $Value" }
    foreach ($property in $properties) {
        $name = if ($Prefix) { "$Prefix.$($property.Name)" } else { $property.Name }
        ConvertTo-MobileLogLines -Value $property.Value -Prefix $name
    }
}

function Format-MobileRunEvent {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record)
    "[$($Record.TimestampUtc)] $($Record.Procedure) | $($Record.MobileName) | $($Record.Event)"
    $data = $Record.Data
    switch ($Record.Event) {
        'RunStarted' {
            "  Run ID: $($Record.RunId)"
            "  Operator: $($data.Operator)"
        }
        'Targets' {
            foreach ($platform in @('Windows', 'Linux')) {
                $targets = @($data.$platform | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                "  $platform targets: $(if ($targets.Count) { $targets -join ', ' } else { '(none)' })"
            }
        }
        'HookInventory' {
            if (-not $data) { '  Hooks: (none)' }
            foreach ($hook in $data) { "  $($hook.Platform) hook: $($hook.Name) | SHA-256: $($hook.Sha256)" }
        }
        'HostResult' {
            "  Host: $($data.HostName) | Platform: $($data.Platform) | Result: $(if ($data.Readiness) { $data.Readiness.ToUpperInvariant() } elseif ($data.Success) { 'SUCCESS' } else { 'FAILED' })"
            if (-not $data.Actions) { '  Actions: no results returned' }
            foreach ($action in $data.Actions) {
                "  [$($action.Status)] $($action.Category) / $($action.Name)"
                if ($null -ne $action.Details) {
                    ConvertTo-MobileLogLines -Value $action.Details -Prefix '    Details'
                }
            }
            foreach ($failure in $data.Failures) { "  ERROR: $failure" }
        }
        'RunCompleted' {
            "  Overall result: $(if ($data.Status) { $data.Status.ToUpperInvariant() } elseif ($data.Success) { 'SUCCESS' } else { 'FAILED' })"
        }
        'RunError' { "  ERROR: $($data.Message)" }
        default {
            if ($null -ne $data) { ConvertTo-MobileLogLines -Value $data -Prefix '  Data' }
        }
    }
    ''
}

function Show-MobileRunLog {
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][string]$Path)
    if ([IO.Path]::GetExtension($Path) -eq '.log') {
        Get-Content -LiteralPath $Path -ErrorAction Stop
        return
    }
    $lineNumber = 0
    Get-Content -LiteralPath $Path -ErrorAction Stop | ForEach-Object {
        $lineNumber++
        if (-not [string]::IsNullOrWhiteSpace($_)) {
            try { $record = $_ | ConvertFrom-Json -ErrorAction Stop }
            catch { throw "Invalid JSON on line $lineNumber in '$Path': $($_.Exception.Message)" }
            Format-MobileRunEvent -Record $record
        }
    }
}

function Write-MobileRunEvent {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Run, [Parameter(Mandatory)][string]$Event, $Data)
    $record = [PSCustomObject]@{
        TimestampUtc = [datetime]::UtcNow.ToString('o')
        RunId = $Run.Id
        MobileName = $Run.MobileName
        Procedure = $Run.Procedure
        Event = $Event
        Data = $Data
    }
    $record | ConvertTo-Json -Depth 20 -Compress | Add-Content -LiteralPath $Run.Path -Encoding UTF8 -ErrorAction Stop
    Format-MobileRunEvent -Record $record | Add-Content -LiteralPath $Run.ReadablePath -Encoding UTF8 -ErrorAction Stop
}

function New-MobileRunLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')][string]$MobileName,
        [Parameter(Mandatory)][ValidateSet('Check-in', 'Check-out', 'Preflight', 'SMB-Status')][string]$Procedure,
        [string]$LogRoot = $script:Config.MobileDeployments
    )
    New-Item -ItemType Directory -Path $LogRoot -Force -ErrorAction Stop | Out-Null
    $id = [guid]::NewGuid().ToString('N')
    $run = [PSCustomObject]@{
        Id = $id; MobileName = $MobileName; Procedure = $Procedure
        Path = Join-Path $LogRoot ("{0}-{1}-{2}-{3}.jsonl" -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), $MobileName, $Procedure, $id)
    }
    $run | Add-Member -NotePropertyName ReadablePath -NotePropertyValue ([IO.Path]::ChangeExtension($run.Path, '.log'))
    # Fail before provisioning if either audit destination cannot be written.
    Write-MobileRunEvent -Run $run -Event 'RunStarted' -Data @{ Operator = "$env:USERDOMAIN\$env:USERNAME" }
    return $run
}

function Get-WindowsProcedureHookRunner {
    [CmdletBinding()]
    param()
    return {
        param([array]$Hooks, [string]$MobileName, [string]$Procedure, [string]$RunId)
        $actions = [System.Collections.Generic.List[object]]::new()
        $failures = [System.Collections.Generic.List[string]]::new()
        foreach ($hook in $Hooks) {
            $started = [datetime]::UtcNow.ToString('o')
            $directory = Join-Path ([IO.Path]::GetTempPath()) ('mobile-hook-' + [guid]::NewGuid().ToString('N'))
            $process = $null
            $exitCode = $null; $stdout = ''; $stderr = ''; $hookSucceeded = $false
            try {
                New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
                $scriptPath = Join-Path $directory 'hook.ps1'
                $launcherPath = Join-Path $directory 'launch.ps1'
                $content = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($hook.ContentBase64))
                [IO.File]::WriteAllText($scriptPath, $content, [Text.UTF8Encoding]::new($true))
                $launcher = {
                    $ErrorActionPreference = 'Stop'
                    try {
                        & $args[0]
                        if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }
                    } catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; exit 1 }
                }
                [IO.File]::WriteAllText($launcherPath, $launcher.ToString(), [Text.UTF8Encoding]::new($true))
                $info = [Diagnostics.ProcessStartInfo]::new()
                $info.FileName = (Get-Process -Id $PID -ErrorAction Stop).Path
                $info.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$launcherPath`" `"$scriptPath`""
                $info.WorkingDirectory = $directory
                $info.UseShellExecute = $false
                $info.RedirectStandardOutput = $true
                $info.RedirectStandardError = $true
                $info.EnvironmentVariables['MOBILE_NAME'] = $MobileName
                $info.EnvironmentVariables['MOBILE_PROCEDURE'] = $Procedure
                $info.EnvironmentVariables['MOBILE_RUN_ID'] = $RunId
                $process = [Diagnostics.Process]::Start($info)
                $outTask = $process.StandardOutput.ReadToEndAsync()
                $errTask = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(300000)) {
                    $process.Kill()
                    throw 'Hook exceeded its five-minute time limit.'
                }
                $exitCode = $process.ExitCode
                $stdout = $outTask.GetAwaiter().GetResult()
                $stderr = $errTask.GetAwaiter().GetResult()
                if ($exitCode -ne 0) { throw "Hook exited with code $exitCode." }
                $hookSucceeded = $true
            } catch {
                $failures.Add("Hook '$($hook.Name)': $($_.Exception.Message)")
                $stderr += "`n$($_.Exception.Message)"
            } finally {
                if ($process) { $process.Dispose() }
                if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue }
            }
            $actions.Add([PSCustomObject]@{
                    Category = 'Hook'; Name = $hook.Name
                    Status = if ($hookSucceeded) { 'Success' } else { 'Failed' }
                    Details = [PSCustomObject]@{
                        Sha256 = $hook.Sha256; StartedUtc = $started; CompletedUtc = [datetime]::UtcNow.ToString('o')
                        ExitCode = $exitCode
                        StdOut = $stdout.Substring(0, [Math]::Min(65536, $stdout.Length))
                        StdErr = $stderr.Substring(0, [Math]::Min(65536, $stderr.Length))
                    }
                })
        }
        [PSCustomObject]@{ Actions = $actions.ToArray(); Failures = $failures.ToArray() }
    }
}

function Get-LinuxProcedureHookScript {
    [CmdletBinding()]
    param([array]$Hooks, [string]$MobileName, [string]$Procedure, [string]$RunId)
    if (-not $Hooks) { return '' }
    $header = @'
# Procedure hooks run in isolated child shells; stdout never mixes with result JSON.
run_mobile_hook() {
    local hook_name="$1" hook_hash="$2" hook_content="$3"
    local hook_dir hook_status='Failed' hook_exit=1 hook_started hook_details
    hook_started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    hook_dir="$(mktemp -d)"
    if [[ -z "$hook_dir" ]]; then
        record_failure "Hook '$hook_name': cannot create temporary directory"
        record_action 'Hook' "$hook_name" 'Failed'
        return
    fi
    chmod 700 "$hook_dir"
    if printf '%s' "$hook_content" | base64 -d > "$hook_dir/hook.sh"; then
        (cd "$hook_dir" && timeout 300 dzdo env \
            MOBILE_NAME="$mobile_hook_name" MOBILE_PROCEDURE="$mobile_hook_procedure" MOBILE_RUN_ID="$mobile_hook_run" \
            bash "$hook_dir/hook.sh") > "$hook_dir/stdout" 2> "$hook_dir/stderr"
        hook_exit=$?
        if [[ "$hook_exit" -eq 0 ]]; then hook_status='Success'; fi
    else
        printf '%s\n' 'Could not decode hook' > "$hook_dir/stderr"
        : > "$hook_dir/stdout"
    fi
    head -c 65536 "$hook_dir/stdout" > "$hook_dir/out-short"
    head -c 65536 "$hook_dir/stderr" > "$hook_dir/err-short"
    hook_details="$(jq -cn --arg sha "$hook_hash" --arg started "$hook_started" \
        --arg ended "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson code "$hook_exit" \
        --rawfile stdout "$hook_dir/out-short" --rawfile stderr "$hook_dir/err-short" \
        '{Sha256:$sha, StartedUtc:$started, CompletedUtc:$ended, ExitCode:$code, StdOut:$stdout, StdErr:$stderr}')"
    actions_json+=( "$(jq -cn --arg name "$hook_name" --arg status "$hook_status" --argjson details "$hook_details" \
        '{Category:"Hook", Name:$name, Status:$status, Details:$details}')" )
    if [[ "$hook_status" != 'Success' ]]; then record_failure "Hook '$hook_name': exit $hook_exit"; fi
    rm -rf -- "$hook_dir"
}
'@
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('mobile_hook_name=' + (ConvertTo-BashArgument $MobileName))
    $lines.Add('mobile_hook_procedure=' + (ConvertTo-BashArgument $Procedure))
    $lines.Add('mobile_hook_run=' + (ConvertTo-BashArgument $RunId))
    $lines.Add($header)
    foreach ($hook in $Hooks) {
        $lines.Add(('run_mobile_hook {0} {1} {2}' -f (ConvertTo-BashArgument $hook.Name),
                (ConvertTo-BashArgument $hook.Sha256), (ConvertTo-BashArgument $hook.ContentBase64)))
    }
    return $lines -join "`n"
}

#endregion

#region Windows provisioning and cleanup

# Literal PowerShell payloads use scriptblocks for editor highlighting and parse checks.
# Convert them to text only when assembling scripts or passing them to remote/task APIs.

function Get-WindowsTask-LogArchiver {
    return {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem
        if (-not ($system.PartOfDomain)) { return }
        $issoGroupParams = @{
            Name = "ISSO"
            Description = "[Mobile] - ISSO GROUP"
        }
        if (-not (Get-LocalGroup "ISSO" -ErrorAction SilentlyContinue)) { New-LocalGroup @issoGroupParams } else { Set-LocalGroup @issoGroupParams }
        $archivePath = "C:\Support\Logs"
        Start-Transcript -Path "C:\Support\Errata.log"
        if (-not (Test-Path -Path $archivePath)) { New-Item -ItemType Directory -Path $archivePath -Force }
        & icacls.exe $archivePath /inheritance:r /T /Q | Out-Null
        & icacls.exe $archivePath /grant Administrators:F ISSO:F System:F /T /Q | Out-Null

        $timeStamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
        $logNames = @(
            "Application"
            "System"
            "Security"
        )
        foreach ($ln in $logNames) {
            $bkUp = Join-Path $archivePath "${ln}_${timeStamp}.evtx"
            if (Test-Path $bkUp) { throw "Target $bkup exists!" }
            wevtutil cl $ln "/bu:${bkUp}"
            if ($LASTEXITCODE -ne 0) {
                Write-Error "wevtutil failed with code: $LASTEXITCODE -- Log: $ln was left untouched "
            }
        }
        Stop-Transcript

    }
}

function New-WindowsPostTask-UserRights {
    [CmdletBinding()]
    param(
        [switch]$Sharing,
        [switch]$HasLinux
    )

    return {
        # Task: User Rights



        $tmpSec = Join-Path -Path $env:TEMP -ChildPath 'sec_export.inf'
        $tmpDB  = Join-Path -Path $env:TEMP -ChildPath 'sec_temp.sdb'

        secedit /export /cfg $tmpSec /areas USER_RIGHTS /quiet

        $objUser = [System.Security.Principal.NTAccount]'Authenticated Users'
        $objSid  = $objUser.Translate( [System.Security.Principal.SecurityIdentifier]).Value

        $rights = @(
            'SeInteractiveLogonRight',
            'SeRemoteInteractiveLogonRight',
            'SeNetworkLogonRight'
        )

        $cfg = Get-Content -Path $tmpSec -Raw -Encoding Unicode

        # Ensure the [Privilege Rights] header exists
        if ($cfg -notmatch '(?m)^\[Privilege Rights\]') { $cfg += "`r`n[Privilege Rights]`r`n" }

        function Add-PrivilegeRight {
            param(
                [string]$ConfigText,
                [string]$RightName,
                [string]$RawSid
            )

            $secSid = "*$RawSid"
            $pattern = "(?m)^(\s*$([regex]::Escape($RightName))\s*=\s*)([^\r\n]*)"

            $matchResult = [regex]::Match($ConfigText, $pattern)

            if ($matchResult.Success) {

                $existingSids = @( $matchResult.Groups[2].Value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })

                if ($secSid -notin $existingSids) {

                    $newValues = @($existingSids + $secSid) -join ','

                    $ConfigText = [regex]::Replace(
                        $ConfigText,
                        $pattern,
                        {
                            param($match)
                            $match.Groups[1].Value + $newValues
                        }
                    )
                }
            } else {
                $ConfigText = $ConfigText -replace `
                    '(?m)^\[Privilege Rights\]', `
                    "[Privilege Rights]`r`n$RightName = $secSid"
            }

            return $ConfigText
        }

        # 1. Apply grant rights
        foreach ($r in $rights) {
            $cfg = Add-PrivilegeRight `
                -ConfigText $cfg `
                -RightName $r `
                -RawSid $objSid
        }

        # Write configuration
        $cfg | Set-Content -Path $tmpSec -Encoding Unicode

        # Apply configuration
        secedit /configure `
            /db $tmpDB `
            /cfg $tmpSec `
            /areas USER_RIGHTS `
            /quiet

        if ($LASTEXITCODE -eq 0) {
            record_action 'UserRights' 'LocalSecurityPolicy' 'Success'
        } else {
            record_action 'UserRights' 'LocalSecurityPolicy' 'Failed'
            record_failure "User rights configuration failed: exit code $LASTEXITCODE"
        }

        # Cleanup
        Remove-Item -Path $tmpSec, $tmpDB -Force -ErrorAction SilentlyContinue
    }.ToString()
}

function Get-PostDeployScript {
    [CmdletBinding()]
    param(
        [switch]$UserRights,
        [switch]$Sharing,
        [switch]$HasLinux,

        [string[]]$DriveLetters
    )

    $selected = @(Get-DeploymentTaskSelection -Platform Windows -Phase PostDeployment)
    if (-not $PSBoundParameters.ContainsKey('UserRights')) { $UserRights = 'UserRights' -in $selected }
    if (-not $PSBoundParameters.ContainsKey('Sharing')) { $Sharing = 'NetworkSharing' -in $selected }
    $tasks = [System.Collections.Generic.List[string]]::new()

    $tasks.Add(({
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
            }).ToString())

    if ($UserRights) { $tasks.Add( (New-WindowsPostTask-UserRights  -Sharing:$Sharing  -HasLinux:$HasLinux)) }

    # NetworkSharing is prepared by the SMB coordinator, independently of this optional task.

    $tasks.Add(({
                "[ Post Deployment Ran - $(Get-Date) ]" |
                    Out-File C:\Post-Deploy.info

                [PSCustomObject]@{
                    Platform = 'Windows'
                    Success  = ($failures.Count -eq 0)
                    Actions  = $actions.ToArray()
                    Failures = $failures.ToArray()
                } | Export-CLIXML C:\Post-Deployment.xml
            }).ToString())

    return ($tasks -join "`n`n")
}

function Get-TaskData {
    param(
        [string]$tasksPath,
        [bool]$hasLinux
    )

    $selected = @(Get-DeploymentTaskSelection -Platform Windows -Phase Scheduled)
    $postTasks = @(Get-DeploymentTaskSelection -Platform Windows -Phase PostDeployment)
    $taskData = @()
    foreach ($task in $selected) {
        switch ($task) {
            'LogArchiver' {
                $trigger = @{
                    Type = [TaskTriggerType]::Weekly
                    DaysOfWeek = 1
                    StartBoundary = (Get-Date '00:00:00').AddDays(1).ToString('s')
                }
                $xml = New-TaskXML -Description 'Mobile Auto Log Archiver' -Author '[Mobile Administration]' `
                    -Execute 'powershell.exe' -ToEncode (Get-WindowsTask-LogArchiver).ToString() -TriggerConfigs @($trigger)
                $taskData += [PSCustomObject]@{ TaskName = 'Mobile-LogArchiver'; TaskXml = $xml }
            }
            'PostDeploy' {
                # Do not register an otherwise empty post-deployment task.
                if ('UserRights' -notin $postTasks) { continue }
                $scriptText = Get-PostDeployScript -HasLinux:$hasLinux
                $trigger = @{ Type = [TaskTriggerType]::Boot; Delay = 'PT1M' }
                $xml = New-TaskXML -Description 'Runs after deployment' -Author '[Mobile Administration]' `
                    -Execute 'powershell.exe' -ToEncode $scriptText -TriggerConfigs @($trigger)
                $taskData += [PSCustomObject]@{ TaskName = 'Mobile-DisjoinTask'; TaskXml = $xml }
            }
        }
    }
    return $taskData
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

    if (('Users' -in $payload.ProvisioningTasks -or $payload.DisJoin) -and
        (-not $payload.AllUsers -or $payload.AllUsers.Count -eq 0)) {
        $failures.Add('No users provided in payload')
    }

    #
    # Users
    #
    foreach ($u in $payload.AllUsers) {

        if ('Users' -in $payload.ProvisioningTasks) {
            $uParams = @{
                Name        = $u.Name
                FullName    = $u.FullName
                Password    = $u.Password
                Description = $u.Description
                ErrorAction = 'Stop'
            }
            $existing = Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue

            if ($existing) {
                Add-Action  -Category 'User'  -Name $u.Name  -Status 'Existed'

                if ( Invoke-Step  -Context "User '$($u.Name)'"  -Action { Set-LocalUser @uParams }) { Add-Action  -Category 'User'  -Name $u.Name  -Status 'Idempotentized'  }
                else {
                    Add-Action  -Category 'User'  -Name $u.Name  -Status 'Failed'
                }
            } else {

                if ( Invoke-Step  -Context "User '$($u.Name)'"  -Action { New-LocalUser @uParams }) {
                    Add-Action  -Category 'User'  -Name $u.Name  -Status 'Created'
                } else {
                    Add-Action  -Category 'User'  -Name $u.Name  -Status 'Failed'
                }
            }
        }

        #
        # Password expiration
        #
        if ('PasswordExpiry' -in $payload.ProvisioningTasks -and $u.MustChangePassword) {

            $success = Invoke-Step  -Context "Password expiry '$($u.Name)'"  -Action { $adsiUser = [ADSI]"WinNT://./$($u.Name),user"; $adsiUser.PasswordExpired = 1; $adsiUser.SetInfo() }

            Add-Action  -Category 'PasswordExpiry'  -Name $u.Name  -Status $(if ($success) { 'Changed' } else { 'Failed' })
        }

        #
        # Groups
        #
        if ('Groups' -in $payload.ProvisioningTasks) {
            foreach ($g in $u.WindowsGroups) {
                $actionName = "$($u.Name):$g"
                $groupStatus = 'Failed'

                $success = Invoke-Step -Context "Group '$g' for '$($u.Name)'" -Action {
                    if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) {
                        New-LocalGroup -Name $g -ErrorAction Stop | Out-Null
                    }

                    $localUser = Get-LocalUser -Name $u.Name -ErrorAction Stop
                    $members = @(Get-LocalGroupMember -Group $g -ErrorAction Stop)

                    if ($localUser.SID.Value -notin @($members | ForEach-Object { $_.SID.Value })) {
                        Add-LocalGroupMember -Group $g -Member "$($env:COMPUTERNAME)\$($u.Name)" -ErrorAction Stop
                    }
                }

                Add-Action -Category 'Privilege' -Name $actionName -Status $(if ($success) { 'OK' } else { 'Failed' })
            }
        }
    }

    #
    # Scheduled tasks
    #
    foreach ($t in $payload.TaskData) {

        $success = Invoke-Step  -Context "Scheduled task '$($t.TaskName)'"  -Action { Register-ScheduledTask  -TaskName $t.TaskName  -Xml $t.TaskXML  -User System  -Force  -ErrorAction Stop }
        $cat = switch ($t.TaskName) {
            "Mobile-LogArchiver" {"Task: LogArchive"}
            "Mobile-DisjoinTask" {"Task: Disjoin"}
        }


        Add-Action  -Category $cat  -Name $t.TaskName  -Status $(if ($success) { 'OK' } else { 'Failed' })
    }

    #
    # BitLocker
    #
    if ('BitLocker' -in $payload.ProvisioningTasks) {
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

            $success = Invoke-Step  -Context "BitLocker '$($drive.MountPoint)'"  -Action { Enable-BitLocker @bitLockerParams }

            Add-Action  -Category 'DiskEncryption'  -Name $drive.MountPoint  -Status $(if ($success) { 'Changed' } else { 'Failed' })
        }
    }

    if ($payload.Hooks) {
        $hookResult = & ([scriptblock]::Create($payload.HookRunner)) -Hooks $payload.Hooks `
            -MobileName $payload.MobileName -Procedure $payload.Procedure -RunId $payload.RunId
        foreach ($action in $hookResult.Actions) { $actions.Add($action) }
        foreach ($failure in $hookResult.Failures) { $failures.Add($failure) }
    }

    #
    # Domain
    #
    if ($payload.DisJoin) {
        foreach ($u in $payload.AllUsers) {
            $ready = Invoke-Step -Context "Local access '$($u.Name)'" -Action {
                $localUser = Get-LocalUser -Name $u.Name -ErrorAction Stop
                if (-not $localUser -or -not $localUser.Enabled) {
                    throw 'Expected local account is missing or disabled.'
                }
                foreach ($g in $u.WindowsGroups) {
                    $members = @(Get-LocalGroupMember -Group $g -ErrorAction Stop)
                    if ($localUser.SID.Value -notin @($members | ForEach-Object { $_.SID.Value })) {
                        throw "Expected membership in '$g' is missing."
                    }
                }
            }
            Add-Action -Category 'LocalAccess' -Name $u.Name -Status $(if ($ready) { 'OK' } else { 'Failed' })
        }
        if ($failures.Count -gt 0) {
            Add-Action -Category 'Domain' -Name 'Disjoin' -Status 'Skipped' -Details 'Deployment prerequisites failed; machine remains on the domain.'
        } else {
            $success = Invoke-Step -Context 'Domain Disjoin' -Action {
                Remove-Computer -WorkGroupName $payload.MobileName -Force -Restart:$false -ErrorAction Stop
            }
            Add-Action -Category 'Domain' -Name 'Disjoin' -Status $(if ($success) { 'Changed' } else { 'Failed' })
        }
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

    $archive   = [bool]$payload.Archive
    $allUsers  = @($payload.AllUsers)

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

    if ($payload.Hooks) {
        $hookResult = & ([scriptblock]::Create($payload.HookRunner)) -Hooks $payload.Hooks `
            -MobileName $payload.MobileName -Procedure $payload.Procedure -RunId $payload.RunId
        foreach ($action in $hookResult.Actions) { $actions.Add($action) }
        foreach ($failure in $hookResult.Failures) { $failures.Add($failure) }
    }

    if ($failures.Count -gt 0) {
        $actions.Add([PSCustomObject]@{ Category = 'Cleanup'; Name = 'Built-in cleanup'; Status = 'Skipped'; Details = 'Check-in hooks failed.' })
        return [PSCustomObject]@{ Platform = 'Windows'; Success = $false; Actions = $actions.ToArray(); Failures = $failures.ToArray() }
    }

    # Ensure archive directory exists if archiving is enabled
    $archiveReady = $true
    if ($archive) {
        $archiveReady = Invoke-Step -Category 'ArchiveDirectory' -Name $archivePath -ScriptBlock {
            if (-not (Test-Path -LiteralPath $archivePath)) {
                New-Item -ItemType Directory -Force -Path $archivePath -ErrorAction Stop | Out-Null
            }
            $archivePath
        }
    }

    foreach ($u in $allUsers) {
        $name        = $u.Name
        $profilePath = "C:\Users\$name"
        $localUser   = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        $sid         = if ($localUser) { $localUser.SID.Value } else { $null }

        # -------------------------------------------------------------
        # 1. LOG OFF USER SESSIONS FIRST (Free locked files & registry)
        # -------------------------------------------------------------
        Invoke-Step -Category 'UserLogoff' -Name $name -ScriptBlock {
            $sessions = query session 2>&1
            foreach ($line in $sessions) {
                # Format: SESSIONNAME USERNAME ID STATE ...
                if ($line -match "\b$([regex]::Escape($name))\b") {
                    $parts = ($line.Trim() -replace '\s+', ' ').Split(' ')
                    # If SESSIONNAME is blank (e.g. disconnected), username is index 0, ID is index 1
                    # If SESSIONNAME exists, username is index 1, ID is index 2
                    $targetId = if ($parts[0] -ieq $name) { $parts[1] } else { $parts[2] }

                    if ($targetId -match '^\d+$') {
                        Write-Host " --- Logging off user: $name (Session ID: $targetId)"
                        logoff $targetId
                    }
                }
            }
            # Wait briefly for Explorer and NTUSER.DAT handles to unload
            Start-Sleep -Seconds 2
        } | Out-Null

        # Skip archiving/removal if archive path failed to create
        if ($archive -and -not $archiveReady) {
            continue
        }

        # -------------------------------------------------------------
        # 2. ARCHIVE USER PROFILE
        # -------------------------------------------------------------
        if ($archive -and (Test-Path -LiteralPath $profilePath)) {
            $archiveFile = Join-Path $archivePath "$name-$timeStamp.zip"

            $archiveOk = Invoke-Step -Category 'ProfileArchive' -Name $name -ScriptBlock {
                Compress-Archive -Path "$profilePath\*" -DestinationPath $archiveFile -CompressionLevel Optimal -Force -ErrorAction Stop
                $archiveFile
            }

            if (-not $archiveOk) { continue }
        }

        # -------------------------------------------------------------
        # 3. REMOVE PROFILE (WMI first to clean registry, then disk)
        # -------------------------------------------------------------
        if (Test-Path -LiteralPath $profilePath) {
            $profileOk = Invoke-Step -Category 'ProfileRemoval' -Name $name -ScriptBlock {
                $profileObject = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
                    Where-Object { ($sid -and $_.SID -eq $sid) -or $_.LocalPath -ieq $profilePath }

                if ($profileObject) {
                    $profileObject | Remove-CimInstance -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $profilePath) {
                    Remove-Item -LiteralPath $profilePath -Recurse -Force -ErrorAction Stop
                }
            }

            if (-not $profileOk) { continue }
        }

        # -------------------------------------------------------------
        # 4. REMOVE LOCAL USER ACCOUNT
        # -------------------------------------------------------------
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

    # -----------------------------------------------------------------
    # 5. BITLOCKER / TPM PROTECTOR CHECK
    # -----------------------------------------------------------------
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

#endregion

#region Linux provisioning and cleanup

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
    record_action 'Task: LogArchive' 'mobile-logrotate.timer' 'Success'
else
    record_action 'Task: LogArchive' 'mobile-logrotate.timer' 'Failed'
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

if [[ "`${#luks_devices[@]}" -eq 0 ]]; then
    record_action 'DiskEncryption' "ALL" 'Failed'
    record_failure 'No encrypted partitions'
else
    for dev in "`${luks_devices[@]}"; do
        if printf "%s\n%s\n" '$CurrentPass' '$NewPin' | dzdo cryptsetup luksAddKey --force --batch-mode "`$dev" &>/dev/null; then
            record_action 'DiskEncryption' "`$dev" 'Success'
        else
            record_action 'DiskEncryption' "`$dev" 'Failed'
            record_failure "Disk encryption `$dev: failed to add LUKS key"
        fi
    done

fi


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

function New-LinuxTask-LeaveDomain {
    param([Parameter(Mandatory)][string]$b64Ktab)
    if ($b64Ktab -notmatch '^[A-Za-z0-9+/]+={0,2}$') { throw 'Invalid base64 keytab.' }

    return @"
# Task: Domain Departure (only after provisioning and local account verification)
if (( `${#failures[@]} > 0 )); then
    record_action 'DomainDisjoin' '-' 'Skipped'
else
    keytab=`$(mktemp)
    if [[ -z "`$keytab" ]]; then
        record_failure 'Could not create temporary keytab'
    elif ! printf '%s' '$b64Ktab' | base64 -d > "`$keytab"; then
        record_failure 'Could not decode domain departure keytab'
    elif ! dzdo kinit -k -t "`$keytab"; then
        record_failure 'Could not authenticate domain departure'
    elif ! command -v adleave >/dev/null 2>&1; then
        record_failure 'Domain departure requires adleave'
    elif dzdo adleave; then
        record_action 'DomainDisjoin' 'Left' 'Success'
    else
        record_failure 'Could not disjoin from domain'
    fi
    if [[ -n "`$keytab" ]]; then rm -f -- "`$keytab"; fi
    if (( `${#failures[@]} > 0 )); then record_action 'DomainDisjoin' '-' 'Failed'; fi
fi
"@
}

function Get-LinuxDeployScript {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$AllUsers,

        [Parameter()]
        [switch]$SkipLuks,

        # [Parameter(ParameterSetName='disjoin', Mandatory=$true)]
        [switch]$Disjoin,

        # [Parameter(ParameterSetName='disjoin', Mandatory=$true)]
        [string]$b64kt,

        [Parameter()]
        [switch]$SkipLogrotate,
        [array]$Hooks = @(),
        [string]$MobileName,
        [string]$RunId
    )

    # 1. Resolve users according to metadata priority
    $linuxUsers = foreach ($group in ($AllUsers | Group-Object BaseName)) {
        $group.Group |
            Where-Object { $null -ne $_.LinuxAccountType } |
            Sort-Object { $script:GroupMetadata[$_.GroupType].Priority } -Descending |
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

    # 3. Assemble optional tasks in dependency order from the manifest selection.
    $selected = @(Get-DeploymentTaskSelection -Platform Linux -Phase Provisioning)
    $tasks = [System.Collections.Generic.List[string]]::new()
    $tasks.Add($header)
    foreach ($task in $selected) {
        switch ($task) {
            'CreateDirectory' { $tasks.Add((New-LinuxTask-CreateDirectory -Path '/mobiles/home')) }
            'LogService' { if (-not $SkipLogrotate) { $tasks.Add((New-LinuxTask-AddLogService)) } }
            'Luks' { if (-not $SkipLuks) { $tasks.Add((New-LinuxTask-Luks -CurrentPass $script:Config.curLuks -NewPin $script:Config.encryptionPin)) } }
            'AddUsers' { if ($linuxUsers) { $tasks.Add((New-LinuxTask-AddUsers -Users $linuxUsers -HomeBase '/mobiles/home')) } }
        }
    }

    if ($Hooks) {
        $tasks.Add((Get-LinuxProcedureHookScript -Hooks $Hooks -MobileName $MobileName -Procedure 'Check-out' -RunId $RunId))
    }

    if ($Disjoin) {
        if (-not $linuxUsers) { throw 'Domain departure requires at least one Linux account.' }
        foreach ($u in $linuxUsers) {
            $name = ConvertTo-BashArgument $u.LinuxName
            $tasks.Add(@"
# Verify the account is local, rather than merely resolvable through the domain.
if awk -F: -v user=$name '`$1 == user { found=1 } END { exit !found }' /etc/passwd; then
    record_action 'LocalAccess' $name 'Success'
else
    record_failure 'Expected local account $($u.LinuxName) is missing'
fi
"@)
            if ($u.LinuxAccountType -eq [LinuxAccountType]::Wheel) {
                $tasks.Add(@"
if ! id -nG $name | tr ' ' '\n' | grep -qx wheel; then
    record_failure 'Expected wheel membership for $($u.LinuxName) is missing'
fi
"@)
            }
        }
        $tasks.Add((New-LinuxTask-LeaveDomain -b64Ktab $b64kt))
    }

    # 4. Standardized JSON Output emitter
    $tasks.Add($footer)

    return ($tasks -join "`n`n")
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

        [switch]$SkipLogrotate,
        [array]$Hooks = @(),
        [string]$MobileName,
        [string]$RunId
    )

    #
    # Resolve canonical Linux account for each user.
    #
    $linuxUsers = foreach ($group in ($AllUsers | Group-Object BaseName)) {
        $group.Group |
            Where-Object { $null -ne $_.LinuxAccountType } |
            Sort-Object {
                $script:GroupMetadata[$_.GroupType].Priority
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
    if ($Hooks) {
        $tasks.Add((Get-LinuxProcedureHookScript -Hooks $Hooks -MobileName $MobileName -Procedure 'Check-in' -RunId $RunId))
        $tasks.Add('if (( ${#failures[@]} == 0 )); then')
        $tasks.Add(':')
    }


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

    if ($Hooks) {
        $tasks.Add('else')
        $tasks.Add("record_action 'Cleanup' 'Built-in cleanup' 'Skipped'")
        $tasks.Add('fi')
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

#endregion

#region Windows information collectors

function Get-WindowsCollector-Registry {
    [CmdletBinding()]
    param()
    return ({
            function Read-MobileRegistryKey {
                param([Parameter(Mandatory)][string]$Path)
                try {
                    $values = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
                    [PSCustomObject]@{ Path = $Path; Status = 'Found'; Values = $values; Error = $null }
                } catch {
                    $missing = $_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound
                    [PSCustomObject]@{
                        Path = $Path
                        Status = if ($missing) { 'Missing' } else { 'Error' }
                        Values = $null
                        Error = if ($missing) { $null } else { $_.Exception.Message }
                    }
                }
            }
        }).ToString()
}

function Get-WindowsCollector-DiskSpace {
    [CmdletBinding()]
    param()

    return ({
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
        }).ToString()

}

function Get-WindowsCollector-Symantec {
    [CmdletBinding()]
    param()
    return ({
            function Get-SymantecInformation {
                # Broadcom article 181033: native path for 14.3 RU5+, WOW6432Node for older x64 agents.
                $registrations = @(foreach ($path in @(
                            'HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\Public-Opstate'
                            'HKLM:\SOFTWARE\WOW6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\Public-Opstate'
                        )) { Read-MobileRegistryKey -Path $path })
                $found = @($registrations | Where-Object Status -eq 'Found')
                $errors = @($registrations | Where-Object Status -eq 'Error')
                $definitions = $found | Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_.Values.LatestVirusDefsDate)
                } | Select-Object -First 1

                [PSCustomObject]@{
                    Status = if ($definitions) { 'Collected' } elseif ($errors.Count) { 'CollectionFailed' }
                    elseif ($found.Count) { 'DefinitionsUnavailable' } else { 'NotDetected' }
                    # Preserve the vendor value; do not guess a date format or time zone.
                    DefinitionDate = if ($definitions) { $definitions.Values.LatestVirusDefsDate } else { $null }
                    DefinitionRevision = if ($definitions) { $definitions.Values.LatestVirusDefsRevision } else { $null }
                    SourcePath = if ($definitions) { $definitions.Path } else { $null }
                    Registrations = $registrations
                    Failures = @($errors | ForEach-Object { "$($_.Path): $($_.Error)" })
                }
            }
        }).ToString()
}

function Get-WindowsCollector-Ivanti {
    [CmdletBinding()]
    param()

    return ({
            function Get-IvantiInformation {
                $paths = @(
                    'HKLM:\SOFTWARE\LANDesk\ManagementSuite\WinClient'
                    'HKLM:\SOFTWARE\WOW6432Node\LANDesk\ManagementSuite\WinClient'
                    'HKLM:\SOFTWARE\WOW6432Node\LANDesk\Inventory'
                    'HKLM:\SOFTWARE\Ivanti\Endpoint Manager'
                )
                $registrations = @(foreach ($path in $paths) { Read-MobileRegistryKey -Path $path })
                # Ivanti Endpoint Manager: Client connectivity / Core information.
                $coreRegistrations = @(foreach ($path in @(
                            'HKLM:\SOFTWARE\WOW6432Node\Intel\LANDesk\LDWM'
                            'HKLM:\SOFTWARE\Intel\LANDesk\LDWM'
                        )) { Read-MobileRegistryKey -Path $path })
                $core = $coreRegistrations | Where-Object {
                    $_.Status -eq 'Found' -and -not [string]::IsNullOrWhiteSpace([string]$_.Values.CoreServer)
                } | Select-Object -First 1

                $failures = [System.Collections.Generic.List[string]]::new()
                foreach ($registration in (@($registrations) + @($coreRegistrations))) {
                    if ($registration.Status -eq 'Error') { $failures.Add("$($registration.Path): $($registration.Error)") }
                }
                $services = @()
                $servicesCollected = $false
                try {
                    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
                            $_.Name -match '^(?:LANDesk|Ivanti)' -or $_.DisplayName -match 'Ivanti|LANDesk'
                        } | Select-Object Name, DisplayName, State, StartMode)
                    $servicesCollected = $true
                } catch { $failures.Add("Services: $($_.Exception.Message)") }

                $version = $registrations | Where-Object { $_.Status -eq 'Found' -and $_.Values.Version } |
                    Select-Object -First 1
                $automatic = @($services | Where-Object StartMode -eq 'Auto')
                $stopped = @($automatic | Where-Object State -ne 'Running')
                $detected = (@($registrations + $coreRegistrations | Where-Object Status -eq 'Found').Count -gt 0 -or $services.Count -gt 0)

                [PSCustomObject]@{
                    Status                 = if ($failures.Count) { 'Partial' } elseif ($detected) { 'Collected' } else { 'NotDetected' }
                    Installed              = if ($detected) { $true } elseif ($failures.Count) { $null } else { $false }
                    Version                = if ($version) { $version.Values.Version } else { $null }
                    ConfiguredCoreServer   = if ($core) { $core.Values.CoreServer } else { $null }
                    CoreServerSourcePath   = if ($core) { $core.Path } else { $null }
                    CoreServerStatus       = if ($core) { 'Collected' }
                    elseif (@($coreRegistrations | Where-Object Status -eq 'Error').Count) { 'CollectionFailed' }
                    else { 'Unavailable' }
                    Services               = $services
                    AutomaticServicesReady = if (-not $servicesCollected -or -not $automatic.Count) { $null } else { $stopped.Count -eq 0 }
                    PolicyStatus           = $null
                    LastPolicySync         = $null
                    LastSecurityScan       = $null
                    Registrations          = $registrations
                    CoreRegistrations      = $coreRegistrations
                    Failures               = $failures.ToArray()
                }
            }
        }).ToString()
}

function Get-WindowsCollector-SecurityUpdates {
    [CmdletBinding()]
    param()

    return ({
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
        }).ToString()
}

function Get-WindowsInformationBlock {
    [CmdletBinding()]
    param()

    $parts = [System.Collections.Generic.List[string]]::new()

    # 1. Inject Child Functions
    $parts.Add((Get-WindowsCollector-Registry))
    $parts.Add((Get-WindowsCollector-Symantec))
    $parts.Add((Get-WindowsCollector-DiskSpace))
    $parts.Add((Get-WindowsCollector-Ivanti))
    $parts.Add((Get-WindowsCollector-SecurityUpdates))

    # 2. Add System Baseline & Aggregator Script
    $parts.Add(({
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
                $symantecInfo = Get-SymantecInformation
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
                        AVDefs              = $symantecInfo.DefinitionDate
                        AVDefsRevision      = $symantecInfo.DefinitionRevision
                        AVDefsStatus        = $symantecInfo.Status
                        IvantiVersion       = $ivantiInfo.Version
                        IvantiCoreServer    = $ivantiInfo.ConfiguredCoreServer
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
                        Symantec = $symantecInfo
                    }
                }
            }).ToString())

    return [scriptblock]::Create($parts -join "`n`n")
}

#endregion

#region Linux information collectors

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

clamav_value="$(clamscan -V 2>/dev/null | awk -F'/' '{print $NF}' | xargs -I{} date -d "{}" +'%Y/%m/%d' 2>/dev/null)"

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

#endregion

#region Information collection orchestration and legacy collectors

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

#endregion

#region Standalone preflight scans and readiness reporting

function Get-MobileDefinitionAssessment {
    [CmdletBinding()]
    param([AllowNull()][string]$Date, [ValidateRange(0, 3650)][int]$MaximumAgeDays = 30)
    $parsed = [datetime]::MinValue
    $valid = [datetime]::TryParseExact($Date, [string[]]@('yyyy-MM-dd', 'yyyy/MM/dd', 'yyyyMMdd'),
        [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)
    if (-not $valid) { return [PSCustomObject]@{ Status = 'Unknown'; Date = $Date; AgeDays = $null } }
    $age = ([datetime]::UtcNow.Date - $parsed.Date).Days
    [PSCustomObject]@{
        Status = if ($age -lt 0) { 'FutureDate' } elseif ($age -gt $MaximumAgeDays) { 'Stale' } else { 'Current' }
        Date = $Date; AgeDays = $age
    }
}

function Get-WindowsPreflightScanWorker {
    [CmdletBinding()]
    param()
    return {
        param([Parameter(Mandatory)][string]$RunDirectory)
        $ErrorActionPreference = 'Stop'
        function Save-ScanState($State) {
            $temporary = Join-Path $RunDirectory 'result.tmp'
            $State | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding UTF8
            Move-Item -LiteralPath $temporary -Destination (Join-Path $RunDirectory 'result.json') -Force
        }
        $options = Get-Content -LiteralPath (Join-Path $RunDirectory 'options.json') -Raw | ConvertFrom-Json
        $state = [ordered]@{
            Status = 'Running'; StartedUtc = [datetime]::UtcNow.ToString('o'); CompletedUtc = $null
            ExitCode = $null; ScanPaths = $options.WindowsScanPaths; ScanName = $options.SymantecScanName
            StdOutPath = Join-Path $RunDirectory 'stdout.txt'; StdErrPath = Join-Path $RunDirectory 'stderr.txt'
            ScanLogs = @(); Error = $null
        }
        Save-ScanState $state
        $process = $null
        try {
            $arguments = [System.Collections.Generic.List[string]]::new()
            $arguments.Add('/Sync')
            if ($options.SymantecScanName) {
                if ($options.SymantecScanName -match '["\r\n]') { throw 'Invalid configured Symantec scan name.' }
                $arguments.Add('/ScanName "' + $options.SymantecScanName + '"')
            } else {
                foreach ($path in $options.WindowsScanPaths) {
                    if ([string]::IsNullOrWhiteSpace($path) -or $path -match '["\r\n]') { throw 'Invalid Windows scan path.' }
                    $arguments.Add('/ScanDir "' + $path.TrimEnd('\') + '"')
                }
            }
            $info = [Diagnostics.ProcessStartInfo]::new()
            $info.FileName = $options.SymantecScanExecutable
            $info.Arguments = $arguments -join ' '
            $info.UseShellExecute = $false
            $info.RedirectStandardOutput = $true
            $info.RedirectStandardError = $true
            $process = [Diagnostics.Process]::Start($info)
            $outTask = $process.StandardOutput.ReadToEndAsync()
            $errTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit([int]($options.ScanTimeoutMinutes * 60000))) {
                $process.Kill()
                $state.Status = 'TimedOut'
                throw 'SEP launcher timed out; its service may still be scanning. Check native scan status.'
            }
            $state.ExitCode = $process.ExitCode
            [IO.File]::WriteAllText($state.StdOutPath, $outTask.GetAwaiter().GetResult())
            [IO.File]::WriteAllText($state.StdErrPath, $errTask.GetAwaiter().GetResult())
            if ($state.ExitCode -ne 0) { throw "DoScan.exe exited with code $($state.ExitCode)." }
            # SEP exit zero does not establish absence of detections.
            $state.Status = 'CompletedNeedsReview'
        } catch {
            if ($state.Status -ne 'TimedOut') { $state.Status = 'Failed' }
            $state.Error = $_.Exception.Message
        } finally {
            if ($process) { $process.Dispose() }
            $state.CompletedUtc = [datetime]::UtcNow.ToString('o')
            if ($env:ProgramData) {
                $state.ScanLogs = @(Get-ChildItem -Path (Join-Path $env:ProgramData 'Symantec\Symantec Endpoint Protection\*\Data\Logs\AV\*') `
                    -File -ErrorAction SilentlyContinue | Where-Object LastWriteTimeUtc -ge ([datetime]$state.StartedUtc) |
                    Select-Object FullName, LastWriteTimeUtc, Length)
            }
            Save-ScanState $state
            $completed = Join-Path (Split-Path $RunDirectory -Parent) 'completed.json'
            $temporary = $completed + '.tmp'
            $state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding UTF8
            Move-Item -LiteralPath $temporary -Destination $completed -Force
        }
    }
}

function Start-WindowsPreflightScanJob {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Options, [Parameter(Mandatory)][scriptblock]$Worker,
        [Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Executable)
    $taskName = 'Mobiles-PreflightAV'
    if ($Root -match '["\r\n]') { throw 'Invalid Windows scan state directory.' }
    # Workers execute as SYSTEM: their directory must not inherit user-write access.
    New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $root -AclObject $acl -ErrorAction Stop
    $runDirectory = Join-Path $root ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null
    $workerPath = Join-Path $runDirectory 'worker.ps1'
    [IO.File]::WriteAllText($workerPath, $Worker.ToString(), [Text.UTF8Encoding]::new($true))
    $workerOptions = [PSCustomObject]@{
        SymantecScanExecutable = $executable; SymantecScanName = $Options.SymantecScanName
        WindowsScanPaths = $Options.WindowsScanPaths; ScanTimeoutMinutes = $Options.ScanTimeoutMinutes
    }
    $workerOptions | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runDirectory 'options.json') -Encoding UTF8
    $saved = [PSCustomObject]@{ Status = 'Starting'; StartedUtc = [datetime]::UtcNow.ToString('o'); CompletedUtc = $null }
    $saved | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runDirectory 'result.json') -Encoding UTF8
    @{ RunDirectory = $runDirectory } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'latest.json') -Encoding UTF8
    try {
        $shell = (Get-Process -Id $PID).Path
        $action = New-ScheduledTaskAction -Execute $shell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workerPath`" -RunDirectory `"$runDirectory`""
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes ($Options.ScanTimeoutMinutes + 5))
        Register-ScheduledTask -TaskName $taskName -Action $action -Settings $settings -User SYSTEM -RunLevel Highest -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $status = 'Starting'
    } catch {
        $saved.Status = 'Failed'
        $saved | Add-Member -NotePropertyName Error -NotePropertyValue $_.Exception.Message
        $saved | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runDirectory 'result.json') -Encoding UTF8
        throw
    }
    [PSCustomObject]@{ RunDirectory = $runDirectory; State = $saved }
}

function Get-WindowsPreflightScanState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Options, [Parameter(Mandatory)][scriptblock]$Worker, [string]$DefinitionDate)
    $root = if ($Options.WindowsScanStateDirectory) { $Options.WindowsScanStateDirectory } else {
        Join-Path $env:ProgramData 'Mobiles\Preflight'
    }
    $taskName = 'Mobiles-PreflightAV'
    $mutex = [Threading.Mutex]::new($false, 'Global\Mobiles-PreflightAV')
    $locked = $false
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { return [PSCustomObject]@{ Status = 'Starting'; Note = 'Another preflight request is dispatching a scan.' } }
        $saved = $null; $lastCompleted = $null; $runDirectory = $null
        if (Test-Path -LiteralPath (Join-Path $root 'latest.json')) {
            $pointer = Get-Content -LiteralPath (Join-Path $root 'latest.json') -Raw -ErrorAction Stop | ConvertFrom-Json
            $runDirectory = $pointer.RunDirectory
            $saved = Get-Content -LiteralPath (Join-Path $runDirectory 'result.json') -Raw -ErrorAction Stop | ConvertFrom-Json
        }
        if (Test-Path -LiteralPath (Join-Path $root 'completed.json')) {
            $lastCompleted = Get-Content -LiteralPath (Join-Path $root 'completed.json') -Raw | ConvertFrom-Json
        }
        $nativeStatus = $null
        foreach ($path in @(
            'HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\AV'
            'HKLM:\SOFTWARE\WOW6432Node\Symantec\Symantec Endpoint Protection\AV'
        )) {
            $key = Read-MobileRegistryKey $path
            if ($key.Status -eq 'Found' -and $null -ne $key.Values.GlobalScanStatus) {
                $value = [int]$key.Values.GlobalScanStatus
                # Any active native observation takes precedence over an older idle view.
                if ($value -in @(1, 2, 3, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22)) { $nativeStatus = $value; break }
                if ($null -eq $nativeStatus) { $nativeStatus = $value }
            }
        }
        $task = $null
        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        }
        $active = ($task -and $task.State -in @('Running', 'Queued')) -or
            $nativeStatus -in @(1, 2, 3, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22)
        $status = 'NotStarted'
        if ($active) { $status = 'Running' }
        elseif ($saved) {
            $status = $saved.Status
            if ($status -in @('Starting', 'Running')) {
                $status = if ($status -eq 'Starting' -and ([datetime]::UtcNow - [datetime]$saved.StartedUtc).TotalSeconds -lt 60) { 'Starting' } else { 'Interrupted' }
            }
        } elseif ($nativeStatus -eq 4) { $status = 'CompletedNeedsReview' }
        elseif ($nativeStatus -eq 10) { $status = 'Interrupted' }
        $launch = -not $Options.SkipScans -and -not $active -and
            $status -notin @('Starting', 'Running') -and ($Options.Rescan -or $status -eq 'NotStarted')
        $maximumAge = if ($null -ne $Options.DefinitionMaxAgeDays) { [int]$Options.DefinitionMaxAgeDays } else { 30 }
        $definition = Get-MobileDefinitionAssessment -Date $DefinitionDate -MaximumAgeDays $maximumAge
        $blocked = $launch -and -not $Options.ForceScan -and $definition.Status -ne 'Current'
        if ($blocked) { $status = 'BlockedDefinitions' }
        if ($launch -and -not $blocked) {
            $candidates = @($Options.SymantecScanExecutable)
            foreach ($directory in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
                if ($directory) { $candidates += Join-Path $directory 'Symantec\Symantec Endpoint Protection\DoScan.exe' }
            }
            $executable = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
            if (-not $executable) { throw 'Symantec DoScan.exe was not found.' }
            $job = Start-WindowsPreflightScanJob -Options $Options -Worker $Worker -Root $root -Executable $executable
            $saved = $job.State
            $runDirectory = $job.RunDirectory
            $status = 'Starting'
        }
        $logs = @()
        if ($env:ProgramData) {
            $logs = @(Get-ChildItem -Path (Join-Path $env:ProgramData 'Symantec\Symantec Endpoint Protection\*\Data\Logs\AV\*') `
                -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 3 |
                ForEach-Object {
                    [PSCustomObject]@{ Path = $_.FullName; ModifiedUtc = $_.LastWriteTimeUtc.ToString('o')
                        Tail = (((Get-Content -LiteralPath $_.FullName -Tail 40 -ErrorAction SilentlyContinue) -join "`n") | ForEach-Object { $_.Substring(0, [Math]::Min(65536, $_.Length)) }) }
                })
        }
        [PSCustomObject]@{
            Status = $status; NativeScanStatus = $nativeStatus; StateDirectory = $root
            Current = $saved; LastCompleted = $lastCompleted; LatestAVLogs = $logs
            DefinitionAssessment = $definition; ScanBlocked = [bool]$blocked
            Note = if ($blocked) { 'Definitions are stale, unknown, or future-dated; use -ForceScan to override.' } else { $null }
            Review = 'SEP completion is not a clean verdict. Review the latest native AV-log evidence.'
        }
    } finally {
        if ($locked) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Get-WindowsPreflightBlock {
    [CmdletBinding()]
    param()
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add('param($Options)')
    $parts.Add((Get-WindowsCollector-Registry))
    $parts.Add((Get-WindowsCollector-Symantec))
    $parts.Add((Get-WindowsCollector-Ivanti))
    $parts.Add('function Start-WindowsPreflightScanJob {' + ${function:Start-WindowsPreflightScanJob}.ToString() + '}')
    $parts.Add('function Get-MobileDefinitionAssessment {' + ${function:Get-MobileDefinitionAssessment}.ToString() + '}')
    $parts.Add('function Get-WindowsPreflightScanState {' + ${function:Get-WindowsPreflightScanState}.ToString() + '}')
    $parts.Add('$scanWorker = {' + (Get-WindowsPreflightScanWorker).ToString() + '}')
    $parts.Add(({
        $actions = [System.Collections.Generic.List[object]]::new()
        $failures = [System.Collections.Generic.List[string]]::new()
        $symantec = Get-SymantecInformation
        $ivanti = Get-IvantiInformation
        $rawDate = [string]$symantec.DefinitionDate
        $normalizedDate = $null
        # Accept only an unambiguous date; keep the original value in Details.
        if ($rawDate -match '^(\d{4})[-/](\d{2})[-/](\d{2})(?:$|[ T])') {
            $normalizedDate = '{0}-{1}-{2}' -f $Matches[1], $Matches[2], $Matches[3]
        } elseif ($rawDate -match '^\d{8}$') { $normalizedDate = $rawDate }
        $actions.Add([PSCustomObject]@{ Category = 'Inventory'; Name = 'Symantec'; Status = $symantec.Status; Details = $symantec })
        $actions.Add([PSCustomObject]@{ Category = 'Inventory'; Name = 'Ivanti'; Status = $ivanti.Status; Details = $ivanti })
        try {
            $scan = Get-WindowsPreflightScanState -Options $Options -Worker $scanWorker -DefinitionDate $normalizedDate
        } catch {
            $scan = [PSCustomObject]@{ Status = 'Failed'; Error = $_.Exception.Message }
        }
        if ($scan.Status -in @('Failed', 'TimedOut', 'Interrupted')) {
            $failures.Add("Symantec scan: $($scan.Status). $($scan.Error)")
        }
        $actions.Add([PSCustomObject]@{ Category = 'AVScan'; Name = 'Symantec'; Status = $scan.Status; Details = $scan })
        [PSCustomObject]@{
            HostName = $env:COMPUTERNAME; Platform = 'Windows'; DefinitionDate = $normalizedDate
            ScanStatus = $scan.Status
            LastScanStatus = $scan.LastCompleted.Status; LastScanCompletedUtc = $scan.LastCompleted.CompletedUtc
            Actions = $actions.ToArray(); Failures = $failures.ToArray()
        }
    }).ToString())
    [scriptblock]::Create($parts -join "`n`n")
}

function Get-LinuxPreflightScanWorker {
    [CmdletBinding()]
    param()
    return @'
#!/usr/bin/env bash
set -o pipefail
export LC_ALL=C
run_dir="$1"
source "$run_dir/options.sh"
export PATH
state_root="$(dirname "$run_dir")"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# mountinfo describes this worker's mount namespace, including NFS bind mounts.
# Decode kernel-escaped mount points before escaping them as literal regex paths.
excluded_nfs=()
exclude_args=(--exclude-dir='^/(proc|sys|dev|run)(/|$)')
discovery_error=''
if [[ ! -r /proc/self/mountinfo ]]; then
    discovery_error='Cannot read /proc/self/mountinfo; NFS exclusions could not be determined'
else
    while IFS= read -r mount_record; do
        mount_fields="${mount_record%% - *}"
        filesystem="${mount_record#* - }"
        filesystem="${filesystem%% *}"
        [[ "$filesystem" == nfs || "$filesystem" == nfs4 ]] || continue
        read -r mount_id parent_id device mount_root mount_point mount_options remainder <<< "$mount_fields"
        printf -v mount_point '%b' "$mount_point"
        excluded_nfs+=("$mount_point")
        pattern="$(printf '%s' "$mount_point" | sed 's/[][\\.^$*+?(){}|]/\\&/g')"
        if [[ "$mount_point" == / ]]; then
            exclude_args+=(--exclude-dir='^/')
        else
            exclude_args+=("--exclude-dir=^${pattern}(/|$)")
        fi
    done < /proc/self/mountinfo
fi
excluded_json="$(printf '%s\n' "${excluded_nfs[@]}" | jq -R . | jq -s 'map(select(length > 0)) | unique | sort')"
jq -n --arg started "$started" --argjson excluded "$excluded_json" \
    '{Status:"Running",StartedUtc:$started,ExcludedNfsMounts:$excluded}' > "$run_dir/result.tmp"
mv -f "$run_dir/result.tmp" "$run_dir/result.json"
# This worker is supervised by systemd, independent of the requesting SSH session.
if [[ -n "$discovery_error" ]]; then
    : > "$run_dir/stdout.txt"
    printf '%s\n' "$discovery_error" > "$run_dir/stderr.txt"
    code=2
else
    timeout "$scan_timeout" clamscan --recursive --infected --stdout --log="$run_dir/clamav.log" \
        "${exclude_args[@]}" -- "${scan_paths[@]}" \
        > "$run_dir/stdout.txt" 2> "$run_dir/stderr.txt"
    code=$?
fi
case "$code" in
    0) status='Clean' ;;
    1) status='ThreatsDetected' ;;
    124|137) status='TimedOut' ;;
    *) status='Failed' ;;
esac
head -c 65536 "$run_dir/stdout.txt" > "$run_dir/out-short"
head -c 65536 "$run_dir/stderr.txt" > "$run_dir/err-short"
jq -n --arg status "$status" --arg started "$started" --arg ended "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson code "$code" --arg version "$version" --arg log "$run_dir/clamav.log" --argjson paths "$(printf '%s\n' "${scan_paths[@]}" | jq -R . | jq -s .)" \
    --argjson excluded "$excluded_json" --rawfile stdout "$run_dir/out-short" --rawfile stderr "$run_dir/err-short" \
    '{Status:$status,StartedUtc:$started,CompletedUtc:$ended,ExitCode:$code,DefinitionVersion:$version,LogPath:$log,ScanPaths:$paths,ExcludedNfsMounts:$excluded,StdOut:$stdout,StdErr:$stderr}' \
    > "$run_dir/result.tmp"
mv -f "$run_dir/result.tmp" "$run_dir/result.json"
cp "$run_dir/result.json" "$state_root/completed.tmp"
mv -f "$state_root/completed.tmp" "$state_root/completed.json"
'@
}

function Get-LinuxPreflightScript {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Options)
    $paths = @($Options.LinuxScanPaths | ForEach-Object { ConvertTo-BashArgument $_ }) -join ' '
    $stateRoot = if ($Options.LinuxScanStateDirectory) { $Options.LinuxScanStateDirectory } else { '/var/log/mobiles/preflight' }
    if (-not $stateRoot.StartsWith('/')) { throw 'LinuxScanStateDirectory must be an absolute path.' }
    $toolDirectories = if ($Options.LinuxToolDirectories) { @($Options.LinuxToolDirectories) } else { @('/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin') }
    foreach ($directory in $toolDirectories) {
        if ([string]::IsNullOrWhiteSpace($directory) -or -not $directory.StartsWith('/') -or $directory -match '[:\r\n]') {
            throw 'LinuxToolDirectories must contain absolute directory paths without colons or newlines.'
        }
    }
    $maximumAge = if ($null -ne $Options.DefinitionMaxAgeDays) { [int]$Options.DefinitionMaxAgeDays } else { 30 }
    $prefix = @"
force_scan=$(([bool]$Options.ForceScan).ToString().ToLowerInvariant())
maximum_age=$maximumAge
export PATH=$(ConvertTo-BashArgument ($toolDirectories -join ':'))
scan_paths=($paths)
scan_timeout=$([int]$Options.ScanTimeoutMinutes * 60)
skip_scans=$(([bool]$Options.SkipScans).ToString().ToLowerInvariant())
rescan=$(([bool]$Options.Rescan).ToString().ToLowerInvariant())
state_root=$(ConvertTo-BashArgument $stateRoot)
"@
    $body = @'
set -o pipefail
export LC_ALL=C
umask 077
for required in jq flock; do
    if ! command -v "$required" >/dev/null 2>&1; then echo "Preflight requires $required; searched PATH=$PATH" >&2; exit 2; fi
done
mkdir -p "$state_root" || exit 2
chmod 700 "$state_root" || exit 2
exec 9> "$state_root/dispatch.lock"
locked=false
if flock -n 9; then locked=true; fi
version="$(clamscan --version 2>/dev/null)"
version_exit=$?
definition_date=''
if [[ "$version_exit" -eq 0 ]]; then
    definition_date="$(date -u -d "${version##*/}" '+%Y-%m-%d' 2>/dev/null)"
fi
definitions_current=false
if [[ -n "$definition_date" ]]; then
    definition_epoch="$(date -u -d "$definition_date" +%s 2>/dev/null)"
    today_epoch="$(date -u -d "$(date -u +%F)" +%s)"
    if [[ -n "$definition_epoch" ]]; then
        age_days=$(( (today_epoch - definition_epoch) / 86400 ))
        if (( age_days >= 0 && age_days <= maximum_age )); then definitions_current=true; fi
    fi
fi
scan_status='NotStarted'
current='null'
last_completed='null'
unit=''
if [[ -s "$state_root/latest.json" ]]; then
    run_dir="$(jq -er '.RunDirectory' "$state_root/latest.json")" || exit 2
    unit="$(jq -er '.Unit' "$state_root/latest.json")" || exit 2
    current="$(jq -c . "$run_dir/result.json")" || exit 2
    scan_status="$(printf '%s' "$current" | jq -r '.Status')"
fi
if [[ -s "$state_root/completed.json" ]]; then
    last_completed="$(jq -c . "$state_root/completed.json")" || exit 2
fi
active=false
if [[ -n "$unit" ]]; then
    unit_state="$(systemctl show -p ActiveState "$unit" 2>/dev/null | cut -d= -f2)"
    case "$unit_state" in active|activating|reloading) active=true ;; esac
fi
# Also respect scans launched outside this program; do not start a duplicate.
for scanner_pid in $(pgrep -x clamscan 2>/dev/null); do
    scanner_state="$(ps -o stat= -p "$scanner_pid" 2>/dev/null)"
    if [[ -n "$scanner_state" && "$scanner_state" != Z* ]]; then active=true; break; fi
done
if [[ "$active" == true ]]; then
    scan_status='Running'
elif [[ "$scan_status" == 'Starting' ]]; then
    started="$(printf '%s' "$current" | jq -r '.StartedUtc // ""')"
    started_epoch="$(date -u -d "$started" +%s 2>/dev/null || echo 0)"
    if (( $(date -u +%s) - started_epoch > 60 )); then scan_status='Interrupted'; fi
elif [[ "$scan_status" == 'Running' ]]; then
    scan_status='Interrupted'
fi
if [[ "$locked" == false ]]; then
    scan_status='Starting'
elif [[ "$skip_scans" == false && "$active" == false && "$scan_status" != Starting && ( "$rescan" == true || "$scan_status" == 'NotStarted' ) ]]; then
    if [[ "$force_scan" != true && "$definitions_current" != true ]]; then
        scan_status='BlockedDefinitions'
    elif [[ "$version_exit" -ne 0 ]]; then
        scan_status='Failed'
        current='{"Status":"Failed","Error":"clamscan is unavailable"}'
    elif ! command -v systemd-run >/dev/null 2>&1; then
        scan_status='Failed'
        current='{"Status":"Failed","Error":"systemd-run is required for detached scans"}'
    else
        run_dir="$(mktemp -d "$state_root/run-XXXXXXXXXX")" || exit 2
        unit="mobiles-preflight-av-$(basename "$run_dir").service"
        declare -p scan_paths scan_timeout version PATH > "$run_dir/options.sh"
        cat > "$run_dir/worker.sh" <<'MOBILE_CLAM_WORKER'
'@
    $afterWorker = @'
MOBILE_CLAM_WORKER
        jq -n --arg started "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{Status:"Starting",StartedUtc:$started}' > "$run_dir/result.json"
        jq -n --arg directory "$run_dir" --arg unit "$unit" '{RunDirectory:$directory,Unit:$unit}' > "$state_root/latest.tmp"
        mv -f "$state_root/latest.tmp" "$state_root/latest.json"
        if systemd-run --unit="$unit" /bin/bash "$run_dir/worker.sh" "$run_dir" > "$run_dir/dispatch-out.txt" 2> "$run_dir/dispatch-error.txt"; then
            scan_status='Starting'
        else
            scan_status='Failed'
            jq -n --rawfile error "$run_dir/dispatch-error.txt" '{Status:"Failed",Error:$error}' > "$run_dir/result.json"
        fi
        current="$(jq -c . "$run_dir/result.json")"
    fi
fi
# Release the dispatch lock before collecting inventory. The worker never owns it.
if [[ "$locked" == true ]]; then flock -u 9; fi
scope_matches=false
definitions_match=false
if [[ "$current" != null ]]; then
    requested_paths="$(printf '%s\n' "${scan_paths[@]}" | jq -R . | jq -s .)"
    scope_matches="$(printf '%s' "$current" | jq --argjson paths "$requested_paths" '.ScanPaths == $paths')"
    definitions_match="$(printf '%s' "$current" | jq --arg version "$version" '.DefinitionVersion == $version')"
fi
jq -n --arg host "$(hostname -s)" --arg date "$definition_date" --arg version "$version" \
    --arg scan "$scan_status" --argjson current "$current" --argjson previous "$last_completed" --arg directory "$state_root" \
    --argjson scope "$scope_matches" --argjson definitions "$definitions_match" \
    '{HostName:$host,Platform:"Linux",DefinitionDate:$date,ScanStatus:$scan,
      LastScanStatus:($previous.Status // null),LastScanCompletedUtc:($previous.CompletedUtc // null),ScanEvidenceCurrent:($scope and $definitions),
      Actions:[
        {Category:"Inventory",Name:"ClamAV",Status:(if $date=="" then "Unknown" else "Collected" end),Details:{Version:$version,DefinitionDate:$date}},
        {Category:"AVScan",Name:"ClamAV",Status:$scan,Details:{StateDirectory:$directory,Current:$current,LastCompleted:$previous,ScopeMatches:$scope,DefinitionsMatch:$definitions,ScanBlocked:($scan=="BlockedDefinitions"),Note:(if $scan=="BlockedDefinitions" then "Definitions are stale, unknown, or future-dated; use -ForceScan to override" else null end)}}
      ],Failures:(if ($scan=="Failed" or $scan=="TimedOut" or $scan=="ThreatsDetected" or $scan=="Interrupted") then ["ClamAV scan: "+$scan] else [] end)}'
'@
    $delimiter = 'MOBILE_PREFLIGHT_ROOT_' + [guid]::NewGuid().ToString('N')
    # The root-owned worker and logs survive SSH disconnects; the client waits only for dispatch/status.
    "dzdo bash <<'$delimiter'`n" + $prefix + "`n" + $body + "`n" + (Get-LinuxPreflightScanWorker) + "`n" + $afterWorker + "`n$delimiter`n"
}

function Invoke-MobilePreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MobileName,
        [ValidateRange(0, 3650)][int]$DefinitionMaxAgeDays = $script:Config.Preflight.DefinitionMaxAgeDays,
        [ValidateRange(1, 1440)][int]$ScanTimeoutMinutes = $script:Config.Preflight.ScanTimeoutMinutes,
        [switch]$SkipScans,
        [switch]$Rescan,
        [Alias('force-scan')][switch]$ForceScan,
        [switch]$PassThru
    )
    if ($SkipScans -and $Rescan) { throw '-SkipScans and -Rescan cannot be used together.' }
    $run = New-MobileRunLog -MobileName $MobileName -Procedure 'Preflight'
    $results = [System.Collections.Generic.List[object]]::new()
    $runSuccess = $false
    $runStatus = 'Failed'
    try {
        $data = Get-MobileData -MobileName $MobileName
        $options = [PSCustomObject]@{
            SkipScans = [bool]$SkipScans; Rescan = [bool]$Rescan; ForceScan = [bool]$ForceScan; DefinitionMaxAgeDays = $DefinitionMaxAgeDays; ScanTimeoutMinutes = $ScanTimeoutMinutes
            WindowsScanStateDirectory = $script:Config.Preflight.WindowsScanStateDirectory
            LinuxScanStateDirectory = $script:Config.Preflight.LinuxScanStateDirectory
            LinuxToolDirectories = $script:Config.Preflight.LinuxToolDirectories
            SymantecScanName = $script:Config.Preflight.SymantecScanName
            SymantecScanExecutable = $script:Config.Preflight.SymantecScanExecutable
            WindowsScanPaths = @($script:Config.Preflight.WindowsScanPaths)
            LinuxScanPaths = @($script:Config.Preflight.LinuxScanPaths)
        }
        if (-not $options.LinuxScanPaths.Count -or @($options.LinuxScanPaths | Where-Object { [string]::IsNullOrWhiteSpace($_) -or -not $_.StartsWith('/') }).Count) {
            throw 'Preflight LinuxScanPaths must contain absolute paths.'
        }
        if (-not $options.WindowsScanPaths.Count -and -not $options.SymantecScanName) { throw 'Configure WindowsScanPaths or SymantecScanName.' }
        Write-MobileRunEvent -Run $run -Event 'Targets' -Data @{ Windows = @($data.Windows); Linux = @($data.Linux) }
        Write-MobileRunEvent -Run $run -Event 'PreflightOptions' -Data $options
        foreach ($platform in @('Windows', 'Linux')) {
            $hosts = @($data.$platform)
            if (-not $hosts.Count) { continue }
            $raw = @()
            $dispatchError = $null
            Write-Host "[+] Preflight $platform targets: $($hosts -join ', '); scans $(if ($SkipScans) { 'status only' } else { 'status/start if needed' })."
            try {
                if ($platform -eq 'Windows') {
                    $remoteErrors = @()
                    $raw = @(Invoke-Command -ComputerName $hosts -ScriptBlock (Get-WindowsPreflightBlock) -ArgumentList $options `
                        -ErrorAction SilentlyContinue -ErrorVariable remoteErrors)
                } else {
                    $raw = @(Invoke-Linux -Computers $hosts -Script (Get-LinuxPreflightScript -Options $options) -KeyPath $script:Config.SSHKeyPath)
                }
            } catch {
                $dispatchError = $_.Exception.Message
                $raw = @()
            }
            foreach ($target in $hosts) {
                $result = $null
                try {
                    if ($platform -eq 'Windows') {
                        $result = $raw | Where-Object PSComputerName -eq $target | Select-Object -First 1
                        if (-not $result) {
                            $errorText = @($remoteErrors | Where-Object { $_.TargetObject -eq $target -or $_.OriginInfo.PSComputerName -eq $target } | ForEach-Object { $_.Exception.Message }) -join '; '
                            throw "No preflight result returned. $dispatchError $errorText"
                        }
                    } else {
                        $response = $raw | Where-Object Target -eq $target | Select-Object -First 1
                        if (-not $response) { throw "No preflight result returned. $dispatchError" }
                        if ($response.ExitCode -ne 0) { throw "SSH exited $($response.ExitCode): $($response.StdErr)" }
                        $result = $response.StdOut | ConvertFrom-Json -ErrorAction Stop
                    }
                    if (-not $result.ScanStatus -or -not $result.Actions) { throw 'Malformed preflight response.' }
                    $definition = Get-MobileDefinitionAssessment -Date $result.DefinitionDate -MaximumAgeDays $DefinitionMaxAgeDays
                    $actions = @($result.Actions) + @([PSCustomObject]@{
                        Category = 'Readiness'; Name = 'AV definition age'; Status = $definition.Status
                        Details = @{ Date = $definition.Date; AgeDays = $definition.AgeDays; MaximumAgeDays = $DefinitionMaxAgeDays }
                    })
                    $ready = $definition.Status -eq 'Current' -and $result.ScanStatus -eq 'Clean' -and $result.ScanEvidenceCurrent -ne $false -and -not $result.Failures
                    $entry = [PSCustomObject]@{
                        HostName = $target; Platform = $platform; Success = $ready
                        Readiness = if ($ready) { 'Ready' } elseif ($result.Failures) { 'Failed' }
                            elseif ($result.ScanStatus -in @('Starting', 'Running', 'NotStarted')) { 'Pending' } else { 'NeedsReview' }
                        Definitions = $definition.Status; Scan = $result.ScanStatus
                        LastScan = $result.LastScanStatus; LastScanUtc = $result.LastScanCompletedUtc
                        Actions = $actions; Failures = @($result.Failures)
                    }
                } catch {
                    $entry = [PSCustomObject]@{
                        HostName = $target; Platform = $platform; Success = $false; Readiness = 'Failed'
                        Definitions = 'Unknown'; Scan = 'Unknown'
                        Actions = @(); Failures = @($_.Exception.Message)
                    }
                }
                $results.Add($entry)
                Write-MobileRunEvent -Run $run -Event 'HostResult' -Data $entry
            }
        }
        $runSuccess = $results.Count -gt 0 -and @($results | Where-Object { -not $_.Success }).Count -eq 0
        $runStatus = if ($runSuccess) { 'Ready' } elseif (@($results | Where-Object Readiness -eq 'Failed').Count) { 'Failed' }
            elseif (@($results | Where-Object Readiness -eq 'Pending').Count) { 'Pending' } else { 'NeedsReview' }
        $results | Format-Table HostName, Platform, Definitions, Scan, LastScan, LastScanUtc -AutoSize -Wrap | Out-String -Width 240 | Write-Host
        Write-Host 'Scans run independently on endpoints. Repeat -Preflight for status/latest results; use -Rescan for a fresh scan. SEP completion still requires AV-log review.'
        if ($PassThru) { $results.ToArray() }
    } catch {
        $runSuccess = $false
        $runStatus = 'Failed'
        Write-MobileRunEvent -Run $run -Event 'RunError' -Data @{ Message = $_.Exception.Message }
        throw
    } finally {
        Write-MobileRunEvent -Run $run -Event 'RunCompleted' -Data @{ Success = $runSuccess; Status = $runStatus }
        Write-Host "[+] Preflight audit log: $($run.ReadablePath)"
    }
}

#endregion

#region Reporting

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
            @{ Header = 'IVANTI CORE'; Getter = { param($r) if ($r.Success -and $r.Summary.IvantiCoreServer) { $r.Summary.IvantiCoreServer } else { '-' } } }
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

function Format-DeploymentResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Results,

        [Parameter(Mandatory)]
        [array]$AllUsers,

        [switch]$Unregister
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

            $accountActions = @( $result.Actions | Where-Object { $_.Category -match 'User(Removal)?' -and $_.Name -in $accountNames }
            )

            #
            # We're intentionally collapsing Created/Existing
            # because deployment reporting only cares whether
            # the desired account state succeeded.
            #
            $status = if (-not $accountActions) {
                '-'
            } elseif ($accountActions.Status -contains 'Failed') { 'FAILED' } else { 'OK' }

            $password = if ($userDefs.MustChangePassword -contains $true) { 'DefaultPasswordSet' } else { 'UserSet' }
            if ($unRegister) { $password = ""}

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
    # Optional header row to visually anchor the columns
    Write-Host ("{0,-30} {1,-30} {2,-30}" -f "USER", "GROUPS", "PASSWORD") -ForegroundColor Gray

    $curUser = ""
    foreach ($uRow in $userRows | Sort-Object User) {
        if ($curUser -ne $uRow.User) {
            $curUser = $uRow.User

            # Safely truncate values exceeding 30 characters to prevent line wrapping/shifting
            $userCol   = if ($curUser.Length -gt 30) { $curUser.Substring(0, 27) + '...' } else { $curUser }
            $groupsCol = "[$($uRow.Groups)]"
            $groupsCol = if ($groupsCol.Length -gt 30) { $groupsCol.Substring(0, 27) + '...]' } else { $groupsCol }
            $passCol   = if ($uRow.Password.Length -gt 30) { $uRow.Password.Substring(0, 27) + '...' } else { $uRow.Password }

            $line = "{0,-30} {1,-30} {2,-30}" -f $userCol, $groupsCol, $passCol
            Write-Host $line -ForegroundColor DarkYellow
        }

        # Indent host status under the active user row
        if ($status -eq 'OK') {
            Write-Host ("  [+] {0}" -f $uRow.Host) -ForegroundColor Green
        } else {
            Write-Host ("  [-] {0}" -f $uRow.Host) -ForegroundColor Red
        }
    }

    # $userRows | Sort-Object Host, User | Format-Table Host, User, Groups, Status, Password -AutoSize

    #
    # DEPLOYMENT TASKS
    #
    $taskRows = foreach ($result in $Results) {

        $host = Get-ShortHostName $result.HostName

        [PSCustomObject]@{
            Host = $host

            # Privileges = Get-AggregateStatus  -Result $result  -Category 'Privilege'
            # NetworkSharing = Get-AggregateStatus -Result $result -Category 'NetworkSharing'

            LogArchiveTask = Get-AggregateStatus -Result $result -Category 'Task: LogArchive'
            # ScheduledTasks = Get-AggregateStatus  -Result $result  -Category 'ScheduledTask'

            Encryption = Get-AggregateStatus  -Result $result  -Category 'DiskEncryption'

            DomainDisjoin = if ($result.Platform -eq 'Windows') {
                Get-AggregateStatus -Result $result -Category 'Domain'
            } else {
                'N/A'
            }

            PostDisjoin = if ($result.Platform -eq 'Windows') {
                Get-AggregateStatus  -Result $result  -Category 'Task: Disjoin'
            } else {
                'N/A'
            }
        }
    }

    Write-Host ""
    Write-Host "[DEPLOYMENT TASKS]" -ForegroundColor Cyan

    $taskRows | Sort-Object Host | Format-Table -AutoSize
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

function Get-MobileOverview {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$MobileName,

        [Parameter()]
        [string]$defaultUsersPath = $Script:Config.mobileDefaultUsers,

        [Parameter()]
        [string]$mobileEntriesPath = $Script:Config.MobileEntries,

        [Parameter()]
        [string]$fallBackPass = $Script:Config.fallbackPass,

        [Parameter()]
        [string]$nfsHome = $Script:Config.NfsHome,

        [Parameter()]
        [string]$mobileDumpPath = $Script:Config.MobileDump,

        [Parameter()]
        [string]$sshKeyPath = $Script:Config.SSHKeyPath,

        [Parameter()]
        [switch]$Full
    )

    $data = Get-MobileData -MobileName $MobileName `
        -defaultUserpath $defaultUsersPath `
        -mobileEntriesPath $mobileEntriesPath `
        -fallbackPass $fallBackPass

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

#endregion

#region SMB deployment coordination

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

function Get-MobileSmbToolPath {
    $directories = if ($script:Config.Preflight.LinuxToolDirectories) { $script:Config.Preflight.LinuxToolDirectories } else { @('/usr/local/sbin','/usr/local/bin','/usr/sbin','/usr/bin','/sbin','/bin') }
    foreach ($directory in $directories) {
        if ([string]::IsNullOrWhiteSpace($directory) -or -not $directory.StartsWith('/') -or $directory -match '[:\r\n]') { throw 'Invalid Linux tool directory.' }
    }
    $directories -join ':'
}

function Get-LinuxMobileSmbInventory {
    $body = @'
ip -o -4 address show up scope global | awk '$4 ~ /^10\./ {print $2, $4}' | jq -Rn '[inputs | split(" ") | {InterfaceName:.[0],IPAddress:(.[1]|split("/")[0]),PrefixLength:(.[1]|split("/")[1]|tonumber)}] | {Interfaces:.}'
'@
    'export PATH=' + (ConvertTo-BashArgument (Get-MobileSmbToolPath)) + "`n" + $body
}

function Get-WindowsMobileSmbWorker {
    return {
        param([ValidateSet('Prepare','Activate','Restore','RestoreBoot','Status')][string]$Mode,
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
        function Set-BootTask([string]$ActionMode) {
            $worker = Join-Path $Root 'worker.ps1'
            $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $action = New-ScheduledTaskAction -Execute $shell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$worker`" -Mode $ActionMode -Root `"$Root`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            Register-ScheduledTask -TaskName $state.TaskName -Action $action -Trigger $trigger -Settings $settings -User SYSTEM -RunLevel Highest -Force | Out-Null
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
                if (Get-LocalUser -Name $Options.UserName -ErrorAction SilentlyContinue) { throw "SMB account '$($Options.UserName)' already exists; refusing to change an unowned password." }
                $adapter = Get-NetAdapter | Where-Object { $_.InterfaceGuid.ToString() -eq $Options.Interface.InterfaceGuid } | Select-Object -First 1
                if (-not $adapter) { throw 'Selected interface is no longer present.' }
                $index = $adapter.InterfaceIndex
                $ipInterface = Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4
                $dnsKey = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{$($Options.Interface.InterfaceGuid.Trim('{}'))}"
                Protect-Directory (Split-Path $Root -Parent)
                Protect-Directory $Root
                $state = [pscustomobject]@{ Status = 'Preparing'; UpdatedUtc = ''; Error = $null
                    UserName = $Options.UserName; UserSid = $null; AccountOwned = $false
                    Interface = $Options.Interface; OriginalDhcp = [string]$ipInterface.Dhcp
                    OriginalDnsStatic = [string]$dnsKey.NameServer
                    Shares = @(); AclDrives = @(); FirewallName = "Mobiles-Smb-$($Options.Id)"; TaskName = "Mobiles-Smb-$($Options.Id)" }
                Save-State
                $Options.Worker | Set-Content -LiteralPath (Join-Path $Root 'worker.ps1') -Encoding UTF8
                New-LocalUser -Name $state.UserName -Password $Credential.Password -Description 'Mobile deployment SMB access' -AccountNeverExpires -PasswordNeverExpires | Out-Null
                $state.UserSid = (Get-LocalUser -Name $state.UserName).SID.Value
                $state.AccountOwned = $true
                Save-State
                # The account gets network logon, but cannot log on interactively.
                $inf = Join-Path $Root 'rights.inf'; $db = Join-Path $Root 'rights.sdb'
                & secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Could not read local logon rights.' }
                $cfg = Get-Content -LiteralPath $inf -Raw
                foreach ($right in @('SeNetworkLogonRight','SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight')) {
                    $pattern = '(?m)^' + $right + '\s*=\s*([^\r\n]*)'
                    $match = [regex]::Match($cfg, $pattern)
                    $values = if ($match.Success -and $match.Groups[1].Value.Trim()) { $match.Groups[1].Value.Trim() + ',' } else { '' }
                    $line = "$right = $values*$($state.UserSid)"
                    if ($match.Success) { $cfg = $cfg.Remove($match.Index, $match.Length).Insert($match.Index, $line) }
                    else { $cfg += "`r`n$line`r`n" }
                }
                $cfg | Set-Content -LiteralPath $inf -Encoding Unicode
                & secedit /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Could not set SMB account logon rights.' }
                foreach ($drive in $Options.Drives) {
                    $path = "${drive}:\"
                    $existing = Get-SmbShare -Name $drive -ErrorAction SilentlyContinue
                    if ($existing -and $existing.Path -ine $path) { throw "Share '$drive' already points somewhere else." }
                    $state.Shares += [pscustomobject]@{ Name = $drive; Created = (-not [bool]$existing) }
                    $state.AclDrives += $drive
                    Save-State # Write intent before changing each resource, so partial preparation is recoverable.
                    $acl = Get-Acl -LiteralPath $path
                    $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($state.UserSid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
                    $acl.AddAccessRule($rule)
                    Set-Acl -LiteralPath $path -AclObject $acl
                    $account = "$env:COMPUTERNAME\$($state.UserName)"
                    if ($existing) { Grant-SmbShareAccess -Name $drive -AccountName $account -AccessRight Full -Force | Out-Null }
                    else { New-SmbShare -Name $drive -Path $path -FullAccess $account | Out-Null }
                }
                New-NetFirewallRule -Name $state.FirewallName -DisplayName 'Mobile SMB access' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -RemoteAddress '10.0.0.0/8' -Profile Any | Out-Null
                Set-BootTask Activate
                $state.Status = 'PreparedPendingReboot'
            } elseif ($Mode -eq 'Activate') {
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
            } elseif ($Mode -eq 'Restore') {
                if (-not $state -or $state.Status -eq 'Restored') { return $state }
                foreach ($share in $state.Shares) {
                    $existing = Get-SmbShare -Name $share.Name -ErrorAction SilentlyContinue
                    if (-not $existing) { continue }
                    if ($existing.Path -ine "$($share.Name):\") { throw "Share '$($share.Name)' changed outside deployment; inspect before cleanup." }
                    if ($share.Created) { Remove-SmbShare -Name $share.Name -Force }
                    else { Revoke-SmbShareAccess -Name $share.Name -AccountName "$env:COMPUTERNAME\$($state.UserName)" -Force }
                }
                if ($state.UserSid) {
                    foreach ($drive in $state.AclDrives) {
                        $path = "${drive}:\"; $acl = Get-Acl -LiteralPath $path
                        $acl.PurgeAccessRules([Security.Principal.SecurityIdentifier]::new($state.UserSid))
                        Set-Acl -LiteralPath $path -AclObject $acl
                    }
                }
                if ($state.UserSid) {
                    $inf = Join-Path $Root 'rights.inf'; $db = Join-Path $Root 'rights.sdb'
                    & secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw 'Could not read logon rights for cleanup.' }
                    $cfg = Get-Content -LiteralPath $inf -Raw
                    $sidToken = "*$($state.UserSid)"
                    $cfg = [regex]::Replace($cfg, '(?m)^(Se\w+Right\s*=\s*)([^\r\n]*)', {
                        param($match)
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
                Get-NetFirewallRule -Name $state.FirewallName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
                Set-BootTask RestoreBoot
                $state.Status = 'RestorePendingReboot'
            } elseif ($Mode -eq 'RestoreBoot') {
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
            Save-State
            $state
        } catch {
            if ($state) { $state.Error = $_.Exception.Message; if ($Mode -eq 'Activate') { $state.Status = 'ActivationFailed' }; Save-State }
            throw
        } finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
    }
}

function Get-LinuxMobileSmbWorker {
    return @'
#!/bin/bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mobile_smb_main() {
    mode="$1"; root="$2"
    umask 077
    if [[ -L /var/lib/mobiles || -L /var/lib/mobiles/smb || -L "$root" ]]; then echo 'Refusing a redirected SMB state directory' >&2; exit 2; fi
    if [[ -e "$root" && ! -O "$root" ]]; then echo 'SMB state directory is not owned by this privileged account' >&2; exit 2; fi
    mkdir -p "$root"
    chmod 700 "$root"
    exec 9>/run/lock/mobiles-smb.lock
    if [[ "$mode" != Status ]]; then flock -n 9 || { echo 'Another SMB operation is in progress' >&2; exit 2; }; fi
    [[ ! -f "$root/environment.sh" ]] || source "$root/environment.sh"
    state="$root/state.json"
    save_status() {
        jq --arg status "$1" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.Status=$status | .UpdatedUtc=$now' "$state" > "$state.tmp"
        mv -f "$state.tmp" "$state"
        jq -c . "$state" >> "$root/history.jsonl"
    }
    failed() {
        code=$?
        trap - ERR
        if [[ -f "$state" ]]; then save_status "${mode}Failed"; fi
        echo "SMB $mode failed; inspect $root and journalctl -u mobiles-smb-$(basename "$root")" >&2
        exit "$code"
    }
    trap failed ERR
    trap 'exit 143' TERM
    trap 'code=$?; if (( code != 0 )); then trap - EXIT; [[ ! -f "$state" ]] || save_status "${mode}Failed"; fi' EXIT
    if [[ "$mode" == Status ]]; then
        if [[ -f "$state" ]]; then cat "$state"; else printf '{"Status":"NotPrepared"}\n'; fi
        return
    fi
    if [[ "$mode" == Prepare ]]; then
        if [[ -f "$state" ]] && [[ "$(jq -r .Status "$state")" != Restored ]]; then echo 'SMB state already exists; inspect/check in before preparing again' >&2; exit 2; fi
        for tool in jq nmcli ip mount.cifs findmnt grubby systemctl systemd-escape flock; do command -v "$tool" >/dev/null || { echo "SMB requires $tool; PATH=$PATH" >&2; exit 2; }; done
        [[ -n "${payload_b64:-}" ]] || { echo 'Missing SMB preparation payload' >&2; exit 2; }
        payload="$(printf '%s' "$payload_b64" | base64 -d)"
        printf '%s' "$payload" | jq 'del(.Password,.Worker)' > "$root/options.json"
        iface="$(jq -r .Interface.InterfaceName "$root/options.json")"
        address="$(jq -r '.Interface | .IPAddress+"/"+(.PrefixLength|tostring)' "$root/options.json")"
        # Match the active NetworkManager connection by device; do not choose a similarly named profile.
        original_uuid="$(nmcli -t -f UUID,DEVICE connection show --active | awk -F: -v dev="$iface" '$2==dev {print $1}')"
        [[ "$original_uuid" =~ ^[a-fA-F0-9-]{36}$ ]] || { echo 'Selected interface requires one active NetworkManager profile' >&2; exit 2; }
        ip -o -4 addr show dev "$iface" | awk -v address="$address" '$4==address {found=1} END {exit !found}'
        id="$(basename "$root")"; unit="mobiles-smb-$id.service"
        mobile_name="mobiles-smb-$id"
        getent group "$(jq -r .LinuxGroup "$root/options.json")" >/dev/null || { echo 'Configured SMBLinuxGroup does not exist' >&2; exit 2; }
        [[ -z "$(nmcli -t -f NAME connection show | grep -Fx "$mobile_name" || true)" ]] || { echo 'Mobile connection name already exists' >&2; exit 2; }
        fips_before="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)"
        normal_kernel="$(grubby --default-kernel)"
        jq -n --arg original "$original_uuid" --arg iface "$iface" --arg unit "$unit" --arg profile "$mobile_name" \
            --arg kernel "$normal_kernel" --arg fips "$fips_before" \
            '{Status:"Preparing",OriginalConnection:$original,InterfaceName:$iface,Unit:$unit,MobileConnection:$profile,OriginalKernel:$kernel,OriginalFips:$fips,MobileKernel:null,MobileInitrd:null,CreatedMountPoints:[],AddedGroupMembers:[],MountDropIns:[],Mounts:[]}' > "$state"
        printf '%s' "$payload" | jq -r .Worker > "$root/worker.sh"
        printf 'export PATH=%q\n' "$PATH" > "$root/environment.sh"
        chmod 700 "$root/worker.sh"
        while IFS= read -r mount_row; do
            host="$(printf '%s' "$mount_row" | jq -r .HostName)"
            target="$(printf '%s' "$mount_row" | jq -r .MountPoint)"
            if [[ -L /share || -L "/share/$host" || -L "$target" ]] || findmnt -rn --mountpoint "$target" >/dev/null; then echo "Unsafe or mounted target $target" >&2; exit 2; fi
            if [[ -e "$target" && ! -d "$target" ]]; then echo "Non-directory target $target" >&2; exit 2; fi
            if [[ -d "$target" ]] && [[ -n "$(ls -A "$target")" ]]; then echo "Mount point $target is not empty" >&2; exit 2; fi
            for directory in /share "/share/$host" "$target"; do
                if [[ ! -d "$directory" ]]; then
                    jq --arg path "$directory" '.CreatedMountPoints += [$path]' "$state" > "$state.tmp"; mv -f "$state.tmp" "$state"
                    mkdir "$directory"
                fi
            done
            mount_unit="$(systemd-escape --path --suffix=mount "$target")"
            drop_in="/etc/systemd/system/$mount_unit.d/50-mobiles-$id.conf"
            [[ ! -e "$drop_in" ]]
            jq --arg path "$drop_in" '.MountDropIns += [$path]' "$state" > "$state.tmp"; mv -f "$state.tmp" "$state"
            mkdir -p "$(dirname "$drop_in")"
            printf '[Mount]\nTimeoutSec=30\n' > "$drop_in"
            credential="$root/credentials-$host"
            printf 'username=%s\npassword=%s\ndomain=%s\n' "$(printf '%s' "$payload" | jq -r .UserName)" "$(printf '%s' "$payload" | jq -r .Password)" "$(printf '%s' "$mount_row" | jq -r ' .CredentialDomain // .HostName')" > "$credential"
            chmod 600 "$credential"
        done < <(jq -c '.Mounts[]' "$root/options.json")
        unset payload payload_b64
        nmcli connection clone uuid "$original_uuid" "$mobile_name" >/dev/null
        nmcli connection modify id "$mobile_name" ipv4.method manual ipv4.addresses "$address" ipv4.gateway '' ipv4.routes '' ipv4.dns '' ipv4.ignore-auto-dns yes ipv4.never-default yes connection.autoconnect no
        # Keep the original profile unchanged; activate the mobile clone only at boot.
        if [[ "$fips_before" == 1 ]]; then
            grubby --info=ALL > "$root/kernel-entries.before"
            info="$(grubby --info=DEFAULT)"
            initrd="$(printf '%s\n' "$info" | sed -n 's/^initrd="\(.*\)"$/\1/p')"
            [[ -f "$normal_kernel" && -f "$initrd" ]] || { echo 'Default kernel/initrd could not be resolved to files' >&2; exit 2; }
            mobile_kernel="/boot/vmlinuz-mobiles-$id"; mobile_initrd="/boot/initramfs-mobiles-$id.img"
            [[ ! -e "$mobile_kernel" && ! -e "$mobile_initrd" ]]
            jq --arg kernel "$mobile_kernel" --arg initrd "$mobile_initrd" '.MobileKernel=$kernel | .MobileInitrd=$initrd' "$state" > "$state.tmp"; mv -f "$state.tmp" "$state"
            # Distinct image paths let grubby remove ONLY the mobile entry, even with the same kernel version.
            cp -p -- "$normal_kernel" "$mobile_kernel"
            cp -p -- "$initrd" "$mobile_initrd"
            if command -v restorecon >/dev/null; then restorecon "$mobile_kernel" "$mobile_initrd"; fi
            grubby --add-kernel="$mobile_kernel" --initrd="$mobile_initrd" --copy-default --title="Mobile SMB $id" --remove-args='fips' --args='fips=0'
            info="$(grubby --info="$mobile_kernel")"
            printf '%s\n' "$info" | grep -q 'fips=0'
            if printf '%s\n' "$info" | grep -q 'fips=1'; then echo 'Mobile entry still enforces FIPS' >&2; exit 2; fi
            grubby --set-default="$mobile_kernel"
        fi
        cat > "/etc/systemd/system/$unit" <<UNIT
[Unit]
Description=Mobile SMB network and mounts
After=NetworkManager.service network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/timeout 300 /bin/bash $root/worker.sh Activate $root
RemainAfterExit=yes
TimeoutStartSec=300
[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable "$unit" >/dev/null
        save_status PreparedPendingReboot
    else
        [[ -f "$state" ]] || { echo 'No saved SMB state' >&2; exit 2; }
        unit="$(jq -r .Unit "$state")"
        original_uuid="$(jq -r .OriginalConnection "$state")"
        mobile_name="$(jq -r .MobileConnection "$state")"
        if [[ "$mode" == Activate ]]; then
            status="$(jq -r .Status "$state")"
            [[ "$status" == PreparedPendingReboot || "$status" == Active || "$status" == Activating || "$status" == ActivateFailed ]]
            save_status Activating
            [[ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)" == 0 ]] || { echo 'FIPS remains enforced; SMB activation blocked' >&2; exit 2; }
            nmcli connection modify id "$mobile_name" connection.autoconnect yes connection.autoconnect-priority 999
            nmcli connection up id "$mobile_name" >/dev/null
            group="$(jq -r .LinuxGroup "$root/options.json")"
            while IFS= read -r local_user; do
                awk -F: -v user="$local_user" '$1==user {found=1} END {exit !found}' /etc/passwd
                if ! id -nG "$local_user" | tr ' ' '\n' | grep -Fxq "$group"; then
                    jq --arg user "$local_user" '.AddedGroupMembers += [$user] | .AddedGroupMembers |= unique' "$state" > "$state.tmp"; mv -f "$state.tmp" "$state"
                    usermod -aG "$group" "$local_user"
                fi
            done < <(jq -r '.LinuxUsers[]' "$root/options.json")
            # Replace only our own managed block; keep the fstab inode, ownership and SELinux label.
            id="$(basename "$root")"
            awk -v begin="# BEGIN MOBILES SMB $id" -v end="# END MOBILES SMB $id" '$0==begin {skip=1;next} $0==end {skip=0;next} !skip' /etc/fstab > "$root/fstab.base"
            cp "$root/fstab.base" "$root/fstab.new"
            printf '\n# BEGIN MOBILES SMB %s\n' "$id" >> "$root/fstab.new"
            while IFS= read -r mount_row; do
                source="$(printf '%s' "$mount_row" | jq -r .Source)"
                target="$(printf '%s' "$mount_row" | jq -r .MountPoint)"
                host="$(printf '%s' "$mount_row" | jq -r .HostName)"
                # All components are validated controller-side; the address is numeric, never DNS.
                printf '%s %s cifs credentials=%s/credentials-%s,sec=ntlmssp,vers=3.0,_netdev,nofail,x-systemd.device-timeout=15s,file_mode=0660,dir_mode=0770,gid=%s 0 0\n' \
                    "$source" "$target" "$root" "$host" "$(jq -r .LinuxGroup "$root/options.json")" >> "$root/fstab.new"
            done < <(jq -c '.Mounts[]' "$root/options.json")
            printf '# END MOBILES SMB %s\n' "$id" >> "$root/fstab.new"
            getent group "$(jq -r .LinuxGroup "$root/options.json")" >/dev/null
            # Refuse conflicts with user-maintained mount entries.
            while IFS= read -r target; do
                if awk -v target="$target" '$1 !~ /^#/ && $2==target {found=1} END {exit !found}' "$root/fstab.base"; then echo "Existing fstab entry for $target" >&2; exit 2; fi
            done < <(jq -r '.Mounts[].MountPoint' "$root/options.json")
            cp -p /etc/fstab "$root/fstab.before-activation"
            cat "$root/fstab.new" > /etc/fstab
            systemctl daemon-reload
            jq '.Mounts=[]' "$state" > "$state.tmp"; mv -f "$state.tmp" "$state"
            had_failure=false
            while IFS= read -r mount_row; do
                target="$(printf '%s' "$mount_row" | jq -r .MountPoint)"
                success=false
                mounted=false
                source="$(printf '%s' "$mount_row" | jq -r .Source)"
                if findmnt -rn --mountpoint "$target" >/dev/null; then
                    if [[ "$(findmnt -rn --mountpoint "$target" -o SOURCE)" == "$source" ]]; then mounted=true; fi
                elif timeout 40 mount "$target"; then mounted=true; fi
                if [[ "$mounted" == true ]]; then
                    if timeout 15 /bin/bash -c 'probe="$(mktemp "$1/.mobiles-write-test-XXXXXXXXXX")" && rm -- "$probe"' _ "$target"; then success=true; fi
                fi
                jq --arg target "$target" --argjson success "$success" '.Mounts += [{MountPoint:$target,Success:$success}]' "$state" > "$state.tmp"; mv -f "$state.tmp" "$state"
                [[ "$success" == true ]] || had_failure=true
            done < <(jq -c '.Mounts[]' "$root/options.json")
            [[ "$had_failure" == false ]]
            save_status Active
        elif [[ "$mode" == Restore ]]; then
            [[ "$(jq -r .Status "$state")" != Restored ]] || { cat "$state"; return; }
            save_status Restoring
            # Abort if a mount is busy. Never use lazy/forced unmount for deployment data.
            while IFS= read -r mount_row; do
                target="$(printf '%s' "$mount_row" | jq -r .MountPoint)"
                source="$(printf '%s' "$mount_row" | jq -r .Source)"
                if findmnt -rn --mountpoint "$target" >/dev/null; then
                    [[ "$(findmnt -rn --mountpoint "$target" -o SOURCE)" == "$source" ]] || { echo "Unexpected mount at $target" >&2; exit 2; }
                    umount "$target"
                fi
            done < <(jq -c '.Mounts[]' "$root/options.json")
            id="$(basename "$root")"
            awk -v begin="# BEGIN MOBILES SMB $id" -v end="# END MOBILES SMB $id" '$0==begin {skip=1;next} $0==end {skip=0;next} !skip' /etc/fstab > "$root/fstab.new"
            cat "$root/fstab.new" > /etc/fstab
            while IFS= read -r local_user; do
                if awk -F: -v user="$local_user" '$1==user {found=1} END {exit !found}' /etc/passwd; then
                    if id -nG "$local_user" | tr ' ' '\n' | grep -Fxq "$(jq -r .LinuxGroup "$root/options.json")"; then gpasswd -d "$local_user" "$(jq -r .LinuxGroup "$root/options.json")" >/dev/null; fi
                fi
            done < <(jq -r '.AddedGroupMembers[]' "$state")
            while IFS= read -r drop_in; do
                rm -f -- "$drop_in"
                rmdir -- "$(dirname "$drop_in")" 2>/dev/null || true
            done < <(jq -r '.MountDropIns[]' "$state")
            rm -f -- "$root"/credentials-*
            mobile_kernel="$(jq -r '.MobileKernel // empty' "$state")"
            if [[ -n "$mobile_kernel" ]]; then
                current_default="$(grubby --default-kernel)"
                if [[ "$current_default" == "$mobile_kernel" ]]; then
                    normal_kernel="$(jq -r .OriginalKernel "$state")"
                    # Kernel updates may remove the checkout default. Select the newest normal entry in boot order then.
                    if [[ ! -f "$normal_kernel" ]] || ! grubby --info="$normal_kernel" >/dev/null 2>&1; then
                        normal_kernel="$(grubby --info=ALL | sed -n 's/^kernel="\(.*\)"$/\1/p' | grep -v '/vmlinuz-mobiles-' | while IFS= read -r path; do [[ ! -f "$path" ]] || { printf '%s\n' "$path"; break; }; done)"
                    fi
                    [[ -n "$normal_kernel" && -f "$normal_kernel" ]] || { echo 'No normal kernel available for restoration' >&2; exit 2; }
                    grubby --set-default="$normal_kernel"
                fi
                normal_kernel="$(grubby --default-kernel)"
                if [[ "$(jq -r .OriginalFips "$state")" == 1 ]]; then
                    grubby --update-kernel="$normal_kernel" --remove-args='fips' --args='fips=1'
                    # New packaged entries can inherit the mobile default's fips=0 during updates.
                    while IFS= read -r path; do
                        [[ "$path" != *'/vmlinuz-mobiles-'* && -f "$path" ]] || continue
                        if ! grep -Fxq "kernel=\"$path\"" "$root/kernel-entries.before"; then grubby --update-kernel="$path" --remove-args='fips' --args='fips=1'; fi
                    done < <(grubby --info=ALL | sed -n 's/^kernel="\(.*\)"$/\1/p')
                fi
                if grubby --info="$mobile_kernel" >/dev/null 2>&1; then grubby --remove-kernel="$mobile_kernel"; fi
                rm -f -- "$mobile_kernel" "$(jq -r .MobileInitrd "$state")"
            fi
            # The next boot restores the untouched original NM profile, so SSH stays up for cleanup now.
            cat > "/etc/systemd/system/$unit" <<UNIT
[Unit]
Description=Restore mobile network configuration
After=NetworkManager.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash $root/worker.sh RestoreBoot $root
RemainAfterExit=yes
TimeoutStartSec=300
[Install]
WantedBy=multi-user.target
UNIT
            systemctl daemon-reload
            systemctl enable "$unit" >/dev/null
            save_status RestorePendingReboot
        elif [[ "$mode" == RestoreBoot ]]; then
            nmcli connection up uuid "$original_uuid" >/dev/null
            if nmcli connection show id "$mobile_name" >/dev/null 2>&1; then nmcli connection delete id "$mobile_name" >/dev/null; fi
            [[ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)" == "$(jq -r .OriginalFips "$state")" ]] || { echo 'Original FIPS enforcement has not been restored' >&2; exit 2; }
            while IFS= read -r target; do rmdir -- "$target" 2>/dev/null || true; done < <(jq -r '.CreatedMountPoints | reverse[]' "$state")
            systemctl disable "$unit" >/dev/null
            rm -f -- "/etc/systemd/system/$unit"
            systemctl daemon-reload
            save_status Restored
        else
            echo 'Unknown SMB worker mode' >&2; exit 2
        fi
    fi
    cat "$state"
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then mobile_smb_main "$@"; fi
'@
}

function Get-LinuxMobileSmbScript {
    param([Parameter(Mandatory)][ValidateSet('Prepare','Restore','Status')][string]$Mode,
        [Parameter(Mandatory)][string]$Id, $Options, [pscredential]$Credential)
    if ($Id -notmatch '^[a-f0-9]{20}$') { throw 'Invalid SMB deployment state ID.' }
    $root = "/var/lib/mobiles/smb/$Id"
    $prefix = "export PATH=$(ConvertTo-BashArgument (Get-MobileSmbToolPath))`n"
    if ($Mode -eq 'Prepare') {
        $Options | Add-Member -NotePropertyName Password -NotePropertyValue $Credential.GetNetworkCredential().Password -Force
        $Options | Add-Member -NotePropertyName Worker -NotePropertyValue (Get-LinuxMobileSmbWorker) -Force
        try { $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Options | ConvertTo-Json -Depth 12 -Compress))) }
        finally { $Options.PSObject.Properties.Remove('Password'); $Options.PSObject.Properties.Remove('Worker') }
        # Source definitions, rather than running the script's CLI footer during preparation.
        $worker = (Get-LinuxMobileSmbWorker) -replace '(?m)^if \[\[ "\$\{BASH_SOURCE\[0\]\}" == "\$0" \]\]; then mobile_smb_main "\$@"; fi\s*$', ''
        $body = $prefix + "payload_b64='$payload'`n" + $worker + "`n" + $prefix + "mobile_smb_main Prepare '$root'"
    } else {
        $body = $prefix + "if [[ -f '$root/worker.sh' ]]; then /bin/bash '$root/worker.sh' $Mode '$root'; else printf '{`"Status`":`"NotPrepared`"}\n'; fi"
    }
    $delimiter = 'MOBILE_SMB_' + [guid]::NewGuid().ToString('N')
    "dzdo bash <<'$delimiter'`n$body`n$delimiter`n"
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
            if ($inventory[0].AccountExists) { throw "SMB account '$userName' already exists on $computer. No passwords were changed." }
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
            $options = [pscustomobject]@{ Id = $plan.Id; UserName = $userName; Interface = $hostInfo.Interface; Drives = $hostInfo.Drives; Worker = (Get-WindowsMobileSmbWorker).ToString() }
            $root = "C:\ProgramData\Mobiles\Smb\$($plan.Id)"
            $result = Invoke-Command -ComputerName $hostInfo.HostName -ScriptBlock (Get-WindowsMobileSmbWorker) -ArgumentList 'Prepare', $root, $options, $SmbCredential -ErrorAction Stop
            if ($result.Status -ne 'PreparedPendingReboot') { throw "SMB preparation did not complete on $($hostInfo.HostName)." }
            $hostInfo.Status = $result.Status
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
        $runner = { param($Hooks, $Runner, $MobileName, $RunId)
            & ([scriptblock]::Create($Runner)) -Hooks $Hooks -MobileName $MobileName -Procedure 'Check-in' -RunId $RunId }
        $result = Invoke-Command -ComputerName $hostInfo.Interface.IPAddress -ScriptBlock $runner -ArgumentList $WindowsHooks, (Get-WindowsProcedureHookRunner).ToString(), $Plan.MobileName, $Run.Id -ErrorAction Stop
        Write-MobileRunEvent -Run $Run -Event 'HostResult' -Data @{ HostName = $hostInfo.HostName; Platform = 'Windows'; Success = (-not $result.Failures.Count); Actions = $result.Actions; Failures = $result.Failures }
        if ($result.Failures.Count) { throw "Check-in hooks failed on $($hostInfo.HostName); SMB cleanup was not started." }
    }
    foreach ($hostInfo in $Plan.Linux) {
        if (-not $LinuxHooks.Count) { break }
        $header = @'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -o pipefail
actions_json=(); failures=()
record_failure() { failures+=("$1"); }
record_action() { actions_json+=("$(jq -cn --arg category "$1" --arg name "$2" --arg status "$3" '{Category:$category,Name:$name,Status:$status}')"); }
'@
        $footer = @'
jq -n --argjson actions "[$(IFS=,; echo "${actions_json[*]}")]" --argjson failures "$(printf '%s\n' "${failures[@]}" | jq -R . | jq -s 'map(select(length>0))')" '{Actions:$actions,Failures:$failures}'
'@
        $scriptText = $header + "`nexport PATH=" + (ConvertTo-BashArgument (Get-MobileSmbToolPath)) + "`n" + (Get-LinuxProcedureHookScript -Hooks $LinuxHooks -MobileName $Plan.MobileName -Procedure Check-in -RunId $Run.Id) + "`n" + $footer
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
        Save-MobileSmbPlan $Plan
        Write-MobileRunEvent -Run $Run -Event 'SmbRestored' -Data @{ HostName = $hostInfo.HostName; Platform = 'Linux'; State = $result }
    }
    foreach ($hostInfo in $Plan.Windows) {
        $root = "C:\ProgramData\Mobiles\Smb\$($Plan.Id)"
        $result = Invoke-Command -ComputerName $hostInfo.Interface.IPAddress -ScriptBlock (Get-WindowsMobileSmbWorker) -ArgumentList 'Restore', $root -ErrorAction Stop
        if ($result.Status -notin @('RestorePendingReboot','Restored') -and $null -ne $result) { throw "SMB restoration incomplete on $($hostInfo.HostName)." }
        $hostInfo.Status = if ($result) { $result.Status } else { 'NotPrepared' }
        Save-MobileSmbPlan $Plan
        Write-MobileRunEvent -Run $Run -Event 'SmbRestored' -Data @{ HostName = $hostInfo.HostName; Platform = 'Windows'; State = $result }
    }
    $Plan.Status = 'RestorePendingReboot'
    Save-MobileSmbPlan $Plan
    Write-Host '[+] SMB cleanup staged. Reboot all hosts to restore original networking and Linux FIPS enforcement; query -SmbStatus afterward.'
}

function Show-MobileSmbStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$MobileName)
    $plan = Read-MobileSmbPlan $MobileName
    if (-not $plan) { throw "No saved SMB deployment for '$MobileName'." }
    $run = New-MobileRunLog -MobileName $MobileName -Procedure 'SMB-Status'
    $states = @(
        foreach ($hostInfo in $plan.Windows) {
            try {
                $root = "C:\ProgramData\Mobiles\Smb\$($plan.Id)"
                try { $state = Invoke-Command -ComputerName $hostInfo.HostName -ScriptBlock (Get-WindowsMobileSmbWorker) -ArgumentList 'Status', $root -ErrorAction Stop }
                catch { $state = Invoke-Command -ComputerName $hostInfo.Interface.IPAddress -ScriptBlock (Get-WindowsMobileSmbWorker) -ArgumentList 'Status', $root -ErrorAction Stop }
                [pscustomobject]@{ HostName = $hostInfo.HostName; IPAddress = $hostInfo.Interface.IPAddress; Platform = 'Windows'; Status = $state.Status; Details = $state }
            } catch { [pscustomobject]@{ HostName = $hostInfo.HostName; IPAddress = $hostInfo.Interface.IPAddress; Platform = 'Windows'; Status = 'Unreachable'; Details = $_.Exception.Message } }
        }
        foreach ($hostInfo in $plan.Linux) {
            try {
                $raw = @(Invoke-Linux -Computers @($hostInfo.HostName) -Script (Get-LinuxMobileSmbScript -Mode Status -Id $plan.Id) -KeyPath $script:Config.SSHKeyPath)
                if ($raw.Count -ne 1 -or $raw[0].ExitCode -ne 0) { $raw = @(Invoke-Linux -Computers @($hostInfo.Interface.IPAddress) -Script (Get-LinuxMobileSmbScript -Mode Status -Id $plan.Id) -KeyPath $script:Config.SSHKeyPath) }
                if ($raw.Count -ne 1) { throw 'No response.' }
                $state = ConvertFrom-MobileSmbLinuxResult $raw[0]
                [pscustomobject]@{ HostName = $hostInfo.HostName; IPAddress = $hostInfo.Interface.IPAddress; Platform = 'Linux'; Status = $state.Status; Details = $state }
            } catch { [pscustomobject]@{ HostName = $hostInfo.HostName; IPAddress = $hostInfo.Interface.IPAddress; Platform = 'Linux'; Status = 'Unreachable'; Details = $_.Exception.Message } }
        }
    )
    if ($states.Count -and @($states | Where-Object Status -ne Restored).Count -eq 0) { $plan.Status = 'Restored'; Save-MobileSmbPlan $plan }
    foreach ($state in $states) { Write-MobileRunEvent -Run $run -Event 'SmbStatus' -Data $state }
    Write-MobileRunEvent -Run $run -Event 'RunCompleted' -Data @{ Success = (@($states | Where-Object { $_.Status -notin @('Active','Restored') }).Count -eq 0) }
    Write-Host "[+] SMB status audit log: $($run.ReadablePath)"
    $states
}

#endregion

#region Deployment commands

function Register-MobileDeployment {
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
        [string]$nfsHome       = $Script:Config.NfsHome,
        [string[]]$SmbHosts,
        [pscredential]$SmbCredential,
        [switch]$Disjoin,
        [string]$LinuxDisjoinKeytab,
        [string]$DomainController,
        [string]$DomainPrincipal,
        [int]$DomainKeyVersion = 0
    )

    $run = New-MobileRunLog -MobileName $MobileName -Procedure 'Check-out'
    $runSuccess = $false
    try {
        $hooks = @(Get-MobileProcedureHooks -Procedure 'Check-out')
        Write-MobileRunEvent -Run $run -Event 'HookInventory' -Data @($hooks | Select-Object Name, Platform, Sha256)
        $windowsHooks = @($hooks | Where-Object Platform -eq 'Windows')
        $linuxHooks = @($hooks | Where-Object Platform -eq 'Linux')
        Write-MobileRunEvent -Run $run -Event 'TaskSelection' -Data $script:Config.DeploymentTasks
        $provisioningTasks = @(Get-DeploymentTaskSelection -Platform Windows -Phase Provisioning)
        $mobileData = Get-MobileData -MobileName $MobileName
        Write-MobileRunEvent -Run $run -Event 'Targets' -Data @{ Windows = @($mobileData.Windows); Linux = @($mobileData.Linux) }
        if ($Disjoin -and $mobileData.Linux.Count -gt 0) {
            $LinuxDisjoinKeytab = Resolve-LinuxDisjoinKeytab -Keytab $LinuxDisjoinKeytab `
                -DomainController $DomainController -Principal $DomainPrincipal -Kvno $DomainKeyVersion
        }
        Write-MobileRunEvent -Run $run -Event 'PreflightStarted' -Data $null
        if (-not (Initialize-Environment)) { throw "Failed to properly initialize environment!" }
        Write-MobileRunEvent -Run $run -Event 'PreflightCompleted' -Data @{ Success = $true }
        $sharingEnabled = 'NetworkSharing' -in @(Get-DeploymentTaskSelection -Platform Windows -Phase PostDeployment)
        if ($SmbHosts -and -not $sharingEnabled) { throw '-SmbHosts requires NetworkSharing in DeploymentTasks.Windows.PostDeployment.' }
        if ($sharingEnabled -and @($mobileData.Windows).Count) {
            $smbPlan = Initialize-MobileSmbDeployment -MobileData $mobileData -MobileName $MobileName -SmbHosts $SmbHosts -SmbCredential $SmbCredential -Run $run
        }
        $mobileData.AllUsers  = Get-UserCreds -MobileName $MobileName -AllUsers $mobileData.AllUsers -mobileDumpPath $mobileDump
        $taskData = @()
        if (@($mobileData.Windows).Count -gt 0) {
            $taskData = @(Get-TaskData -hasLinux:$($mobileData.Linux.Count -gt 0))
        }


        $windowsPayload = [PSCustomObject]@{
            allUsers = @($mobileData.AllUsers)
            taskData = @($taskData)
            MobileName = $MobileName
            Disjoin = $disJoin
            Bitlocker = $defaultPin
            ProvisioningTasks = $provisioningTasks
            Hooks = $windowsHooks
            HookRunner = (Get-WindowsProcedureHookRunner).ToString()
            Procedure = 'Check-out'
            RunId = $run.Id

        }

        $winErrors = [System.Collections.Generic.List[object]]::new()
        $rawWindows = @()
        if (@($mobileData.Windows).Count -gt 0) {
            $rawWindows = Invoke-Command `
                -ComputerName $mobileData.Windows `
                -ScriptBlock $Script:WindowsDeployBlock `
                -ArgumentList $windowsPayload `
                -ErrorVariable winErrors `
                -ErrorAction SilentlyContinue
        }


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

            if ($alreadyReturned) { continue }

            $hostErrors = @(
                $winErrors |
                    Where-Object {
                        $_.TargetObject -eq $computer -or
                        $_.OriginInfo.PSComputerName -eq $computer
                    }
            )

            $messages = if ($hostErrors) {
                @($hostErrors | ForEach-Object { $_.Exception.Message })
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
        foreach ($result in $winResults) { Write-MobileRunEvent -Run $run -Event 'HostResult' -Data $result }

        if ($mobileData.Linux.Count -gt 0) {
            $linSplat = @{ allUsers = $mobileData.AllUsers; Hooks = $linuxHooks; MobileName = $MobileName; RunId = $run.Id }
            if ($disjoin) {
                $linSplat['disjoin'] = $true
                $linSplat['b64kt'] = $LinuxDisjoinKeytab
            }
            $linuxDeploy = Get-LinuxDeployScript @linSplat
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
        foreach ($result in $linResults) { Write-MobileRunEvent -Run $run -Event 'HostResult' -Data $result }
        $runSuccess = ($results.Count -gt 0 -and @($results | Where-Object { -not $_.Success }).Count -eq 0)
        Format-DeploymentResults -results $results -allUsers $mobileData.AllUsers
    } catch {
        $runSuccess = $false
        Write-MobileRunEvent -Run $run -Event 'RunError' -Data @{ Message = $_.Exception.Message }
        throw
    } finally {
        Write-MobileRunEvent -Run $run -Event 'RunCompleted' -Data @{ Success = $runSuccess }
        Write-Host "[+] Check-out audit log: $($run.ReadablePath)"
        Write-Verbose "Structured audit log: $($run.Path)"
    }

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
        [Parameter()]
        [switch]$archive
    )
    $run = New-MobileRunLog -MobileName $MobileName -Procedure 'Check-in'
    $runSuccess = $false
    try {
        $hooks = @(Get-MobileProcedureHooks -Procedure 'Check-in')
        Write-MobileRunEvent -Run $run -Event 'HookInventory' -Data @($hooks | Select-Object Name, Platform, Sha256)
        $windowsHooks = @($hooks | Where-Object Platform -eq 'Windows')
        $linuxHooks = @($hooks | Where-Object Platform -eq 'Linux')
        Write-MobileRunEvent -Run $run -Event 'TaskSelection' -Data $script:Config.DeploymentTasks
        $mobileData = Get-MobileData -MobileName $MobileName
        Write-MobileRunEvent -Run $run -Event 'Targets' -Data @{ Windows = @($mobileData.Windows); Linux = @($mobileData.Linux) }
        $smbPlan = Read-MobileSmbPlan $MobileName
        if ($smbPlan -and $smbPlan.Status -ne 'Restored') {
            Invoke-MobileSmbCheckInHooks -Plan $smbPlan -Run $run -WindowsHooks $windowsHooks -LinuxHooks $linuxHooks
            Restore-MobileSmbDeployment -Plan $smbPlan -Run $run
            $windowsHooks = @(); $linuxHooks = @() # Already executed before storage teardown.
            $mobileData.Windows = @($smbPlan.Windows | ForEach-Object { $_.Interface.IPAddress })
            $mobileData.Linux = @($smbPlan.Linux | ForEach-Object { $_.Interface.IPAddress })
        }
        $taskData = @(
            [PSCustomObject]@{ TaskName = 'Mobile-LogArchiver' }
            [PSCustomObject]@{ TaskName = 'Mobile-DisjoinTask' }
        )
        $winErrors = [System.Collections.Generic.List[object]]::new()

        $winResults = @()
        $linResults = @()

        if (@($mobileData.Windows).Count -gt 0) {
            $winErrors = [System.Collections.Generic.List[object]]::new()

            $payload = [PSCustomObject]@{
                MobileName = $MobileName
                TaskData = $taskData
                Archive =  [bool]$archive.IsPresent
                AllUsers = $mobileData.AllUsers
                Bitlocker = $oldEncryption
                Hooks = $windowsHooks
                HookRunner = (Get-WindowsProcedureHookRunner).ToString()
                Procedure = 'Check-in'
                RunId = $run.Id
            }

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

        foreach ($result in $winResults) { Write-MobileRunEvent -Run $run -Event 'HostResult' -Data $result }

        if (@($mobileData.Linux).Count -gt 0) {
            $linuxUnregister = Get-LinuxUnregisterScript `
                -AllUsers $mobileData.AllUsers `
                -Archive:$archive -Hooks $linuxHooks -MobileName $MobileName -RunId $run.Id

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

        $results = @($winResults) + @($linResults)
        foreach ($result in $linResults) { Write-MobileRunEvent -Run $run -Event 'HostResult' -Data $result }
        $runSuccess = ($results.Count -gt 0 -and @($results | Where-Object { -not $_.Success }).Count -eq 0)
        Format-DeploymentResults $results -AllUsers $mobileData.AllUsers -Unregister
    } catch {
        $runSuccess = $false
        Write-MobileRunEvent -Run $run -Event 'RunError' -Data @{ Message = $_.Exception.Message }
        throw
    } finally {
        Write-MobileRunEvent -Run $run -Event 'RunCompleted' -Data @{ Success = $runSuccess }
        Write-Host "[+] Check-in audit log: $($run.ReadablePath)"
        Write-Verbose "Structured audit log: $($run.Path)"
    }

}

#endregion
