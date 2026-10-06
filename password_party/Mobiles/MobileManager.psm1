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

#endregion

#region Runtime configuration

function Set-MobileConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$Overrides)

    $merged = @{}
    foreach ($property in $script:Config.PSObject.Properties) {
        $merged[$property.Name] = $property.Value
    }
    foreach ($key in $Overrides.Keys) {
        if (-not $merged.ContainsKey($key)) { throw "Unknown mobile configuration key '$key'." }
        if ([string]::IsNullOrWhiteSpace([string]$Overrides[$key])) {
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

#region Windows provisioning and cleanup

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
        $path = "${d}:\"

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

$denyRights = @(
    'SeDenyInteractiveLogonRight',
    'SeDenyRemoteInteractiveLogonRight',
    'SeDenyBatchLogonRight',
    'SeDenyServiceLogonRight'
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
    }
    else {
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

# 2. Apply deny rights
if ($sharingSid) {
    foreach ($r in $denyRights) {
        $cfg = Add-PrivilegeRight `
            -ConfigText $cfg `
            -RightName $r `
            -RawSid $sharingSid
    }
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
}
else {
    record_action 'UserRights' 'LocalSecurityPolicy' 'Failed'
    record_failure "User rights configuration failed: exit code $LASTEXITCODE"
}

# Cleanup
Remove-Item -Path $tmpSec, $tmpDB -Force -ErrorAction SilentlyContinue
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


    $logCollect = New-TaskXML -Description 'Mobile Auto Log Archiver' `
        -Author '[Mobile Administration]' -Execute 'powershell.exe' `
        -ToEncode (Get-WindowsTask-LogArchiver).ToString() -TriggerConfigs @($weeklyTrigger)

    $taskData += @([PsCustomObject]@{Taskname = "Mobile-LogArchiver"; TaskXml = $logCollect})
    $taskData += @([PsCustomObject]@{Taskname = "Mobile-DisjoinTask"; TaskXml = $domainDisjoinTask})

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

    if (-not $payload.AllUsers -or $payload.AllUsers.Count -eq 0) {
        $failures.Add('No users provided in payload')
    }

    #
    # Users
    #
    foreach ($u in $payload.AllUsers) {

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

        #
        # Password expiration
        #
        if ($u.MustChangePassword) {

            $success = Invoke-Step  -Context "Password expiry '$($u.Name)'"  -Action { $adsiUser = [ADSI]"WinNT://./$($u.Name),user"; $adsiUser.PasswordExpired = 1; $adsiUser.SetInfo() }

            Add-Action  -Category 'PasswordExpiry'  -Name $u.Name  -Status $(if ($success) { 'Changed' } else { 'Failed' })
        }

        #
        # Groups
        #
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
        [switch]$SkipLogrotate
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

    # 3. Assemble tasks pipeline dynamically
    $tasks = [System.Collections.Generic.List[string]]::new()
    $tasks.Add($header)

    $tasks.Add((New-LinuxTask-CreateDirectory -Path '/mobiles/home'))

    if (-not $SkipLogrotate) { $tasks.Add((New-LinuxTask-AddLogService )) }

    if (-not $SkipLuks) { $tasks.Add((New-LinuxTask-Luks  -CurrentPass $script:Config.curLuks  -NewPin $script:Config.encryptionPin)) }

    if ($linuxUsers) { $tasks.Add((New-LinuxTask-AddUsers -Users $linuxUsers -HomeBase '/mobiles/home')) }

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

        [switch]$SkipLogrotate
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

#endregion

#region Windows information collectors

function Get-WindowsCollector-Registry {
    [CmdletBinding()]
    param()
    return @'
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
'@
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

function Get-WindowsCollector-Symantec {
    [CmdletBinding()]
    param()
    return @'
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
    $parts.Add((Get-WindowsCollector-Registry))
    $parts.Add((Get-WindowsCollector-Symantec))
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
'@)

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
        [switch]$Disjoin,
        [string]$LinuxDisjoinKeytab,
        [string]$DomainController,
        [string]$DomainPrincipal,
        [int]$DomainKeyVersion = 0
    )

    $mobileData = Get-MobileData -MobileName $MobileName
    if ($Disjoin -and $mobileData.Linux.Count -gt 0) {
        $LinuxDisjoinKeytab = Resolve-LinuxDisjoinKeytab -Keytab $LinuxDisjoinKeytab `
            -DomainController $DomainController -Principal $DomainPrincipal -Kvno $DomainKeyVersion
    }
    if (-not (Initialize-Environment)) { throw "Failed to properly initialize environment!" }
    $mobileData.AllUsers  = Get-UserCreds -MobileName $MobileName -AllUsers $mobileData.AllUsers -mobileDumpPath $mobileDump
    $taskData = Get-TaskData -hasLinux:$($mobileData.Linux.Count -gt 0)


    $windowsPayload = [PSCustomObject]@{
        allUsers = @($mobileData.AllUsers)
        taskData = @($taskData)
        MobileName = $MobileName
        Disjoin = $disJoin
        Bitlocker = $defaultPin

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
    if ($mobileData.Linux.Count -gt 0) {
        $linSplat = @{ allUsers = $mobileData.AllUsers }
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
    Format-DeploymentResults -results $results -allUsers $mobileData.AllUsers
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
            Archive =  [bool]$archive.IsPresent
            AllUsers = $mobileData.AllUsers
            Bitlocker = $oldEncryption
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

    Format-DeploymentResults (@($winResults) + @($linResults)) -AllUsers $mobileData.AllUsers -Unregister


}

#endregion
