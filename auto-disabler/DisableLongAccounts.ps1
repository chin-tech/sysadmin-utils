[CmdletBinding()]
param (
    [int]$MaxDays = 90,
    [string[]]$ExcludedUsers = @('Administrator', 'Guest', 'DefaultAccount', 'HomeGroupUser$')
)

$computerName = $env:COMPUTERNAME
$adsiComputer = [ADSI]"WinNT://$computerName"
$currentUser  = $env:USERNAME
$today        = Get-Date

Write-Host "[*] Inspecting local accounts on $computerName (Threshold: $MaxDays days)..." -ForegroundColor Cyan

# Filter only user objects
$adsiComputer.Children | Where-Object { $_.SchemaClassName -eq 'User' } | ForEach-Object {
    $user = $_
    $userName = $user.Name[0]
    
    # 1. Skip current logged-in user or excluded accounts
    if ($userName -ieq $currentUser -or $ExcludedUsers -icontains $userName) {
        Write-Verbose "Skipping excluded/current user: $userName"
        return
    }

    # 2. Check if account is disabled via UserFlags bitmask (0x0002 = ADS_UF_ACCOUNTDISABLE)
    $userFlags = $user.UserFlags[0]
    $isDisabled = [bool]($userFlags -band 2)

    if ($isDisabled) {
        Write-Host "[-] Skipping: $userName (Already Disabled)" -ForegroundColor DarkGray
        return
    }

    # 3. Determine Last Login
    $lastLogin = $null
    try {
        $lastLogin = $user.LastLogin[0]
    } catch {
        $lastLogin = $null
    }

    $daysInactive = 9999
    $neverLoggedIn = $false

    if ($lastLogin -and ($lastLogin -is [datetime]) -and ($lastLogin.Year -ge 1980)) {
        $daysInactive = ($today - $lastLogin).Days
    } else {
        $neverLoggedIn = $true
    }

    # 4. Evaluate Threshold & Disable
    if ($daysInactive -gt $MaxDays) {
        $dateStamp = $today.ToString("yyyy-MM-dd")
        $auditReason = if ($neverLoggedIn) {
            "[DISABLED: $dateStamp - No login record > ${MaxDays}d]"
        } else {
            "[DISABLED: $dateStamp - Inactive for ${daysInactive}d]"
        }

        # Append to Description
        $currentDesc = ""
        try {
            $currentDesc = $user.Description[0]
        } catch {
            $currentDesc = ""
        }

        $newDesc = if ([string]::IsNullOrWhiteSpace($currentDesc)) {
            $auditReason
        } else {
            "$($currentDesc.Trim()) $auditReason"
        }

        # Truncate if exceeding 256 chars for SAM description limit
        if ($newDesc.Length -gt 256) {
            $newDesc = $newDesc.Substring(0, 256)
        }

        Write-Host "[+] Disabling: $userName (Inactive: $($daysInactive)d)" -ForegroundColor Yellow
        Write-Host "    Old Description: $currentDesc"
        Write-Host "    New Description: $newDesc"

        # Apply flags and description
        $user.Put("UserFlags", ($userFlags -bor 2))
        $user.Put("Description", $newDesc)
        $user.SetInfo()
    } else {
        Write-Host "[*] Active: $userName (Last login $daysInactive days ago)" -ForegroundColor Green
    }
}

Write-Host "[+] Scan completed." -ForegroundColor Cyan