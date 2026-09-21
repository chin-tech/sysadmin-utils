<#
.SYNOPSIS
    Logon-triggered script. If the current user appears in the [users]
    section of any mobile entry, prompts once (or once per account) for
    passwords and writes a CMS-encrypted credential file for later pickup
    by Get-UserCreds / Unprotect-CmsMessage on the admin host. If the user
    isn't found anywhere, exits silently.

.DESCRIPTION
    This is the "client-side" half of the deployer credential flow:
      1. New-DeployerCertificate (elsewhere) creates a DocumentEncryptionCert
         and exports Deployer.pfx (private key) + Deployer.cer (public key).
      2. THIS script only needs the public cert (embedded below as base64)
         -- it encrypts with Protect-CmsMessage and never touches the
         private key.
      3. Get-UserCreds later decrypts with the private key (Deployer.pfx)
         via Unprotect-CmsMessage on the admin host that holds it.

    Every mobile entry under MobileEntriesPath is scanned for a [users]
    row whose username matches the current user. A user can appear in
    more than one mobile, or under a groups value that expands to more
    than one local account (see Set-Groups). All matches are collected.

    When more than one account variant is derived, the user is asked
    whether to use a single shared password for all of them or set a
    distinct password per account. Every prompt clearly states which
    account(s) the password being entered applies to. All resulting
    lines are written into a single encrypted file so Get-UserCreds can
    pick the right line no matter which mobile it's provisioning.

    Because this script never has the private key, it can only overwrite a
    user's credential file, not append to it -- appending would require
    decrypting the existing blob first.

.PARAMETER UserName
    Overrides the detected current user. Defaults to $env:USERNAME.
    Mainly useful for testing this script against another account's
    mobile assignments without logging on as them.

.PARAMETER MobileEntriesPath
    Directory containing mobile entry files. Defaults to $Config.MobileEntries
    if a $Config object is supplied.

.PARAMETER MobileDumpPath
    Destination directory for the encrypted credential files.
    Defaults to $Config.MobileDump if a $Config object is supplied.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$UserName = $env:USERNAME,

    [Parameter()]
    [PSCustomObject]$Config,

    [Parameter()]
    [string]$MobileEntriesPath = $(if ($Config) { $Config.MobileEntries
        } else { $null
        }),

    [Parameter()]
    [string]$MobileDumpPath = $(if ($Config) { $Config.MobileDump
        } else { $null
        }),

    # Optional override: pass a base64 blob at call time instead of the embedded one below.
    [Parameter()]
    [string]$CertB64Override
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Configuration: Adjust Complexity Requirements here ---
$MinLength = 14
# Regex: 1 Upper, 1 Lower, 1 Digit, 1 Special
$ComplexityRegex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{$MinLength,}$"

# --- Embedded public certificate (Deployer.cer, base64) ---
# Generate with, on the machine that holds Deployer.cer:
#   [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\to\Deployer.cer"))
# This is the PUBLIC key only -- safe to embed in a script distributed widely,
# since it can encrypt but never decrypt existing credential files.
$CertB64 = @'
PASTE_YOUR_BASE64_CERT_BLOB_HERE
'@

# --- Preconditions ---
if ([string]::IsNullOrWhiteSpace($MobileEntriesPath)) {
    Write-Error "No MobileEntriesPath resolved. Pass -MobileEntriesPath explicitly or -Config with a .MobileEntries property."
    return
}

if ([string]::IsNullOrWhiteSpace($MobileDumpPath)) {
    Write-Error "No MobileDumpPath resolved. Pass -MobileDumpPath explicitly or -Config with a .MobileDump property."
    return
}

if (-not (Test-Path $MobileEntriesPath)) {
    # Nothing to scan -- fail quiet-ish since this runs unattended at every logon.
    Write-Verbose "MobileEntriesPath '$MobileEntriesPath' does not exist. Nothing to do."
    return
}

if (-not (Test-Path $MobileDumpPath)) {
    New-Item -ItemType Directory -Path $MobileDumpPath -Force | Out-Null
}

# --- Group-name derivation, copied from the mobile module's Set-Groups ---
# NOTE: kept intentionally identical to the module's behavior, including the
# early-return quirk on 'i*'/'t*' matches (they skip the default "local"
# entry, unlike 'p*'/'d*rw'/'d*ro' which append to it).
function Set-Groups {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [array]$Groups
    )

    $grps = @("local")
    if ($Groups.Length -eq 0) {
        return $grps
    }

    foreach ($g in $Groups) {
        switch -WildCard ($g) {
            'i*' { return @('isso')
            }
            't*' { return @('adm')
            }
            'p*' { $grps += @("priv")
            }
            'd*rw' { $grps += @("dtrw")
            }
            'd*ro' { $grps += @("dtro")
            }
        }
    }
    return $grps
}

# --- Scan every mobile entry for a [users] row matching the current user ---
function Find-UserMobileAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MobileEntriesPath,
        [Parameter(Mandatory = $true)][string]$UserName
    )

    $assignments = [System.Collections.Generic.List[object]]::new()
    $entryFiles = Get-ChildItem -Path $MobileEntriesPath -File -ErrorAction SilentlyContinue

    foreach ($entryFile in $entryFiles) {
        $currentSection = $null
        $sections = @{}

        foreach ($line in Get-Content $entryFile.FullName) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#') -or $trimmed.StartsWith(';')) {
                continue
            }
            if ($trimmed -match '^\[(?<Header>.+)\]$') {
                $currentSection = $Matches.Header
                if (-not $sections.ContainsKey($currentSection)) {
                    $sections[$currentSection] = [System.Collections.Generic.List[string]]::new()
                }
                continue
            }
            if ($null -ne $currentSection) {
                $sections[$currentSection].Add($trimmed)
            }
        }

        if (-not $sections.ContainsKey('users')) {
            continue
        }

        $rows = $sections['users'] | ConvertFrom-Csv
        foreach ($row in $rows) {
            if ($row.username -ieq $UserName) {
                $groups = if ($row.groups) { $row.groups -split ';'
                } else { @()
                }
                $assignments.Add([PSCustomObject]@{
                        MobileName = $entryFile.BaseName
                        Groups     = $groups
                    })
            }
        }
    }

    return $assignments
}

# --- Shared "are you sure" prompt, reused by every dialog below ---
function Confirm-CancelDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MobileList
    )

    $result = [System.Windows.Forms.MessageBox]::Show(
        "You are assigned to a mobile ($MobileList) and a password is required to continue deployment. Cancel anyway?",
        "Exit", "YesNo", "Warning"
    )
    return ($result -eq 'Yes')
}

# --- Shared visual style for the dialogs below ---
$script:AccentColor  = [System.Drawing.Color]::FromArgb(0, 99, 177)
$script:MutedColor   = [System.Drawing.Color]::FromArgb(110, 110, 110)
$script:DividerColor = [System.Drawing.Color]::FromArgb(225, 225, 225)
$script:BodyFont     = New-Object System.Drawing.Font("Segoe UI", 9.5)
$script:BoldFont     = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$script:HeaderFont   = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
$script:TargetFont   = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)

# Builds a form with a colored header banner already attached, so every
# dialog shares the same look. Returns the form; caller adds their own
# controls starting below the banner (banner is 56px tall).
function New-StyledForm {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][int]$Width,
        [Parameter(Mandatory = $true)][int]$Height,
        [Parameter(Mandatory = $true)][string]$HeaderText
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size($Width, $Height)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.Topmost = $true
    $form.BackColor = [System.Drawing.Color]::White
    $form.Font = $script:BodyFont

    $banner = New-Object System.Windows.Forms.Panel
    $banner.BackColor = $script:AccentColor
    $banner.Location = New-Object System.Drawing.Point(0, 0)
    $banner.Size = New-Object System.Drawing.Size($Width, 56)
    $form.Controls.Add($banner)

    $bannerLabel = New-Object System.Windows.Forms.Label
    $bannerLabel.ForeColor = [System.Drawing.Color]::White
    $bannerLabel.Font = $script:HeaderFont
    $bannerLabel.BackColor = [System.Drawing.Color]::Transparent
    $bannerLabel.Location = New-Object System.Drawing.Point(20, 13)
    $bannerLabel.Size = New-Object System.Drawing.Size(($Width - 40), 30)
    $bannerLabel.Text = $HeaderText
    $banner.Controls.Add($bannerLabel)

    return $form
}

# Flat, colored button matching the banner style. Use -Primary for the
# main call-to-action; omit it for a neutral gray button.
function New-AccentButton {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][System.Drawing.Point]$Location,
        [Parameter(Mandatory = $true)][System.Drawing.Size]$Size,
        [switch]$Primary
    )

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text
    $btn.Location = $Location
    $btn.Size = $Size
    $btn.FlatStyle = 'Flat'
    $btn.FlatAppearance.BorderSize = 0
    $btn.Font = $script:BoldFont
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand

    if ($Primary) {
        $btn.BackColor = $script:AccentColor
        $btn.ForeColor = [System.Drawing.Color]::White
    } else {
        $btn.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
        $btn.ForeColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
    }

    return $btn
}

# --- Asks which password strategy to use. Only shown when there's more
#     than one account variant -- with a single account there's nothing
#     to choose between. Returns 'Same', 'Different', or $null on cancel. ---
function Get-PasswordMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MobileList,
        [Parameter(Mandatory = $true)][string[]]$AccountVariants
    )

    $form = New-StyledForm -Title "Password Mode" -Width 440 -Height 300 -HeaderText "Choose Password Mode"

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(24, 68)
    $label.Size = New-Object System.Drawing.Size(390, 65)
    $label.ForeColor = $script:MutedColor
    $label.Text = "Assigned to: $MobileList`n`nThis covers $($AccountVariants.Count) accounts: $($AccountVariants -join ', ')"
    $form.Controls.Add($label)

    $radioSame = New-Object System.Windows.Forms.RadioButton
    $radioSame.Text = "Use ONE password for all $($AccountVariants.Count) accounts"
    $radioSame.Location = New-Object System.Drawing.Point(26, 148)
    $radioSame.Size = New-Object System.Drawing.Size(390, 22)
    $radioSame.Checked = $true
    $form.Controls.Add($radioSame)

    $radioDiff = New-Object System.Windows.Forms.RadioButton
    $radioDiff.Text = "Set a DIFFERENT password for each account"
    $radioDiff.Location = New-Object System.Drawing.Point(26, 176)
    $radioDiff.Size = New-Object System.Drawing.Size(390, 22)
    $form.Controls.Add($radioDiff)

    $btnOk = New-AccentButton -Text 'Continue' -Primary `
        -Location (New-Object System.Drawing.Point(254, 226)) `
        -Size (New-Object System.Drawing.Size(150, 34))
    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $btnOk
    $form.Controls.Add($btnOk) | Out-Null

    try {
        while ($true) {
            $dialogResult = $form.ShowDialog()
            if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
                return $(if ($radioDiff.Checked) { 'Different' } else { 'Same' })
            } else {
                if (Confirm-CancelDeployment -MobileList $MobileList) {
                    return $null
                }
                # else: loop back and re-show the same choice dialog
            }
        }
    } finally {
        $form.Dispose()
    }
}

# --- Prompts for one password/confirm pair. $TargetLabel is shown large
#     and bold so it's unmistakable which account(s) this password is for.
#     Returns the validated plaintext password, or $null if the user
#     cancelled and confirmed they want to abort. ---
function Show-PasswordPrompt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TargetLabel,
        [Parameter(Mandatory = $true)][string]$MobileList,
        [Parameter(Mandatory = $true)][int]$MinLength,
        [Parameter(Mandatory = $true)][string]$ComplexityRegex
    )

    while ($true) {
        # $TargetLabel is either a single account name, or (in "same
        # password for all" mode) several names joined with newlines.
        # NOTE: named $targetAccounts, not $TargetAccounts/$targetLabel --
        # avoid any case-insensitive collision with the $TargetLabel param
        # (see the note further down about $lblTarget for why that matters).
        $targetAccounts = $TargetLabel -split "`n"

        # A multi-account list needs a scrollable box so it can never get
        # visually clipped, however many accounts are in it. A single
        # account keeps the original big bold callout -- it always fits
        # on one line, so there's nothing to scroll.
        $yOffset = if ($targetAccounts.Count -gt 1) { 46 } else { 0 }

        $form = New-StyledForm -Title "Set Secure Password" -Width 440 -Height (430 + $yOffset) -HeaderText "Set Secure Password"

        $introLabel = New-Object System.Windows.Forms.Label
        $introLabel.Location = New-Object System.Drawing.Point(24, 66)
        $introLabel.Size = New-Object System.Drawing.Size(390, 20)
        $introLabel.ForeColor = $script:MutedColor
        $introLabel.Text = "Assigned to: $MobileList"
        $form.Controls.Add($introLabel)

        $lblTargetHeader = New-Object System.Windows.Forms.Label
        $lblTargetHeader.Location = New-Object System.Drawing.Point(24, 90)
        $lblTargetHeader.Size = New-Object System.Drawing.Size(390, 24)
        $lblTargetHeader.Font = $script:TargetFont
        $lblTargetHeader.ForeColor = $script:AccentColor
        $lblTargetHeader.Text = if ($targetAccounts.Count -gt 1) {
            "Password for ALL $($targetAccounts.Count) accounts:"
        } else {
            "Password for:"
        }
        $form.Controls.Add($lblTargetHeader)

        if ($targetAccounts.Count -gt 1) {
            # Read-only, scrollable -- every account is reachable no matter
            # how long the list gets, instead of silently clipping.
            $lstTarget = New-Object System.Windows.Forms.TextBox
            $lstTarget.Location = New-Object System.Drawing.Point(24, 118)
            $lstTarget.Size = New-Object System.Drawing.Size(390, 70)
            $lstTarget.Multiline = $true
            $lstTarget.ReadOnly = $true
            $lstTarget.ScrollBars = 'Vertical'
            $lstTarget.BorderStyle = 'FixedSingle'
            $lstTarget.BackColor = [System.Drawing.Color]::FromArgb(245, 248, 252)
            $lstTarget.Font = $script:BodyFont
            $lstTarget.Text = ($targetAccounts -join "`r`n")
            $lstTarget.TabStop = $false
            $form.Controls.Add($lstTarget)
        } else {
            # NOTE: named $lblTarget (not $targetLabel) deliberately --
            # PowerShell variables are case-insensitive, so $targetLabel
            # would be the same variable as the $TargetLabel string
            # parameter above. Reassigning it to a Label control would
            # silently coerce that control back to a string (since the
            # variable stays bound to the parameter's [string] type),
            # breaking every property access on it afterward.
            $lblTarget = New-Object System.Windows.Forms.Label
            $lblTarget.Location = New-Object System.Drawing.Point(24, 118)
            $lblTarget.Size = New-Object System.Drawing.Size(390, 30)
            $lblTarget.Font = $script:TargetFont
            $lblTarget.ForeColor = $script:AccentColor
            $lblTarget.Text = $targetAccounts[0]
            $form.Controls.Add($lblTarget)
        }

        $divider = New-Object System.Windows.Forms.Panel
        $divider.BackColor = $script:DividerColor
        $divider.Location = New-Object System.Drawing.Point(24, (156 + $yOffset))
        $divider.Size = New-Object System.Drawing.Size(390, 1)
        $form.Controls.Add($divider)

        $reqLabel = New-Object System.Windows.Forms.Label
        $reqLabel.Location = New-Object System.Drawing.Point(24, (167 + $yOffset))
        $reqLabel.Size = New-Object System.Drawing.Size(390, 32)
        $reqLabel.ForeColor = $script:MutedColor
        $reqLabel.Text = "Minimum $MinLength characters, including upper, lower, number and symbol."
        $form.Controls.Add($reqLabel)

        $passLabel1 = New-Object System.Windows.Forms.Label
        $passLabel1.Text = "Password"
        $passLabel1.Font = $script:BoldFont
        $passLabel1.Location = New-Object System.Drawing.Point(24, (207 + $yOffset))
        $passLabel1.Size = New-Object System.Drawing.Size(200, 18)
        $form.Controls.Add($passLabel1)

        $txtPass1 = New-Object System.Windows.Forms.TextBox
        $txtPass1.Location = New-Object System.Drawing.Point(24, (228 + $yOffset))
        $txtPass1.Size = New-Object System.Drawing.Size(390, 24)
        $txtPass1.PasswordChar = '*'
        $txtPass1.BorderStyle = 'FixedSingle'
        $form.Controls.Add($txtPass1)

        $passLabel2 = New-Object System.Windows.Forms.Label
        $passLabel2.Text = "Confirm Password"
        $passLabel2.Font = $script:BoldFont
        $passLabel2.Location = New-Object System.Drawing.Point(24, (262 + $yOffset))
        $passLabel2.Size = New-Object System.Drawing.Size(200, 18)
        $form.Controls.Add($passLabel2)

        $txtPass2 = New-Object System.Windows.Forms.TextBox
        $txtPass2.Location = New-Object System.Drawing.Point(24, (283 + $yOffset))
        $txtPass2.Size = New-Object System.Drawing.Size(390, 24)
        $txtPass2.PasswordChar = '*'
        $txtPass2.BorderStyle = 'FixedSingle'
        $form.Controls.Add($txtPass2)

        $btnOk = New-AccentButton -Text 'Continue' -Primary `
            -Location (New-Object System.Drawing.Point(264, (330 + $yOffset))) `
            -Size (New-Object System.Drawing.Size(150, 34))
        $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $btnOk
        $form.Controls.Add($btnOk) | Out-Null

        $dialogResult = $form.ShowDialog()

        if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
            $P1 = $txtPass1.Text
            $P2 = $txtPass2.Text

            if ($P1 -ne $P2) {
                [System.Windows.Forms.MessageBox]::Show("Passwords do not match!", "Error", "OK", "Error") | Out-Null
                $P1 = $P2 = $null
                $form.Dispose()
                continue
            }

            if ($P1 -notmatch $ComplexityRegex) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Password does not meet complexity requirements (Min $MinLength chars, Upper, Lower, Digit, Special).",
                    "Complexity Error", "OK", "Warning"
                ) | Out-Null
                $P1 = $P2 = $null
                $form.Dispose()
                continue
            }

            $form.Dispose()
            return $P1
        } else {
            $form.Dispose()
            if (Confirm-CancelDeployment -MobileList $MobileList) {
                return $null
            }
            # else: loop back and re-show the prompt for this same account
        }
    }
}

$assignments = Find-UserMobileAssignments -MobileEntriesPath $MobileEntriesPath -UserName $UserName

if ($assignments.Count -eq 0) {
    # Not assigned anywhere -- normal case for most logons. Exit quietly.
    Write-Verbose "User '$UserName' was not found in any mobile entry's [users] section."
    return
}

# Union of every derived account-name variant across all matched mobiles.
$accountVariants = [System.Collections.Generic.List[string]]::new()
foreach ($a in $assignments) {
    foreach ($grp in (Set-Groups $a.Groups)) {
        $variant = "$UserName.$grp"
        if ($accountVariants -notcontains $variant) {
            $accountVariants.Add($variant)
        }
    }
}

$mobileList = ($assignments | Select-Object -ExpandProperty MobileName -Unique) -join ', '
Write-Host "[+] '$UserName' found on mobile(s): $mobileList" -ForegroundColor Cyan
Write-Host "[+] Account variants to be set: $($accountVariants -join ', ')" -ForegroundColor Cyan

# Load the cert directly from bytes -- no store lookup, no file path needed.
# Only the public key is required for Protect-CmsMessage.
$b64ToUse = if ($CertB64Override) { $CertB64Override
} else { $CertB64
}
$b64ToUse = ($b64ToUse -replace '\s', '')  # strip whitespace/newlines from wrapped blobs

if ([string]::IsNullOrWhiteSpace($b64ToUse) -or $b64ToUse -eq 'PASTE_YOUR_BASE64_CERT_BLOB_HERE') {
    Write-Error "No certificate blob configured. Paste the base64 Deployer.cer content into `$CertB64 or pass -CertB64Override."
    return
}

try {
    $certBytes = [Convert]::FromBase64String($b64ToUse)
    # NOTE: New-Object (not ::new()) is required here -- the unary comma forces
    # PowerShell to pass $certBytes as a single byte[] argument rather than
    # unrolling it into per-byte constructor args. ::new() doesn't honor that
    # trick the same way and throws a "cannot find an overload" error.
    $deployerCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $certBytes)
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to load the embedded certificate blob: $($_.Exception.Message)",
        "Invalid Certificate", "OK", "Error"
    ) | Out-Null
    return
}

if ((Get-Date) -gt $deployerCert.NotAfter) {
    Write-Warning "The embedded certificate expired on $($deployerCert.NotAfter). Encryption will still work but the recipient may not be able to decrypt if their private key/cert pairing has also lapsed."
}

# --- Collect password(s), then encrypt and write. Retries the whole
#     collection step if the encrypted write itself fails. ---
$written = $false
while (-not $written) {
    $passwordMode = if ($accountVariants.Count -gt 1) {
        Get-PasswordMode -MobileList $mobileList -AccountVariants $accountVariants
    } else {
        'Same'
    }

    if ($null -eq $passwordMode) {
        Write-Host "Cancelled by user -- no credential written." -ForegroundColor Yellow
        return
    }

    $passwordMap = [ordered]@{}
    $cancelled = $false

    if ($passwordMode -eq 'Same') {
        $allLabel = $accountVariants -join "`n"

        $pwd = Show-PasswordPrompt -TargetLabel $allLabel -MobileList $mobileList -MinLength $MinLength -ComplexityRegex $ComplexityRegex
        if ($null -eq $pwd) {
            $cancelled = $true
        } else {
            foreach ($variant in $accountVariants) {
                $passwordMap[$variant] = $pwd
            }
            $pwd = $null
        }
    } else {
        foreach ($variant in $accountVariants) {
            $pwd = Show-PasswordPrompt -TargetLabel $variant -MobileList $mobileList -MinLength $MinLength -ComplexityRegex $ComplexityRegex
            if ($null -eq $pwd) {
                $cancelled = $true
                break
            }
            $passwordMap[$variant] = $pwd
            $pwd = $null
        }
    }

    if ($cancelled) {
        Write-Host "Cancelled by user -- no credential written." -ForegroundColor Yellow
        return
    }

    $timestamp = Get-Date -Format 's'
    $plainLines = foreach ($variant in $accountVariants) {
        "${timestamp}:${variant}:$($passwordMap[$variant])"
    }
    $plainBody = $plainLines -join "`n"

    $destFile = Join-Path $MobileDumpPath $UserName

    try {
        Protect-CmsMessage -To $deployerCert -Content $plainBody -OutFile $destFile -ErrorAction Stop
        Write-Host "[+] Encrypted credential written for $UserName -> $destFile" -ForegroundColor Green
        Write-Host "    Covers: $($accountVariants -join ', ')" -ForegroundColor Green
        $written = $true
    } catch {
        Write-Warning "Failed to encrypt/write credential for $($UserName): $($_.Exception.Message)"
        $retry = [System.Windows.Forms.MessageBox]::Show(
            "Failed to write the credential file:`n$($_.Exception.Message)`n`nTry entering the password(s) again?",
            "Write Failed", "YesNo", "Error"
        )
        if ($retry -ne 'Yes') {
            return
        }
        # else: loop back to password collection and try again
    } finally {
        # Best-effort scrub of plaintext from memory
        $plainBody = $null
        $plainLines = $null
        if ($passwordMap) {
            foreach ($k in @($passwordMap.Keys)) { $passwordMap[$k] = $null }
        }
        $passwordMap = $null
        [System.GC]::Collect()
    }
}
