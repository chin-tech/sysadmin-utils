<#
.SYNOPSIS
    Logon-triggered script. If the current user appears in the [users]
    section of any mobile entry, prompts once for a password and writes a
    CMS-encrypted credential file for later pickup by Get-UserCreds /
    Unprotect-CmsMessage on the admin host. If the user isn't found
    anywhere, exits silently.

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
    than one local account (see Set-Groups). All matches are collected,
    the password is entered ONCE, and every derived account-name variant
    is written into a single encrypted file so Get-UserCreds can pick the
    right line no matter which mobile it's provisioning.

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
    [string]$MobileEntriesPath = $(if ($Config)
        { $Config.MobileEntries 
        } else
        { $null 
        }),

    [Parameter()]
    [string]$MobileDumpPath = $(if ($Config)
        { $Config.MobileDump 
        } else
        { $null 
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
if ([string]::IsNullOrWhiteSpace($MobileEntriesPath))
{
    Write-Error "No MobileEntriesPath resolved. Pass -MobileEntriesPath explicitly or -Config with a .MobileEntries property."
    return
}

if ([string]::IsNullOrWhiteSpace($MobileDumpPath))
{
    Write-Error "No MobileDumpPath resolved. Pass -MobileDumpPath explicitly or -Config with a .MobileDump property."
    return
}

if (-not (Test-Path $MobileEntriesPath))
{
    # Nothing to scan -- fail quiet-ish since this runs unattended at every logon.
    Write-Verbose "MobileEntriesPath '$MobileEntriesPath' does not exist. Nothing to do."
    return
}

if (-not (Test-Path $MobileDumpPath))
{
    New-Item -ItemType Directory -Path $MobileDumpPath -Force | Out-Null
}

# --- Group-name derivation, copied from the mobile module's Set-Groups ---
# NOTE: kept intentionally identical to the module's behavior, including the
# early-return quirk on 'i*'/'t*' matches (they skip the default "local"
# entry, unlike 'p*'/'d*rw'/'d*ro' which append to it).
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
            { $grps += @("priv") 
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

# --- Scan every mobile entry for a [users] row matching the current user ---
function Find-UserMobileAssignments
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MobileEntriesPath,
        [Parameter(Mandatory = $true)][string]$UserName
    )

    $assignments = [System.Collections.Generic.List[object]]::new()
    $entryFiles = Get-ChildItem -Path $MobileEntriesPath -File -ErrorAction SilentlyContinue

    foreach ($entryFile in $entryFiles)
    {
        $currentSection = $null
        $sections = @{}

        foreach ($line in Get-Content $entryFile.FullName)
        {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#') -or $trimmed.StartsWith(';'))
            {
                continue
            }
            if ($trimmed -match '^\[(?<Header>.+)\]$')
            {
                $currentSection = $Matches.Header
                if (-not $sections.ContainsKey($currentSection))
                {
                    $sections[$currentSection] = [System.Collections.Generic.List[string]]::new()
                }
                continue
            }
            if ($null -ne $currentSection)
            {
                $sections[$currentSection].Add($trimmed)
            }
        }

        if (-not $sections.ContainsKey('users'))
        {
            continue
        }

        $rows = $sections['users'] | ConvertFrom-Csv
        foreach ($row in $rows)
        {
            if ($row.username -ieq $UserName)
            {
                $groups = if ($row.groups)
                { $row.groups -split ';' 
                } else
                { @() 
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

$assignments = Find-UserMobileAssignments -MobileEntriesPath $MobileEntriesPath -UserName $UserName

if ($assignments.Count -eq 0)
{
    # Not assigned anywhere -- normal case for most logons. Exit quietly.
    Write-Verbose "User '$UserName' was not found in any mobile entry's [users] section."
    return
}

# Union of every derived account-name variant across all matched mobiles.
$accountVariants = [System.Collections.Generic.List[string]]::new()
foreach ($a in $assignments)
{
    foreach ($grp in (Set-Groups $a.Groups))
    {
        $variant = "$UserName.$grp"
        if ($accountVariants -notcontains $variant)
        {
            $accountVariants.Add($variant)
        }
    }
}

$mobileList = ($assignments | Select-Object -ExpandProperty MobileName -Unique) -join ', '
Write-Host "[+] '$UserName' found on mobile(s): $mobileList" -ForegroundColor Cyan
Write-Host "[+] Account variants to be set: $($accountVariants -join ', ')" -ForegroundColor Cyan

# Load the cert directly from bytes -- no store lookup, no file path needed.
# Only the public key is required for Protect-CmsMessage.
$b64ToUse = if ($CertB64Override)
{ $CertB64Override 
} else
{ $CertB64 
}
$b64ToUse = ($b64ToUse -replace '\s', '')  # strip whitespace/newlines from wrapped blobs

if ([string]::IsNullOrWhiteSpace($b64ToUse) -or $b64ToUse -eq 'PASTE_YOUR_BASE64_CERT_BLOB_HERE')
{
    Write-Error "No certificate blob configured. Paste the base64 Deployer.cer content into `$CertB64 or pass -CertB64Override."
    return
}

try
{
    $certBytes = [Convert]::FromBase64String($b64ToUse)
    # NOTE: New-Object (not ::new()) is required here -- the unary comma forces
    # PowerShell to pass $certBytes as a single byte[] argument rather than
    # unrolling it into per-byte constructor args. ::new() doesn't honor that
    # trick the same way and throws a "cannot find an overload" error.
    $deployerCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $certBytes)
} catch
{
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to load the embedded certificate blob: $($_.Exception.Message)",
        "Invalid Certificate", "OK", "Error"
    ) | Out-Null
    return
}

if ((Get-Date) -gt $deployerCert.NotAfter)
{
    Write-Warning "The embedded certificate expired on $($deployerCert.NotAfter). Encryption will still work but the recipient may not be able to decrypt if their private key/cert pairing has also lapsed."
}

# --- Single prompt for this user, covering every derived account variant ---
$ValidEntry = $false
while (-not $ValidEntry)
{
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Set Secure Password: $UserName"
    $form.Size = New-Object System.Drawing.Size(420, 340)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.Topmost = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20, 10)
    $label.Size = New-Object System.Drawing.Size(370, 80)
    $label.Text = "You are assigned to: $mobileList`nEnter a new password for [$UserName].`n[Requirements]`nMin $MinLength chars, must include: Upper, Lower, Number, and Symbol."
    $form.Controls.Add($label)

    $passLabel1 = New-Object System.Windows.Forms.Label
    $passLabel1.Text = "Password:"
    $passLabel1.Location = New-Object System.Drawing.Point(20, 95)
    $form.Controls.Add($passLabel1)

    $txtPass1 = New-Object System.Windows.Forms.TextBox
    $txtPass1.Location = New-Object System.Drawing.Point(20, 115)
    $txtPass1.Size = New-Object System.Drawing.Size(360, 20)
    $txtPass1.PasswordChar = '*'
    $form.Controls.Add($txtPass1)

    $passLabel2 = New-Object System.Windows.Forms.Label
    $passLabel2.Text = "Confirm Password:"
    $passLabel2.Location = New-Object System.Drawing.Point(20, 155)
    $form.Controls.Add($passLabel2)

    $txtPass2 = New-Object System.Windows.Forms.TextBox
    $txtPass2.Location = New-Object System.Drawing.Point(20, 175)
    $txtPass2.Size = New-Object System.Drawing.Size(360, 20)
    $txtPass2.PasswordChar = '*'
    $form.Controls.Add($txtPass2)

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = 'Encrypt & Continue'
    $btnOk.Location = New-Object System.Drawing.Point(230, 240)
    $btnOk.Size = New-Object System.Drawing.Size(150, 30)
    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $btnOk
    $form.Controls.Add($btnOk) | Out-Null

    $dialogResult = $form.ShowDialog()

    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $P1 = $txtPass1.Text
        $P2 = $txtPass2.Text

        if ($P1 -ne $P2)
        {
            [System.Windows.Forms.MessageBox]::Show("Passwords do not match!", "Error", "OK", "Error") | Out-Null
            $P1 = $P2 = $null
            $form.Dispose()
            continue
        }

        if ($P1 -notmatch $ComplexityRegex)
        {
            [System.Windows.Forms.MessageBox]::Show(
                "Password does not meet complexity requirements (Min $MinLength chars, Upper, Lower, Digit, Special).",
                "Complexity Error", "OK", "Warning"
            ) | Out-Null
            $P1 = $P2 = $null
            $form.Dispose()
            continue
        }

        $ValidEntry = $true
        $FinalPassword = $P1
        $timestamp = Get-Date -Format 's'

        # One line per derived account-name variant, all sharing this one password.
        $plainLines = $accountVariants | ForEach-Object { "${timestamp}:${_}:${FinalPassword}" }
        $plainBody = $plainLines -join "`n"

        $destFile = Join-Path $MobileDumpPath $UserName

        try
        {
            Protect-CmsMessage -To $deployerCert -Content $plainBody -OutFile $destFile -ErrorAction Stop
            Write-Host "[+] Encrypted credential written for $UserName -> $destFile" -ForegroundColor Green
            Write-Host "    Covers: $($accountVariants -join ', ')" -ForegroundColor Green
        } catch
        {
            Write-Warning "Failed to encrypt/write credential for $($UserName): $($_.Exception.Message)"
            $ValidEntry = $false
        } finally
        {
            # Best-effort scrub of plaintext from memory
            $plainBody = $null
            $plainLines = $null
            $FinalPassword = $null
            $P1 = $null
            $P2 = $null
            [System.GC]::Collect()
        }

        $form.Dispose()
    } else
    {
        $exitCheck = [System.Windows.Forms.MessageBox]::Show(
            "You are assigned to a mobile ($mobileList) and a password is required to continue deployment. Cancel anyway?",
            "Exit", "YesNo", "Warning"
        )
        $form.Dispose()
        if ($exitCheck -eq 'Yes')
        {
            Write-Host "Cancelled by user -- no credential written." -ForegroundColor Yellow
            return
        }
    }
}
