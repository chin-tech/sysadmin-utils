<#
.SYNOPSIS
    Prompts for new passwords for a set of accounts, validates complexity,
    and writes each as a CMS-encrypted credential file for later pickup by
    Get-UserCreds / Unprotect-CmsMessage on the admin host.

.DESCRIPTION
    This is the "client-side" half of the deployer credential flow:
      1. New-DeployerCertificate (elsewhere) creates a DocumentEncryptionCert
         and exports Deployer.pfx (private key) + Deployer.cer (public key).
      2. THIS script only needs Deployer.cer imported into the local cert
         store — it encrypts with the public key via Protect-CmsMessage.
      3. Get-UserCreds later decrypts with the private key (Deployer.pfx)
         via Unprotect-CmsMessage on the admin host that holds it.

    Because this script never has the private key, it can only overwrite a
    user's credential file, not append to it — appending would require
    decrypting the existing blob first.

.PARAMETER UserList
    Base account names to prompt for (e.g. 'Admin_Service','Vault_User').
    These should match the base username Get-UserCreds derives via
    ($_.Name -split '\.')[0].

.PARAMETER MobileDumpPath
    Destination directory for the encrypted credential files.
    Defaults to $Config.MobileDump if a $Config object is supplied.

.PARAMETER CertSubject
    Substring to match against installed cert Subjects when locating the
    deployer cert (mirrors the check in Initialize-Functionality).
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$UserList = @("Admin_Service", "Vault_User"),

    [Parameter()]
    [PSCustomObject]$Config,

    [Parameter()]
    [string]$MobileDumpPath = $(if ($Config) { $Config.MobileDump } else { $null }),

    [Parameter()]
    [string]$CertSubject = $(if ($Config -and $Config.CertName) { $Config.CertName } else { 'MobileDeployer' })
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Configuration: Adjust Complexity Requirements here ---
$MinLength = 14
# Regex: 1 Upper, 1 Lower, 1 Digit, 1 Special
$ComplexityRegex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{$MinLength,}$"

# --- Preconditions ---
if ([string]::IsNullOrWhiteSpace($MobileDumpPath))
{
    Write-Error "No MobileDumpPath resolved. Pass -MobileDumpPath explicitly or -Config with a .MobileDump property."
    return
}

if (-not (Test-Path $MobileDumpPath))
{
    New-Item -ItemType Directory -Path $MobileDumpPath -Force | Out-Null
}

# Locate the deployer cert -- mirrors the lookup in Initialize-Functionality.
# Only the public key is required for Protect-CmsMessage.
$deployerCert = Get-ChildItem -Path Cert:\CurrentUser\My |
    Where-Object { $_.Subject -like "*CN=MobileDeployer*" -or $_.Subject -like "*$CertSubject*" } |
    Select-Object -First 1

if (-not $deployerCert)
{
    [System.Windows.Forms.MessageBox]::Show(
        "The deployer encryption certificate (CN=$CertSubject) was not found in Cert:\CurrentUser\My." + `
        "`n`nImport Deployer.cer before running this script.",
        "Missing Certificate", "OK", "Error"
    ) | Out-Null
    return
}

Write-Host "[+] Using certificate: $($deployerCert.Subject) [Thumbprint: $($deployerCert.Thumbprint)]" -ForegroundColor Cyan

$results = [System.Collections.Generic.List[object]]::new()

foreach ($User in $UserList)
{
    $ValidEntry = $false
    while (-not $ValidEntry)
    {
        # --- Form Setup ---
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Set Secure Password: $User"
        $form.Size = New-Object System.Drawing.Size(400, 320)
        $form.StartPosition = 'CenterScreen'
        $form.FormBorderStyle = 'FixedDialog'
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.Topmost = $true

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20, 10)
        $label.Size = New-Object System.Drawing.Size(350, 60)
        $label.Text = "Enter a new password for [$User].`n[Requirements]`nMin $MinLength chars, must include: Upper, Lower, Number, and Symbol."
        $form.Controls.Add($label)

        # First Input
        $passLabel1 = New-Object System.Windows.Forms.Label
        $passLabel1.Text = "Password:"
        $passLabel1.Location = New-Object System.Drawing.Point(20, 75)
        $form.Controls.Add($passLabel1)

        $txtPass1 = New-Object System.Windows.Forms.TextBox
        $txtPass1.Location = New-Object System.Drawing.Point(20, 95)
        $txtPass1.Size = New-Object System.Drawing.Size(340, 20)
        $txtPass1.PasswordChar = '*'
        $form.Controls.Add($txtPass1)

        # Second Input
        $passLabel2 = New-Object System.Windows.Forms.Label
        $passLabel2.Text = "Confirm Password:"
        $passLabel2.Location = New-Object System.Drawing.Point(20, 135)
        $form.Controls.Add($passLabel2)

        $txtPass2 = New-Object System.Windows.Forms.TextBox
        $txtPass2.Location = New-Object System.Drawing.Point(20, 155)
        $txtPass2.Size = New-Object System.Drawing.Size(340, 20)
        $txtPass2.PasswordChar = '*'
        $form.Controls.Add($txtPass2)

        $btnOk = New-Object System.Windows.Forms.Button
        $btnOk.Text = 'Encrypt & Continue'
        $btnOk.Location = New-Object System.Drawing.Point(210, 220)
        $btnOk.Size = New-Object System.Drawing.Size(150, 30)
        $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $btnOk
        $form.Controls.Add($btnOk) | Out-Null

        $dialogResult = $form.ShowDialog()

        if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK)
        {
            $P1 = $txtPass1.Text
            $P2 = $txtPass2.Text

            # 1. Check Matching
            if ($P1 -ne $P2)
            {
                [System.Windows.Forms.MessageBox]::Show("Passwords do not match!", "Error", "OK", "Error") | Out-Null
                $P1 = $P2 = $null
                $form.Dispose()
                continue
            }

            # 2. Check Complexity
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

            # --- SUCCESS: build the plaintext line Get-UserCreds expects ---
            $ValidEntry = $true
            $FinalPassword = $P1
            $timestamp = Get-Date -Format 's'
            $plainLine = "${timestamp}:${User}:${FinalPassword}"

            $destFile = Join-Path $MobileDumpPath $User
            if (Test-Path $destFile)
            {
                $overwrite = [System.Windows.Forms.MessageBox]::Show(
                    "A credential file already exists for [$User]. Overwrite it?",
                    "Existing Credential Found", "YesNo", "Question"
                )
                if ($overwrite -ne 'Yes')
                {
                    $ValidEntry = $false
                    $P1 = $P2 = $FinalPassword = $plainLine = $null
                    $form.Dispose()
                    continue
                }
            }

            try
            {
                # Encrypt with the deployer cert's PUBLIC key only.
                Protect-CmsMessage -To $deployerCert -Content $plainLine -OutFile $destFile -ErrorAction Stop
                Write-Host "[+] Encrypted credential written for $User -> $destFile" -ForegroundColor Green
                $results.Add([PSCustomObject]@{ User = $User; Status = 'OK'; Path = $destFile })
            } catch
            {
                Write-Warning "Failed to encrypt/write credential for $($User): $($_.Exception.Message)"
                $results.Add([PSCustomObject]@{ User = $User; Status = 'FAILED'; Path = $destFile })
                $ValidEntry = $false
            } finally
            {
                # Best-effort scrub of plaintext from memory
                $plainLine = $null
                $FinalPassword = $null
                $P1 = $null
                $P2 = $null
                [System.GC]::Collect()
            }

            $form.Dispose()
        } else
        {
            $exitCheck = [System.Windows.Forms.MessageBox]::Show("Cancel checkout process?", "Exit", "YesNo")
            $form.Dispose()
            if ($exitCheck -eq 'Yes')
            {
                Write-Host "`nCheckout cancelled by user." -ForegroundColor Yellow
                return
            }
        }
    }
}

Write-Host "`n--- Summary ---" -ForegroundColor Cyan
$results | Format-Table -AutoSize