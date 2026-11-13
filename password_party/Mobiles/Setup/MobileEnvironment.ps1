# Administrator-only setup helpers. Loaded by Initialize-Mobiles.ps1 into the
# configured manager's scope; normal mobile commands do not load this file.

. (Join-Path $PSScriptRoot 'Gpo.ps1')

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

function Set-MobileSetupPermissions([string]$Path, [switch]$Directory) {
    $identity = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rights = if ($Directory) { [Security.AccessControl.FileSystemRights]::FullControl } else {
        [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Synchronize
    }
    $inheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [Security.AccessControl.InheritanceFlags]::None }
    $matches = @($acl.Access | Where-Object {
        $_.IdentityReference.Value -ieq $identity -and -not $_.IsInherited -and
        $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -eq $rights -and
        $_.InheritanceFlags -eq $inheritance -and $_.PropagationFlags -eq 'None'
    })
    if ($acl.AreAccessRulesProtected -and $matches.Count -eq 1) { return $false }
    $grant = if ($Directory) { '(OI)(CI)(F)' } else { '(R)' }
    $null = icacls.exe $Path /inheritance:r /grant:r "${identity}:$grant" 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Could not set SSH permissions on '$Path' (icacls exit $LASTEXITCODE)." }
    return $true
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
        $permissionsChanged = $false
        if (Set-MobileSetupPermissions $localSsh -Directory) { $permissionsChanged = $true }
        if (Set-MobileSetupPermissions $nfsSsh -Directory) { $permissionsChanged = $true }

        # 3. Keypair generation
        $keyCreated = $false
        if (-not (Test-Path $KeyPath)) {
            $keyDir = Split-Path -Parent $KeyPath
            if (-not (Test-Path $keyDir)) { New-Item -ItemType Directory -Path $keyDir -Force | Out-Null }
            ssh-keygen -f "$KeyPath" -C 'MobileDeployer' -N '""' -t ecdsa -q
            $keyCreated = $true
        }

        if (Set-MobileSetupPermissions $KeyPath) { $permissionsChanged = $true }

        # 4. Authorized keys enrollment
        $pubKey = (ssh-keygen -yf $KeyPath).Trim()
        if (-not (Test-Path $rAuthorized)) {
            New-Item -ItemType File -Path $rAuthorized -Force | Out-Null
        }

        $existingAuth = Get-Content -Path $rAuthorized -ErrorAction SilentlyContinue
        $enrolled = $existingAuth -notcontains $pubKey
        if ($enrolled) {
            Add-Content -Path $rAuthorized -Value $pubKey -Encoding UTF8
        }
        if (Set-MobileSetupPermissions $rAuthorized) { $permissionsChanged = $true }

        $status = if ($keyCreated) { 'CREATED' } elseif ($permissionsChanged -or $enrolled) { 'REPAIRED' } else { 'OK' }
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
        [Parameter()][switch]$ForceGpoRefresh,
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
        $logonScript = (Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'MobileLogon.ps1') -Raw -ErrorAction Stop) `
            -replace 'PASTE_YOUR_BASE64_CERT_BLOB_HERE', $certProvision.CertificateBase64
        $results.Add((New-ShortcutGPO -TargetOUFriendlyName $OUPath -LogonScript $logonScript -ForceGpoRefresh:$ForceGpoRefresh))

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
