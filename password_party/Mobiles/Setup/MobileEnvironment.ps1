# Administrator-only setup helpers. Loaded by Initialize-Mobiles.ps1 into the
# configured manager's scope; normal mobile commands do not load this file.

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
        $LogOnScript = (Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'MobileLogon.ps1') -ErrorAction Stop) `
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
