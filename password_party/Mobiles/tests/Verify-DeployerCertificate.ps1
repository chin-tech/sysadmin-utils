# Offline certificate-flow checks. No certificate store, domain, or Pester required.
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join "`n") }
$names = @('New-InitResult', 'Test-AndFixDeployerCert', 'Initialize-Environment')
$source = $ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names
}, $false) | ForEach-Object { $_.Extent.Text }
$module = New-Module -ScriptBlock ([scriptblock]::Create($source -join "`n"))
try {
    & $module {
        function Assert($condition, $message) { if (-not $condition) { throw $message } }
        $script:cert = [pscustomobject]@{ Subject = 'CN=fixture'; Thumbprint = 'fixture'; HasPrivateKey = $true }
        $script:cert | Add-Member ScriptMethod Export {
            param($contentType)
            if ($contentType -ne [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) {
                throw 'Private certificate material must not be exported into the logon script'
            }
            if ($script:mode -eq 'export-failed') { throw 'Fixture public export failed' }
            [byte[]]@(1, 2, 3)
        }
        function Get-ChildItem { [CmdletBinding()] param($Path)
            if ($script:mode -in @('existing', 'export-failed')) { $script:cert }
        }
        function Test-Path { param($LiteralPath) $script:mode -in @('import', 'import-failed') }
        function Import-PfxCertificate { [CmdletBinding()] param($FilePath, $CertStoreLocation, $Password)
            if ($script:mode -eq 'import-failed') { throw 'Fixture import failed' }
            $script:cert
        }
        function New-SelfSignedCertificate { [CmdletBinding()] param($Subject, $Type, $CertStoreLocation, $KeyExportPolicy, $NotAfter)
            if ($script:mode -eq 'create-failed') { throw 'Fixture creation failed' }
            $script:cert
        }
        function Export-PfxCertificate { [CmdletBinding()] param($Cert, $FilePath, $Password) 'ignored export output' }
        function Export-Certificate { [CmdletBinding()] param($Cert, $FilePath) 'ignored export output' }
        $password = ConvertTo-SecureString fixture -AsPlainText -Force
        foreach ($mode in @('existing', 'import', 'create')) {
            $script:mode = $mode
            $output = @(Test-AndFixDeployerCert -CertName fixture -PfxStoragePath /tmp -CertPassword $password)
            Assert ($output.Count -eq 1) 'Certificate helper leaked extra pipeline output'
            $expected = @{ existing = 'OK'; import = 'REPAIRED'; create = 'CREATED' }[$mode]
            Assert ($output[0].Result.Status -eq $expected) "Incorrect ledger status: $mode"
            Assert ($output[0].CertificateBase64 -eq 'AQID') "Public base64 unavailable: $mode"
            $scriptText = 'certificate: PASTE_YOUR_BASE64_CERT_BLOB_HERE' -replace 'PASTE_YOUR_BASE64_CERT_BLOB_HERE', $output[0].CertificateBase64
            Assert ($scriptText -eq 'certificate: AQID') 'Certificate substitution failed'
        }
        foreach ($mode in @('import-failed', 'create-failed', 'export-failed')) {
            $script:mode = $mode
            $result = Test-AndFixDeployerCert -CertName fixture -PfxStoragePath /tmp -CertPassword $password
            Assert ($result.Result.Status -eq 'FAILED' -and $result.Result.Fatal -and $null -eq $result.CertificateBase64) "Failure leaked certificate payload: $mode"
        }
        # A failing helper must stop initialization before reading or publishing scripts.
        function Test-AndFixDirectories { param($PathMap) New-InitResult 'Dir:fixture' 'OK' 'Fixture'; New-InitResult 'Dir:fixture2' 'OK' 'Fixture' }
        function Test-AndFixSshEnvironment { param($KeyPath, $NfsHome) New-InitResult 'SSH:fixture' 'OK' 'Fixture' }
        function Get-Content { [CmdletBinding()] param($Path) throw 'Initialization tried to read a script after certificate failure' }
        $initialized = Initialize-Environment -SshKeyPath /tmp/key -NfsHome /tmp/home -AdminRoot /tmp `
            -MobileDump /tmp/dump -MobileEntries /tmp/entries -CertName fixture
        Assert ($initialized -eq $false) 'Certificate failure did not stop initialization'
        'PASS: existing/imported/new public certificate payloads, failure results, replacement, and initialization failure gate.'
    }
} finally { Remove-Module $module -ErrorAction SilentlyContinue }
