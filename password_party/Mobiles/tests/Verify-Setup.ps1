# Offline setup separation checks. No certificate store, AD, SSH, or GPO changes.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobiles-setup-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $fixture | Out-Null
function Assert($condition, $message) { if (-not $condition) { throw $message } }
try {
    # Run the real entry point against a harmless module and setup implementation.
    Copy-Item (Join-Path $root 'Initialize-Mobiles.ps1') $fixture
    New-Item -ItemType Directory (Join-Path $fixture 'Setup') | Out-Null
    '@{ RootModule="MobileManager.psm1"; ModuleVersion="1.0"; FunctionsToExport=@("Set-MobileConfig") }' |
        Set-Content (Join-Path $fixture 'MobileManager.psd1')
    'function Set-MobileConfig { param($Overrides) $script:Config=$Overrides }' |
        Set-Content (Join-Path $fixture 'MobileManager.psm1')
    '@{ Priority="file"; OnlyFile="retained" }' | Set-Content (Join-Path $fixture 'cfg.psd1')
    @'
function Initialize-Environment {
    [CmdletBinding()]
    param([switch]$Console,[switch]$HaltOnError)
    [pscustomobject]@{ Config=$script:Config; Options=@{}+$PSBoundParameters }
}
'@ | Set-Content (Join-Path $fixture 'Setup/MobileEnvironment.ps1')
    $result = & (Join-Path $fixture 'Initialize-Mobiles.ps1') -ConfigOverride @{Priority='explicit'} -Debug:$false
    Assert ($result.Config.Priority -eq 'explicit' -and $result.Config.OnlyFile -eq 'retained') 'Setup configuration precedence changed'
    Assert ($result.Options.Console -and $result.Options.HaltOnError -and -not $result.Options.Debug) 'Setup did not forward reporting/failure/debug options'
    Assert (-not (Get-Command Initialize-Environment -ErrorAction SilentlyContinue)) 'Setup function escaped into the public session'
    $manifest = Import-PowerShellDataFile (Join-Path $root 'MobileManager.psd1')
    Assert ('Initialize-Environment' -notin $manifest.FunctionsToExport) 'Setup is still exported by the manager'

    # Exercise the real read-only prerequisite check with controlled observations.
    $tokens=$null; $errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'MobileManager.psm1'),[ref]$tokens,[ref]$errors)
    Assert (-not $errors.Count) 'Module failed to parse'
    $definition=$ast.EndBlock.Statements | Where-Object {$_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Assert-MobileEnvironment'}
    $module=New-Module -ScriptBlock ([scriptblock]::Create($definition.Extent.Text))
    try {
        & $module {
            function Assert($condition,$message) { if(-not $condition){throw $message} }
            $script:Config=[pscustomobject]@{NfsHome='home';AdminRoot='admin';MobileDump='dump';MobileEntries='entries';SSHKeyPath='key';CertName='fixture'}
            $script:missing=@()
            $script:hasPrivateKey=$true
            function Test-Path {param($LiteralPath,$PathType) $LiteralPath -notin $script:missing}
            function Get-ChildItem {[CmdletBinding()]param($Path) [pscustomobject]@{Subject='CN=fixture';HasPrivateKey=$script:hasPrivateKey}}
            function New-Item {throw 'Prerequisite check attempted a repair'}
            function Initialize-Environment {throw 'Prerequisite check invoked setup'}
            function Assert-Blocked {
                $message=''
                try {Assert-MobileEnvironment -Linux} catch {$message=$_.Exception.Message}
                Assert ($message.Contains('Initialize-Mobiles.ps1')) 'Missing setup was accepted or gave no actionable guidance'
            }
            Assert-MobileEnvironment -Linux
            $script:missing=@('key')
            Assert-MobileEnvironment # A Windows-only mobile does not need SSH.
            Assert-Blocked
            $script:missing=@('dump')
            Assert-Blocked
            $script:missing=@()
            $script:hasPrivateKey=$false
            Assert-Blocked
        }
    } finally {Remove-Module $module -ErrorAction SilentlyContinue}
    'PASS: separate setup entry point, configuration precedence, private helpers, read-only prerequisites and missing-setup guidance.'
} finally {
    Remove-Module MobileManager -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
