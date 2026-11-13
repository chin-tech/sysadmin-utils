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
    param([switch]$Console,[switch]$HaltOnError,[switch]$ForceGpoRefresh)
    [pscustomobject]@{ Config=$script:Config; Options=@{}+$PSBoundParameters }
}
'@ | Set-Content (Join-Path $fixture 'Setup/MobileEnvironment.ps1')
    $result = & (Join-Path $fixture 'Initialize-Mobiles.ps1') -ConfigOverride @{Priority='explicit'} -Debug:$false
    Assert ($result.Config.Priority -eq 'explicit' -and $result.Config.OnlyFile -eq 'retained') 'Setup configuration precedence changed'
    Assert ($result.Options.Console -and $result.Options.HaltOnError -and -not $result.Options.Debug) 'Setup did not forward reporting/failure/debug options'
    $result = & (Join-Path $fixture 'Initialize-Mobiles.ps1') -ForceGpoRefresh
    Assert ($result.Options.ForceGpoRefresh) 'Forced GPO refresh was not forwarded'
    $result = & (Join-Path $fixture 'Initialize-Mobiles.ps1') -ForceGpoRefresh:$false
    Assert (-not $result.Options.ForceGpoRefresh) 'Explicit false GPO refresh was enabled'
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
    $setupAst=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Setup/MobileEnvironment.ps1'),[ref]$tokens,[ref]$errors)
    $definition=$setupAst.EndBlock.Statements | Where-Object {$_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Set-MobileSetupPermissions'}
    $module=New-Module -ScriptBlock ([scriptblock]::Create($definition.Extent.Text))
    $oldDomain=$env:USERDOMAIN; $oldUser=$env:USERNAME
    try {
        $env:USERDOMAIN='fixture'; $env:USERNAME='operator'
        & $module {
            function Assert($condition,$message) { if(-not $condition){throw $message} }
            $script:rule=[pscustomobject]@{
                IdentityReference=[pscustomobject]@{Value='fixture\operator'};IsInherited=$false;AccessControlType='Allow'
                FileSystemRights=[Security.AccessControl.FileSystemRights]::FullControl
                InheritanceFlags=[Security.AccessControl.InheritanceFlags]3;PropagationFlags='None'
            }
            $script:acl=[pscustomobject]@{AreAccessRulesProtected=$true;Access=@($script:rule)}
            $script:aclWrites=0
            function Get-Acl {[CmdletBinding()]param($LiteralPath) $script:acl}
            function icacls.exe {
                $script:aclWrites++
                $global:LASTEXITCODE=if($script:failAcl){5}else{0}
                if(-not $script:failAcl){$script:acl.AreAccessRulesProtected=$true}
            }
            Assert (-not (Set-MobileSetupPermissions fixture -Directory)) 'Matching directory ACL was rewritten'
            Assert ($script:aclWrites -eq 0) 'Permission utility ran for an unchanged ACL'
            $script:acl.AreAccessRulesProtected=$false
            Assert (Set-MobileSetupPermissions fixture -Directory) 'Unprotected directory ACL was not repaired'
            Assert (-not (Set-MobileSetupPermissions fixture -Directory) -and $script:aclWrites -eq 1) 'Permission repair did not settle to a no-op'
            $script:rule.FileSystemRights=[Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Synchronize
            $script:rule.InheritanceFlags=[Security.AccessControl.InheritanceFlags]::None
            Assert (-not (Set-MobileSetupPermissions fixture)) 'Matching key-file ACL was rewritten'
            $script:acl.AreAccessRulesProtected=$false; $script:failAcl=$true
            $rejected=$false
            try {Set-MobileSetupPermissions fixture | Out-Null} catch {$rejected=$_.Exception.Message.Contains('icacls exit 5')}
            Assert $rejected 'Native ACL repair failure was ignored'
        }
    } finally {
        $env:USERDOMAIN=$oldDomain; $env:USERNAME=$oldUser
        Remove-Module $module -ErrorAction SilentlyContinue
    }
    # Run the actual initializer with mocked provisioning boundaries, so the
    # template location, certificate substitution, and GPO switch are covered.
    $module=New-Module -ScriptBlock {param($path) . $path} -ArgumentList (Join-Path $root 'Setup/MobileEnvironment.ps1')
    try {
        & $module {
            param($root)
            function Assert($condition,$message) {if(-not $condition){throw $message}}
            $script:Config=[pscustomobject]@{MobileOU='fixture';CertName='fixture'}
            function Test-AndFixDirectories {param($PathMap) foreach($name in $PathMap.Keys){New-InitResult $name OK 'fixture'}}
            function Test-AndFixSshEnvironment {param($KeyPath,$NfsHome) New-InitResult 'SSH' OK 'fixture'}
            function Test-AndFixDeployerCert {param($CertName,$PfxStoragePath) [pscustomobject]@{Result=(New-InitResult 'Certificate' OK 'fixture');CertificateBase64='AQID'}}
            function Get-Content {
                [CmdletBinding()]param($Path,[switch]$Raw)
                Assert ($Path -eq (Join-Path $root 'MobileLogon.ps1') -and $Raw) 'Initializer did not read the root template as a complete script'
                'fixture PASTE_YOUR_BASE64_CERT_BLOB_HERE'
            }
            function New-ShortcutGPO {
                param($TargetOUFriendlyName,$LogonScript,[switch]$ForceGpoRefresh)
                Assert ($LogonScript -eq 'fixture AQID') 'Public certificate was not substituted into the published script'
                $script:forced=[bool]$ForceGpoRefresh
                New-InitResult GPO OK 'fixture'
            }
            $options=@{SshKeyPath='key';NfsHome='home';AdminRoot='admin';MobileDump='dump';MobileEntries='entries'}
            Assert (Initialize-Environment @options -ForceGpoRefresh -HaltOnError) 'Initializer failed with valid boundaries'
            Assert $script:forced 'Initializer did not forward forced GPO refresh'
            Assert (Initialize-Environment @options -ForceGpoRefresh:$false -HaltOnError) 'Normal initializer failed'
            Assert (-not $script:forced) 'Normal initializer enabled forced refresh'
        } $root
    } finally {Remove-Module $module -ErrorAction SilentlyContinue}
    'PASS: separate setup entry point, configuration precedence, private helpers, read-only prerequisites, no-op SSH ACL checks, ACL failure handling and missing-setup guidance.'
} finally {
    Remove-Module MobileManager -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
