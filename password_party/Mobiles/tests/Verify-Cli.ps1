# Test native CLI binding and dispatch using a harmless substitute module.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobiles-cli-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $fixture | Out-Null
try {
    Copy-Item (Join-Path $root 'Mobiles.ps1') $fixture
    $cli = Join-Path $fixture 'Mobiles.ps1'
    '@{ RootModule = "MobileManager.psm1"; ModuleVersion = "1.0" }' | Set-Content (Join-Path $fixture 'MobileManager.psd1')
    '@{ Priority = "file"; OnlyFile = "retained" }' | Set-Content (Join-Path $fixture 'cfg.psd1')
    $source = @'
function Set-MobileConfig { param($Overrides) $script:configuration = $Overrides }
'@
    foreach ($name in @('Get-MobileOverview','Invoke-MobilePreflight','Register-MobileDeployment','Unregister-Deployment','Set-MobileGpoPermission','New-MobileDeployment','Initialize-Environment')) {
        $source += "`nfunction $name {" + @'
    [CmdletBinding()]
    param([string]$MobileName, [switch]$Full, [switch]$Archive, [switch]$Disjoin,
        [string]$LinuxDisjoinKeytab, [string]$DomainController, [string]$DomainPrincipal, [int]$DomainKeyVersion,
        [switch]$SkipScans, [switch]$Rescan, [switch]$ForceScan, [int]$DefinitionMaxAgeDays, [int]$ScanTimeoutMinutes,
        [switch]$Add, [switch]$Remove, [switch]$Force, [switch]$Console)
    [pscustomobject]@{ Command=$MyInvocation.MyCommand.Name; Options=@{} + $PSBoundParameters; Config=$script:configuration }
}
'@
    }
    $source | Set-Content (Join-Path $fixture 'MobileManager.psm1')
    function Assert($condition, $message) { if (-not $condition) { throw $message } }
    function Assert-Rejected([hashtable]$Options) {
        $rejected = $false
        try { & $cli @Options | Out-Null } catch [System.Management.Automation.ParameterBindingException] { $rejected = $true }
        Assert $rejected 'An incompatible or out-of-range CLI option was accepted'
    }

    $result = & $cli
    Assert ($result.Command -eq 'Get-MobileOverview' -and -not $result.Options.MobileName) 'Default overview requires a mode switch or target'
    $result = & $cli fixture -Full
    Assert ($result.Command -eq 'Get-MobileOverview' -and $result.Options.MobileName -eq 'fixture' -and $result.Options.Full) 'Positional overview/Full changed'
    $result = & $cli -Info -Name fixture -ConfigOverride @{ Priority='explicit' } -Verbose:$false -Debug:$false
    Assert ($result.Config.Priority -eq 'explicit' -and $result.Config.OnlyFile -eq 'retained') 'Configuration precedence changed'
    Assert (-not $result.Options.Debug -and -not $result.Options.Verbose) 'Explicit false common switches were enabled'
    $result = & $cli -Info -enableDebug
    Assert ([bool]$result.Options.Debug) 'Legacy enableDebug no longer forwards Debug'

    $result = & $cli -Preflight fixture -force-scan -SkipScans:$false -Rescan -DefinitionMaxAgeDays 0 -ScanTimeoutMinutes 12
    Assert ($result.Command -eq 'Invoke-MobilePreflight' -and $result.Options.ForceScan -and $result.Options.Rescan -and -not $result.Options.SkipScans -and $result.Options.DefinitionMaxAgeDays -eq 0 -and $result.Options.ScanTimeoutMinutes -eq 12) 'Preflight options/default-sensitive values were not forwarded'
    $result = & $cli -Preflight fixture
    Assert (-not $result.Options.ContainsKey('DefinitionMaxAgeDays') -and -not $result.Options.ContainsKey('ScanTimeoutMinutes')) 'Omitted AV settings override module defaults'
    $result = & $cli -RegisterDeployment fixture -Disjoin -LinuxDisjoinKeytab fixture-keytab -DomainController dc -DomainPrincipal admin -DomainKeyVersion 3
    Assert ($result.Command -eq 'Register-MobileDeployment' -and $result.Options.Disjoin -and $result.Options.LinuxDisjoinKeytab -eq 'fixture-keytab' -and $result.Options.DomainController -eq 'dc' -and $result.Options.DomainPrincipal -eq 'admin' -and $result.Options.DomainKeyVersion -eq 3) 'Check-out options were not forwarded'
    $result = & $cli -UnRegisterDeployment fixture -Archive
    Assert ($result.Command -eq 'Unregister-Deployment' -and $result.Options.Archive) 'Check-in dispatch changed'
    $result = & $cli -GPO -Add fixture
    Assert ($result.Command -eq 'Set-MobileGpoPermission' -and $result.Options.Add) 'GPO add dispatch changed'
    $result = & $cli -GPO -Remove fixture -Force
    Assert ($result.Command -eq 'Set-MobileGpoPermission' -and $result.Options.Remove -and $result.Options.Force) 'GPO remove dispatch changed'
    Assert ((& $cli -New).Command -eq 'New-MobileDeployment') 'New mobile dispatch changed'
    $result = & $cli -Initialize
    Assert ($result.Command -eq 'Initialize-Environment' -and $result.Options.Console) 'Initialization dispatch changed'

    Assert-Rejected @{ Preflight=$true; Name='fixture'; Disjoin=$true }
    Assert-Rejected @{ RegisterDeployment=$true; Name='fixture'; Rescan=$true }
    Assert-Rejected @{ GPO=$true; Add=$true; Remove=$true; Name='fixture' }
    Assert-Rejected @{ Preflight=$true; Name='fixture'; DefinitionMaxAgeDays=-1 }
    Assert-Rejected @{ Preflight=$true; Name='fixture'; ScanTimeoutMinutes=0 }
    $sets = (Get-Command $cli).ParameterSets
    foreach ($set in ($sets | Where-Object Name -in @('Preflight','RegisterDeployment','UnRegisterDeployment','GPOAdd','GPORemove'))) {
        Assert ([bool]($set.Parameters | Where-Object Name -eq 'Name').IsMandatory) "Missing mandatory target for $($set.Name)"
    }
    'PASS: all CLI modes, native parameter-set validation, config precedence, option forwarding, aliases, defaults and explicit false switches.'
} finally {
    Remove-Module MobileManager -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
