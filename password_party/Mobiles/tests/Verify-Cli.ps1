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
    foreach ($name in @('Get-MobileOverview','Invoke-MobileScan','Register-MobileDeployment','Unregister-Deployment','Set-MobileGpoPermission','New-MobileDeployment')) {
        $source += "`nfunction $name {" + @'
    [CmdletBinding()]
    param([string]$MobileName, [switch]$Full, [switch]$Archive, [switch]$Disjoin,
        [string]$SmbHost, [string]$LinuxDisjoinKeytab, [string]$DomainPrincipal, [int]$DomainKeyVersion,
        [switch]$Rescan,
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

    function Get-ParameterCompletion([string]$Arguments) {
        $line = "& '" + $cli.Replace("'", "''") + "' " + $Arguments
        @([System.Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches |
            Where-Object ResultType -eq ParameterName | ForEach-Object CompletionText)
    }
    function Assert-Completion([string]$Arguments, [string[]]$Expected) {
        $actual = @(Get-ParameterCompletion $Arguments)
        Assert (-not (Compare-Object @($Expected | Sort-Object) @($actual | Sort-Object))) "Unexpected completion for '$Arguments': $($actual -join ', ')"
    }
    # Exercise discovery before the first invocation: no module/config/site work is needed.
    Assert-Completion '-' @('-Info','-RegisterDeployment','-UnRegisterDeployment','-Scan','-New','-GPO','-Name','-Full')
    Assert-Completion '-Scan fixture -' @('-Rescan','-Force')
    Assert-Completion '-RegisterDeployment fixture -' @('-SmbHost','-Disjoin','-LinuxDisjoinKeytab','-DomainPrincipal','-DomainKeyVersion')
    Assert-Completion '-UnRegisterDeployment fixture -' @('-Archive')
    Assert-Completion '-Info fixture -' @('-Full')
    Assert-Completion '-GPO fixture -' @('-Add','-Remove','-Force')
    Assert (@(Get-ParameterCompletion '-New -').Count -eq 0) 'New offered unrelated parameters'
    Assert (-not (Get-Module MobileManager)) 'Tab completion imported the deployment module'

    $result = & $cli
    Assert ($result.Command -eq 'Get-MobileOverview' -and -not $result.Options.MobileName) 'Default overview requires a mode switch or target'
    $result = & $cli fixture -Full
    Assert ($result.Command -eq 'Get-MobileOverview' -and $result.Options.MobileName -eq 'fixture' -and $result.Options.Full) 'Positional overview/Full changed'
    $result = & $cli -Info -Name fixture -ConfigOverride @{ Priority='explicit' } -Verbose:$false -Debug:$false
    Assert ($result.Config.Priority -eq 'explicit' -and $result.Config.OnlyFile -eq 'retained') 'Configuration precedence changed'
    Assert (-not $result.Options.Debug -and -not $result.Options.Verbose) 'Explicit false common switches were enabled'
    $result = & $cli -Info -Debug
    Assert ([bool]$result.Options.Debug) 'Debug no longer forwards to module commands'
    Assert-Rejected @{ Info=$true; enableDebug=$true }
    Assert-Rejected @{ Preflight=$true; Name='fixture' }

    $result = & $cli -Scan fixture -Rescan -Force
    Assert ($result.Command -eq 'Invoke-MobileScan' -and $result.Options.Force -and $result.Options.Rescan) 'Scan controls were not forwarded'
    $result = & $cli -Scan fixture
    Assert (-not $result.Options.ContainsKey('Force') -and -not $result.Options.ContainsKey('Rescan')) 'Omitted scan controls were forwarded'
    $result = & $cli -RegisterDeployment fixture -Disjoin -LinuxDisjoinKeytab fixture-keytab -DomainPrincipal admin -DomainKeyVersion 3
    Assert ($result.Command -eq 'Register-MobileDeployment' -and $result.Options.Disjoin -and $result.Options.LinuxDisjoinKeytab -eq 'fixture-keytab' -and $result.Options.DomainPrincipal -eq 'admin' -and $result.Options.DomainKeyVersion -eq 3) 'Check-out options were not forwarded'
    $result = & $cli -RegisterDeployment fixture -SmbHost WIN01
    Assert ($result.Options.SmbHost -eq 'WIN01') 'SMB host was not forwarded'
    $result = & $cli -RegisterDeployment fixture -SmbHost ''
    Assert ($result.Options.SmbHost -eq '') 'Blank SMB host was not preserved'
    Assert-Rejected @{ Scan=$true; Name='fixture'; SmbHost='WIN01' }
    $result = & $cli -UnRegisterDeployment fixture -Archive
    Assert ($result.Command -eq 'Unregister-Deployment' -and $result.Options.Archive) 'Check-in dispatch changed'
    $result = & $cli -GPO -Add fixture
    Assert ($result.Command -eq 'Set-MobileGpoPermission' -and $result.Options.Add) 'GPO add dispatch changed'
    $result = & $cli -GPO -Remove fixture -Force
    Assert ($result.Command -eq 'Set-MobileGpoPermission' -and $result.Options.Remove -and $result.Options.Force) 'GPO remove dispatch changed'
    Assert ((& $cli -New).Command -eq 'New-MobileDeployment') 'New mobile dispatch changed'
    Assert-Rejected @{ Initialize=$true }

    Assert-Rejected @{ Scan=$true; Name='fixture'; Disjoin=$true }
    Assert-Rejected @{ RegisterDeployment=$true; Name='fixture'; DomainController='dc' }
    Assert-Rejected @{ RegisterDeployment=$true; Name='fixture'; Rescan=$true }
    Assert-Rejected @{ GPO=$true; Add=$true; Remove=$true; Name='fixture' }
    Assert-Rejected @{ GPO=$true; Name='fixture' }
    Assert-Rejected @{ GPO=$true; Add=$true; Force=$true; Name='fixture' }
    Assert-Rejected @{ New=$true; Full=$true }
    Assert-Rejected @{ Initialize=$true; Archive=$true }
    foreach ($retired in @('SkipScans','ForceScan','force-scan','DefinitionMaxAgeDays','ScanTimeoutMinutes')) {
        $arguments = @{ Scan=$true; Name='fixture'; $retired=1 }
        Assert-Rejected $arguments
    }
    $result = & $cli -Force -Scan fixture -ErrorAction Stop
    Assert ($result.Options.Force) 'Options before their command selector no longer bind'
    $result = & $cli -UnRegisterDeployment fixture -Archive:$false
    Assert (-not $result.Options.Archive) 'Explicit false dynamic switch was enabled'
    $sets = (Get-Command $cli).ParameterSets
    foreach ($set in ($sets | Where-Object Name -in @('Scan','RegisterDeployment','UnRegisterDeployment','GPO'))) {
        Assert ([bool]($set.Parameters | Where-Object Name -eq 'Name').IsMandatory) "Missing mandatory target for $($set.Name)"
    }
    'PASS: context-specific completion, discovery without module loading, all CLI modes, invalid combinations, config precedence, forwarding, aliases and explicit false switches.'
} finally {
    Remove-Module MobileManager -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
