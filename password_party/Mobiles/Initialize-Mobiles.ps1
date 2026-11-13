<#
.SYNOPSIS
Administrator setup for mobile deployment directories, SSH, certificates, and GPO scripts.
.DESCRIPTION
Run explicitly for initial provisioning or deliberate repairs, using the operator
account and configuration that will manage deployments. Routine mobile commands
never invoke this setup script. Ordinary repeats preserve matching state; use
-ForceGpoRefresh to back up and deliberately republish the managed GPO content.
#>
[CmdletBinding()]
param([hashtable]$ConfigOverride, [switch]$ForceGpoRefresh)

$manager = Import-Module (Join-Path $PSScriptRoot 'MobileManager.psd1') -Force -PassThru
$configPath = Join-Path $PSScriptRoot 'cfg.psd1'
$overrides = if (Test-Path -LiteralPath $configPath) {
    Import-PowerShellDataFile -Path $configPath
} else { @{} }
if ($ConfigOverride) {
    foreach ($key in $ConfigOverride.Keys) { $overrides[$key] = $ConfigOverride[$key] }
}
Set-MobileConfig -Overrides $overrides

$options = @{}
foreach ($option in @('Verbose', 'Debug', 'ForceGpoRefresh')) {
    if ($PSBoundParameters.ContainsKey($option)) { $options[$option] = $PSBoundParameters[$option] }
}
# Setup helpers share the configured module's private state, but are loaded only
# for this invocation and are never exported by MobileManager.
& $manager {
    param($SetupPath, $Options)
    . $SetupPath
    Initialize-Environment -Console -HaltOnError @Options
} (Join-Path $PSScriptRoot 'Setup/MobileEnvironment.ps1') $options
