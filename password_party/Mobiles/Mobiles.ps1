[CmdletBinding(DefaultParameterSetName = 'Info')]
param(
    # Commands. Omitting a command shows the mobile overview.
    [Parameter(ParameterSetName = 'Info')]
    [switch]$Info,
    [Parameter(Mandatory, ParameterSetName = 'RegisterDeployment')]
    [switch]$RegisterDeployment,
    [Parameter(Mandatory, ParameterSetName = 'UnRegisterDeployment')]
    [switch]$UnRegisterDeployment,
    [Parameter(Mandatory, ParameterSetName = 'Preflight')]
    [switch]$Preflight,
    [Parameter(Mandatory, ParameterSetName = 'Initialize')]
    [switch]$Initialize,
    [Parameter(Mandatory, ParameterSetName = 'NewMobile')]
    [switch]$New,
    [Parameter(Mandatory, ParameterSetName = 'GPOAdd')]
    [Parameter(Mandatory, ParameterSetName = 'GPORemove')]
    [switch]$GPO,

    # Target. Only the overview can omit a name.
    [Parameter(Position = 0, ParameterSetName = 'Info')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'RegisterDeployment')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'UnRegisterDeployment')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Preflight')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'GPOAdd')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'GPORemove')]
    [string]$Name,

    # Overview and check-in options.
    [Parameter(ParameterSetName = 'Info')]
    [switch]$Full,
    [Parameter(ParameterSetName = 'UnRegisterDeployment')]
    [switch]$Archive,

    # Check-out and Linux domain departure options.
    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [switch]$Disjoin,
    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [string]$LinuxDisjoinKeytab,
    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [string]$DomainController,
    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [string]$DomainPrincipal,
    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [int]$DomainKeyVersion = 0,

    # AV preflight options.
    [Parameter(ParameterSetName = 'Preflight')]
    [switch]$SkipScans,
    [Parameter(ParameterSetName = 'Preflight')]
    [switch]$Rescan,
    [Parameter(ParameterSetName = 'Preflight')]
    [Alias('force-scan')]
    [switch]$ForceScan,
    [Parameter(ParameterSetName = 'Preflight')]
    [ValidateRange(0, 3650)]
    [int]$DefinitionMaxAgeDays,
    [Parameter(ParameterSetName = 'Preflight')]
    [ValidateRange(1, 1440)]
    [int]$ScanTimeoutMinutes,

    # GPO action and removal options.
    [Parameter(Mandatory, ParameterSetName = 'GPOAdd')]
    [switch]$Add,
    [Parameter(Mandatory, ParameterSetName = 'GPORemove')]
    [switch]$Remove,
    [Parameter(ParameterSetName = 'GPORemove')]
    [switch]$Force,

    # Shared options. PowerShell also provides -Verbose and -Debug.
    [hashtable]$ConfigOverride,
    [switch]$enableDebug
)

Import-Module (Join-Path $PSScriptRoot 'MobileManager.psd1') -Force

# Local file overrides module defaults; explicit overrides take precedence over the file.
$configPath = Join-Path $PSScriptRoot 'cfg.psd1'
$overrides = if (Test-Path -LiteralPath $configPath) {
    Import-PowerShellDataFile -Path $configPath
} else { @{} }
if ($ConfigOverride) {
    foreach ($key in $ConfigOverride.Keys) { $overrides[$key] = $ConfigOverride[$key] }
}
Set-MobileConfig -Overrides $overrides

$commandOptions = @{}
foreach ($option in @('Verbose', 'Debug')) {
    if ($PSBoundParameters.ContainsKey($option)) { $commandOptions[$option] = $PSBoundParameters[$option] }
}
if ($enableDebug) { $commandOptions.Debug = $true }

switch ($PSCmdlet.ParameterSetName) {
    'Info' { Get-MobileOverview -MobileName $Name -Full:$Full @commandOptions }
    'Preflight' {
        foreach ($option in @('SkipScans', 'Rescan', 'ForceScan', 'DefinitionMaxAgeDays', 'ScanTimeoutMinutes')) {
            if ($PSBoundParameters.ContainsKey($option)) { $commandOptions[$option] = $PSBoundParameters[$option] }
        }
        Invoke-MobilePreflight -MobileName $Name @commandOptions
    }
    'RegisterDeployment' {
        foreach ($option in @('Disjoin', 'LinuxDisjoinKeytab', 'DomainController', 'DomainPrincipal', 'DomainKeyVersion')) {
            if ($PSBoundParameters.ContainsKey($option)) { $commandOptions[$option] = $PSBoundParameters[$option] }
        }
        Register-MobileDeployment -MobileName $Name @commandOptions
    }
    'UnRegisterDeployment' { Unregister-Deployment -MobileName $Name -Archive:$Archive @commandOptions }
    'GPOAdd' { Set-MobileGpoPermission -MobileName $Name -Add @commandOptions }
    'GPORemove' { Set-MobileGpoPermission -MobileName $Name -Remove -Force:$Force @commandOptions }
    'NewMobile' { New-MobileDeployment @commandOptions }
    'Initialize' { Initialize-Environment -Console @commandOptions }
}
