[CmdletBinding(DefaultParameterSetName = 'Info')]
param(
    # --- Mode Switches ---
    [Parameter(Mandatory = $true, ParameterSetName = 'Info')]
    [switch]$Info,

    [Parameter(Mandatory = $true, ParameterSetName = 'RegisterDeployment')]
    [switch]$RegisterDeployment,

    [Parameter(Mandatory = $true, ParameterSetName = 'UnRegisterDeployment')]
    [switch]$UnRegisterDeployment,

    [Parameter(Mandatory = $true, ParameterSetName = 'GPOAdd')]
    [Parameter(Mandatory = $true, ParameterSetName = 'GPORemove')]
    [switch]$GPO,

    # --- Sub-Action Switches (GPO) ---
    [Parameter(Mandatory = $true, ParameterSetName = 'GPOAdd')]
    [switch]$Add,

    [Parameter(Mandatory = $true, ParameterSetName = 'GPORemove')]
    [switch]$Remove,


    [Parameter(ParameterSetName='Initialize', Mandatory=$true)]
    [Switch]$Initialize,

    [Parameter(Mandatory = $false, ParameterSetName = 'UnRegisterDeployment')]
    [switch]$Archive,

    # --- Target Name ---
    [Parameter(Mandatory = $false, ParameterSetName = 'Info', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'RegisterDeployment', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'UnRegisterDeployment', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'GPOAdd', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'GPORemove', Position = 0)]
    [string]$Name,

    # --- Inspection Depth (Info Only) ---
    [Parameter(ParameterSetName = 'Info')]
    [switch]$Full,

    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [switch]$Disjoin,

    # Prepared keytab credential for Linux departure; never a plaintext password.
    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [string]$LinuxDisjoinKeytab,

    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [string]$DomainController,

    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [string]$DomainPrincipal,

    [Parameter(ParameterSetName = 'RegisterDeployment')]
    [int]$DomainKeyVersion = 0,

    # --- Force Switch (GPO Remove Only) ---
    [Parameter(ParameterSetName = 'GPORemove')]
    [switch]$Force,

    [Parameter(ParameterSetName='NewMobile')]
    [switch]$New,


    # --- Optional Config Override ---
    [Parameter()]
    [hashtable]$ConfigOverride,

    [Parameter()]
    [switch]$enableDebug
)

# Import module from local directory
$modulePath = Join-Path $PSScriptRoot 'MobileManager.psd1'
Import-Module $modulePath -Force
$overrideFile = Join-Path $PSScriptRoot 'cfg.psd1'
$overrides = @{}
if (Test-Path -LiteralPath $overrideFile) {
    $fileConfig = Import-PowerShellDataFile -Path $overrideFile
    foreach ($key in $fileConfig.Keys) { $overrides[$key] = $fileConfig[$key] }
}
if ($ConfigOverride) {
    foreach ($key in $ConfigOverride.Keys) { $overrides[$key] = $ConfigOverride[$key] }
}
Set-MobileConfig -Overrides $overrides

$passThru = @{}
if ($enableDebug -or $PSBoundParameters.ContainsKey('Debug')) {
    $passThru['Debug'] = $true
}

if ($PSBoundParameters.ContainsKey('Verbose')) {
    $passThru['Verbose'] = $true
}

switch ($PSCmdlet.ParameterSetName) {
    'Info' {
        if ([string]::IsNullOrWhiteSpace($Name)) {
            Get-MobileOverview @passThru
        } else {
            Get-MobileOverview -MobileName $Name -Full:$Full @passThru
        }
    }

    'GPOAdd' { Set-MobileGpoPermission -MobileName $Name -Add @passThru }

    'GPORemove' { Set-MobileGpoPermission -MobileName $Name -Remove -Force:$Force @passThru }

    'RegisterDeployment' { Register-MobileDeployment -MobileName $Name -Disjoin:$Disjoin -LinuxDisjoinKeytab $LinuxDisjoinKeytab -DomainController $DomainController -DomainPrincipal $DomainPrincipal -DomainKeyVersion $DomainKeyVersion @passThru }

    'UnRegisterDeployment' { UnRegister-Deployment -MobileName $Name -Archive:$Archive @passThru }
    'NewMobile' { New-MobileDeployment @passThru }
    'Initialize' {Initialize-Environment -Console @passThru}

}
