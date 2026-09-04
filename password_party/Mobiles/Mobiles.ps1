[CmdletBinding(DefaultParameterSetName = 'Info')]
param(
    # --- Mode Switches ---
    [Parameter(Mandatory = $true, ParameterSetName = 'Info')]
    [switch]$Info,

    [Parameter(Mandatory = $true, ParameterSetName = 'Deploy')]
    [switch]$Deploy,

    [Parameter(Mandatory = $true, ParameterSetName = 'GPOAdd')]
    [Parameter(Mandatory = $true, ParameterSetName = 'GPORemove')]
    [switch]$GPO,

    # --- Sub-Action Switches (GPO) ---
    [Parameter(Mandatory = $true, ParameterSetName = 'GPOAdd')]
    [switch]$Add,

    [Parameter(Mandatory = $true, ParameterSetName = 'GPORemove')]
    [switch]$Remove,

    # --- Target Name ---
    [Parameter(Mandatory = $false, ParameterSetName = 'Info', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'Deploy', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'GPOAdd', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'GPORemove', Position = 0)]
    [string]$Name,

    # --- Inspection Depth (Info Only) ---
    [Parameter(ParameterSetName = 'Info')]
    [switch]$Full,

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
$overrideFile = "cfg.psd1"
$ConfigOverRide = if (Test-Path $overrideFile)
{
    Import-PowerShellDataFile -Path $overrideFile
} else
{
    $null
}


$passThru = @{}
if ($ConfigOverride)
{
    $passThru['Config'] = $ConfigOverride
}
if ($PSBoundParameters.ContainsKey('Debug'))
{
    $passThru['Debug'] = $true
}

if ($PSBoundParameters.ContainsKey('Verbose'))
{
    $passThru['Verbose'] = $true
}

switch ($PSCmdlet.ParameterSetName)
{
    'Info'
    {
        if ([string]::IsNullOrWhiteSpace($Name))
        {
            Get-MobileOverview @passThru
        } else
        {
            Get-MobileOverview -MobileName $Name -Full:$Full @passThru
        }
    }

    'GPOAdd'
    {
        Set-MobileGpoPermission -MobileName $Name -Add @passThru
    }

    'GPORemove'
    {
        Set-MobileGpoPermission -MobileName $Name -Remove -Force:$Force @passThru
    }

    'Deploy'
    {
        Start-MobileDeployment -MobileName $Name @passThru
    }
    'NewMobile'
    {
        New-MobileDeployment @passThru

    }
}
