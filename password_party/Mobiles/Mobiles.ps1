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

    # --- Force Switch (GPO Remove Only) ---
    [Parameter(ParameterSetName = 'GPORemove')]
    [switch]$Force,

    # --- Optional Config Override ---
    [Parameter()]
    [hashtable]$ConfigOverride
)

# Import module from local directory
$modulePath = Join-Path $PSScriptRoot 'MobileManager.psd1'
Import-Module $modulePath -Force

switch ($PSCmdlet.ParameterSetName) {
    'Info' {
        if ([string]::IsNullOrWhiteSpace($Name)) {
            Get-MobileOverview -Config $ConfigOverride
        }
        else {
            Get-MobileData -MobileName $Name -Config $ConfigOverride | Format-List
        }
    }

    'GPOAdd' {
        Set-MobileGpoPermission -MobileName $Name -Add -Config $ConfigOverride
    }

    'GPORemove' {
        Set-MobileGpoPermission -MobileName $Name -Remove -Force:$Force -Config $ConfigOverride
    }

    'Deploy' {
        Test-SshEnvironment
        Start-MobileDeployment -MobileName $Name -Config $ConfigOverride
    }
}