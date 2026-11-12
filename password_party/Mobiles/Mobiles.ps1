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
    [Parameter(Mandatory, ParameterSetName = 'GPO')]
    [switch]$GPO,

    # Target. Only the overview can omit a name.
    [Parameter(Position = 0, ParameterSetName = 'Info')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'RegisterDeployment')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'UnRegisterDeployment')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Preflight')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'GPO')]
    [string]$Name,

    # Explicitly callable, but kept out of the everyday completion menu.
    [Parameter(DontShow)]
    [hashtable]$ConfigOverride,
    [Parameter(DontShow)]
    [switch]$enableDebug
)

dynamicparam {
    # Keep discovery local: completing a command must not import the module,
    # read site configuration, or contact endpoints.
    $mode = 'Info'
    foreach ($command in @('Info', 'RegisterDeployment', 'UnRegisterDeployment', 'Preflight', 'Initialize', 'New', 'GPO')) {
        if ($PSBoundParameters.ContainsKey($command)) { $mode = $command; break }
    }
    $options = switch ($mode) {
        'Info' { [ordered]@{ Full = [switch] } }
        'RegisterDeployment' { [ordered]@{
            Disjoin = [switch]
            LinuxDisjoinKeytab = [string]
            DomainController = [string]
            DomainPrincipal = [string]
            DomainKeyVersion = [int]
        } }
        'UnRegisterDeployment' { [ordered]@{ Archive = [switch] } }
        'Preflight' { [ordered]@{
            SkipScans = [switch]
            Rescan = [switch]
            ForceScan = [switch]
            DefinitionMaxAgeDays = [int]
            ScanTimeoutMinutes = [int]
        } }
        'GPO' { [ordered]@{ Add = [switch]; Remove = [switch]; Force = [switch] } }
        default { [ordered]@{} }
    }
    $parameters = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
    foreach ($option in $options.Keys) {
        $attributes = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
        $parameter = [System.Management.Automation.ParameterAttribute]::new()
        $parameter.ParameterSetName = $mode
        $attributes.Add($parameter)
        switch ($option) {
            'ForceScan' { $attributes.Add([System.Management.Automation.AliasAttribute]::new('force-scan')) }
            'DefinitionMaxAgeDays' { $attributes.Add([System.Management.Automation.ValidateRangeAttribute]::new(0, 3650)) }
            'ScanTimeoutMinutes' { $attributes.Add([System.Management.Automation.ValidateRangeAttribute]::new(1, 1440)) }
        }
        $parameters.Add($option, [System.Management.Automation.RuntimeDefinedParameter]::new($option, $options[$option], $attributes))
    }
    return $parameters
}

end {
    # GPO has one command mode; require exactly one action before loading site code.
    if ($PSCmdlet.ParameterSetName -eq 'GPO' -and (($PSBoundParameters.ContainsKey('Add') -eq $PSBoundParameters.ContainsKey('Remove')) -or
            ($PSBoundParameters.ContainsKey('Add') -and $PSBoundParameters.ContainsKey('Force')))) {
        throw [System.Management.Automation.ParameterBindingException]::new('Use -GPO with either -Add or -Remove. -Force applies only to -Remove.')
    }

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
        'Info' { Get-MobileOverview -MobileName $Name -Full:([bool]$PSBoundParameters['Full']) @commandOptions }
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
        'UnRegisterDeployment' { Unregister-Deployment -MobileName $Name -Archive:([bool]$PSBoundParameters['Archive']) @commandOptions }
        'GPO' {
            if ($PSBoundParameters.ContainsKey('Add')) { Set-MobileGpoPermission -MobileName $Name -Add @commandOptions }
            else { Set-MobileGpoPermission -MobileName $Name -Remove -Force:([bool]$PSBoundParameters['Force']) @commandOptions }
        }
        'NewMobile' { New-MobileDeployment @commandOptions }
        'Initialize' { Initialize-Environment -Console @commandOptions }
    }
}
