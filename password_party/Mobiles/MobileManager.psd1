@{
    # Script module or binary module file associated with this manifest.
    RootModule             = 'MobileManager.psm1'

    # Version number of this module.
    ModuleVersion          = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions   = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID                   = '85f01ed9-1c84-4ef0-a6cf-741c38e915d1'

    # Author of this module
    Author                 = 'Alexander Chin-Lenn'

    # Description of the functionality provided by this module
    Description            = 'Module for managing mobile deployments, GPO ACL assignments, and scheduled tasks.'

    # Functions to export from this module (keep internal helpers hidden)
    FunctionsToExport      = @(
        'Get-MobileData',
        'Get-MobileOverview',
        'Set-MobileGpoPermission',
        'Start-MobileDeployment',
        'Initialize-Ssh-Environment'
        'New-MobileDeployment'
        'Write-MobileFile'
        'Set-MobileGpoPermission'
        'Set-MobileDebug'
    )

    # Cmdlets, Variables, and Aliases to export
    CmdletsToExport        = @()
    VariablesToExport      = @()
    AliasesToExport        = @()

    # Private data for default configuration paths (can be overridden at runtime)
    PrivateData            = @{
        PSData = @{
            DefaultConfig = @{
                GpoId          = '00000000-0000-0000-0000-000000000000'
                sshKeyName     = 'deployer'
                certName       = 'deployer'
                fallbackPass    = 'defaultPass'
                curLuks         = 'defaultLuks'
                encryptionPin     = 'defaultPin'
                adminRoot = "C:\TEMP"
                nfsHomeRoot   = "C:\TEMP\"

            }
        }
    }
}
