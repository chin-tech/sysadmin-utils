# Offline fixtures for registry-backed collectors; no Windows agents or Pester needed.
# Run: pwsh -NoProfile -File ./tests/Verify-WindowsCollectors.ps1
$ErrorActionPreference = 'Stop'
$tokens = $null
$issues = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'MobileManager.psm1'), [ref]$tokens, [ref]$issues)
if ($issues.Count) { throw ($issues.Message -join "`n") }
$names = @('Test-DeploymentTaskPlan', 'Get-DeploymentTaskSelection', 'Get-WindowsCollector-Registry', 'Get-WindowsCollector-Symantec', 'Get-WindowsCollector-Ivanti',
    'Get-WindowsInformationBlock', 'Get-WindowsCollector-DiskSpace', 'Get-WindowsCollector-SecurityUpdates',
    'Get-TaskData', 'New-WindowsPostTask-NetworkSharing', 'New-WindowsPostTask-UserRights', 'Get-PostDeployScript')
$definitions = $ast.FindAll({ param($node)
    ($node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names) -or
    ($node -is [System.Management.Automation.Language.TypeDefinitionAst] -and $node.Name -eq 'TaskTriggerType') -or
    ($node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$script:DeploymentTaskCatalog')
}, $false) | ForEach-Object { $_.Extent.Text }
$module = New-Module -ScriptBlock ([scriptblock]::Create($definitions -join "`n"))
try {
    & $module {
        param($taskPlan)
        $script:Config = [pscustomobject]@{ DeploymentTasks = $taskPlan }
        function Assert($condition, $message) { if (-not $condition) { throw $message } }
        . ([scriptblock]::Create((Get-WindowsCollector-Registry)))
        . ([scriptblock]::Create((Get-WindowsCollector-Symantec)))
        . ([scriptblock]::Create((Get-WindowsCollector-Ivanti)))
        function Get-ItemProperty {
            [CmdletBinding()] param($LiteralPath)
            if ($script:denied -contains $LiteralPath) {
                throw [UnauthorizedAccessException]::new('Fixture access denied')
            }
            if ($script:registry.ContainsKey($LiteralPath)) { return $script:registry[$LiteralPath] }
            $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                [System.Management.Automation.ItemNotFoundException]::new('Fixture key absent'),
                'FixtureMissingKey', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $LiteralPath))
        }
        function Get-CimInstance {
            [CmdletBinding()] param($ClassName)
            if ($script:serviceFailure) { throw 'Fixture service query failed' }
            $script:services
        }
        $script:registry = @{}
        $script:denied = @()
        $script:services = @()
        $script:serviceFailure = $false
        $native = 'HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\Public-Opstate'
        $legacy = 'HKLM:\SOFTWARE\WOW6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\Public-Opstate'
        $core = 'HKLM:\SOFTWARE\WOW6432Node\Intel\LANDesk\LDWM'
        $nativeCore = 'HKLM:\SOFTWARE\Intel\LANDesk\LDWM'

        Assert ((Get-SymantecInformation).Status -eq 'NotDetected') 'Missing SEP was reported as an error'
        $script:registry[$native] = [pscustomobject]@{ LatestVirusDefsDate = 'fixture-native-date'; LatestVirusDefsRevision = 0 }
        $script:registry[$legacy] = [pscustomobject]@{ LatestVirusDefsDate = 'fixture-legacy-date'; LatestVirusDefsRevision = 7 }
        $sep = Get-SymantecInformation
        Assert ($sep.DefinitionDate -eq 'fixture-native-date' -and $sep.DefinitionRevision -eq 0) 'Native date/revision selection failed'
        $script:registry.Remove($native)
        $sep = Get-SymantecInformation
        Assert ($sep.DefinitionDate -eq 'fixture-legacy-date' -and $sep.SourcePath -eq $legacy) 'Older SEP path fallback failed'
        $script:registry.Clear()
        $script:registry[$native] = [pscustomobject]@{ LatestVirusDefsRevision = 3 }
        Assert ((Get-SymantecInformation).Status -eq 'DefinitionsUnavailable') 'Missing definition date was not distinguished'
        $script:registry.Clear()
        $script:denied = @($native)
        $sep = Get-SymantecInformation
        Assert ($sep.Status -eq 'CollectionFailed' -and $sep.Failures.Count -eq 1) 'SEP access failure was hidden'
        $script:denied = @()

        $script:registry[$core] = [pscustomobject]@{ CoreServer = 'core.example.test' }
        $ivanti = Get-IvantiInformation
        Assert ($ivanti.ConfiguredCoreServer -eq 'core.example.test' -and $ivanti.CoreServerSourcePath -eq $core) 'Ivanti configured core was not collected'
        Assert ($null -eq $ivanti.AutomaticServicesReady) 'No services were incorrectly reported as ready'
        $script:registry.Clear()
        $script:registry[$nativeCore] = [pscustomobject]@{ CoreServer = 'native.example.test' }
        Assert ((Get-IvantiInformation).ConfiguredCoreServer -eq 'native.example.test') 'Native Ivanti fallback failed'
        $script:serviceFailure = $true
        $ivanti = Get-IvantiInformation
        Assert ($ivanti.ConfiguredCoreServer -eq 'native.example.test' -and $ivanti.Failures.Count -eq 1) 'Service failure discarded registry results'
        $script:registry.Clear()
        $script:denied = @($core)
        $ivanti = Get-IvantiInformation
        Assert ($ivanti.CoreServerStatus -eq 'CollectionFailed' -and $null -eq $ivanti.Installed) 'Ivanti access failure was reported as absent'
        $script:denied = @()
        $script:serviceFailure = $false
        $script:services = @([pscustomobject]@{ Name = 'IvantiAgent'; DisplayName = 'Ivanti Agent'; StartMode = 'Auto'; State = 'Stopped' })
        Assert ((Get-IvantiInformation).AutomaticServicesReady -eq $false) 'Stopped automatic service was reported ready'

        $block = Get-WindowsInformationBlock
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseInput($block.ToString(), [ref]$tokens, [ref]$errors) | Out-Null
        Assert ($errors.Count -eq 0) 'Composed Windows collector failed to parse'
        Assert ($block.ToString().Contains('IvantiCoreServer') -and $block.ToString().Contains('AVDefsRevision')) 'Composed summary omitted new telemetry'
        # Optional post-deployment fragments must compose into executable PowerShell.
        $payloads = @(
            New-WindowsPostTask-NetworkSharing
            New-WindowsPostTask-NetworkSharing -DriveLetters C, D
            foreach ($sharing in @($false, $true)) {
                foreach ($linux in @($false, $true)) {
                    New-WindowsPostTask-UserRights -Sharing:$sharing -HasLinux:$linux
                    foreach ($rights in @($false, $true)) {
                        Get-PostDeployScript -Sharing:$sharing -HasLinux:$linux -UserRights:$rights
                    }
                }
            }
        )
        foreach ($payload in $payloads) {
            $tokens = $null
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseInput($payload, [ref]$tokens, [ref]$errors) | Out-Null
            Assert ($errors.Count -eq 0) 'Generated post-deployment payload failed to parse'
        }
        function New-TaskXML { param($Description, $Author, $Execute, $ToEncode, $TriggerConfigs) 'fixture-xml' }
        function Get-WindowsTask-LogArchiver { { 'fixture log archiver' } }
        $scheduled = @(Get-TaskData -hasLinux:$false)
        Assert (($scheduled.TaskName -join ',') -eq 'Mobile-LogArchiver,Mobile-DisjoinTask') 'Default scheduled selection changed'
        $script:Config.DeploymentTasks.Windows.PostDeployment = @()
        $postScript = Get-PostDeployScript
        Assert (-not $postScript.Contains('secedit') -and -not $postScript.Contains('New-SmbShare')) 'Disabled post-deployment tasks were assembled'
        $scheduled = @(Get-TaskData -hasLinux:$false)
        Assert ($scheduled.Count -eq 1 -and $scheduled[0].TaskName -eq 'Mobile-LogArchiver') 'Empty post-deployment selection registered an empty task'
        $script:Config.DeploymentTasks.Windows.Scheduled = @()
        Assert (@(Get-TaskData -hasLinux:$false).Count -eq 0) 'Disabled scheduled tasks were registered'
        'PASS: SEP native/legacy values, missing/denied keys, Ivanti core server, partial service failures, and composed script syntax.'
    } (Import-PowerShellDataFile (Join-Path (Split-Path $PSScriptRoot -Parent) 'MobileManager.psd1')).PrivateData.PSData.DefaultConfig.DeploymentTasks
} finally { Remove-Module $module -ErrorAction SilentlyContinue }
