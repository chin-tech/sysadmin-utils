# Offline hook execution and audit checks. Runs harmless local fixtures only.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobile-hooks-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join '; ') }
$statements = @($ast.EndBlock.Statements)
$names = @('Get-LinuxDeploymentUsers', 'Get-LinuxResultHeader', 'Get-LinuxResultFooter', 'ConvertFrom-WindowsDeploymentResult', 'ConvertFrom-LinuxDeploymentResult', 'ConvertTo-MobileLogLines', 'Format-MobileRunEvent', 'Show-MobileRunLog', 'Get-MobileProcedureHooks', 'Write-MobileRunEvent', 'New-MobileRunLog', 'Get-WindowsProcedureHookRunner',
    'New-LinuxTask-RestoreSmbBoot', 'Get-LinuxProcedureHookScript', 'ConvertTo-BashArgument', 'Get-LinuxDeployScript', 'Get-LinuxUnregisterScript',
    'New-LinuxTask-LeaveDomain', 'Get-DeploymentTaskSelection', 'Test-DeploymentTaskPlan',
    'Register-MobileDeployment', 'Unregister-Deployment')
$source = $statements | Where-Object {
    ($_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -in $names) -or
    ($_ -is [System.Management.Automation.Language.TypeDefinitionAst] -and $_.Name -in @('GroupType', 'LinuxAccountType')) -or
    ($_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -in @(
        '$script:GroupMetadata', '$script:DeploymentTaskCatalog', '$script:WindowsDeployBlock', '$script:WindowsUnregisterBlock'))
} | ForEach-Object { $_.Extent.Text }
$module = New-Module -ScriptBlock ([scriptblock]::Create($source -join "`n"))
try {
    & $module {
        param($fixture, $root)
        function Assert($condition, $message) { if (-not $condition) { throw $message } }
        # Mixed replies exercise the common check-in/check-out result handling.
        $windows = @(ConvertFrom-WindowsDeploymentResult -Computers @('good','denied','offline','missing') -Results @(
            [pscustomobject]@{ PSComputerName='good'; Success=$true; Actions=@('fixture-action'); Failures=@() }
        ) -TransportErrors @(
            [pscustomobject]@{ TargetObject='denied'; Exception=[Exception]::new('access denied') },
            [pscustomobject]@{ OriginInfo=[pscustomobject]@{ PSComputerName='offline' }; Exception=[Exception]::new('connection failed') }
        ))
        Assert ($windows.Count -eq 4 -and $windows[0].Success -and $windows[0].Actions[0] -eq 'fixture-action') 'Windows replies were lost or duplicated'
        Assert ($windows[1].Failures[0] -eq 'access denied' -and $windows[2].Failures[0] -eq 'connection failed' -and $windows[3].Failures[0] -like 'No result*') 'Windows transport failures were attributed to the wrong hosts'
        $linuxResults = @(ConvertFrom-LinuxDeploymentResult -Results @(
            [pscustomobject]@{ Target='good'; ExitCode=0; StdOut='{"HostName":"good","Platform":"Linux","Success":true,"Actions":[],"Failures":[]}'; StdErr='' },
            [pscustomobject]@{ Target='malformed'; ExitCode=0; StdOut='invalid json'; StdErr='' },
            [pscustomobject]@{ Target='denied'; ExitCode=1; StdOut=''; StdErr='permission denied' },
            [pscustomobject]@{ Target='empty'; ExitCode=255; StdOut=''; StdErr='' }
        ))
        Assert ($linuxResults.Count -eq 4 -and $linuxResults[0].Success) 'Linux replies were lost'
        Assert ($linuxResults[1].Failures[0] -like 'Invalid JSON*' -and $linuxResults[2].Failures[0] -eq 'permission denied' -and $linuxResults[3].Failures[0] -like '*255*') 'Linux failures lost their diagnostics'
        $scripts = Join-Path $fixture 'Scripts'
        New-Item -ItemType Directory -Path "$scripts/Check-in", "$scripts/Check-out" | Out-Null
        Set-Content -LiteralPath "$scripts/Check-out/10-first.ps1" -Value 'Write-Output "first:$env:MOBILE_NAME"'
        Set-Content -LiteralPath "$scripts/Check-out/20-second.ps1" -Value 'Write-Output "second:$env:MOBILE_PROCEDURE"'
        Set-Content -LiteralPath "$scripts/Check-out/30-failed.ps1" -Value 'Write-Error "fixture failure"'
        Set-Content -LiteralPath "$scripts/Check-out/ignored.txt" -Value 'not executable'
        Set-Content -LiteralPath "$scripts/Check-in/10-return.ps1" -Value 'Write-Output "return:$env:MOBILE_PROCEDURE"'
        $hooks = @(Get-MobileProcedureHooks -Procedure Check-out -ScriptsRoot $scripts)
        Assert (($hooks.Name -join ',') -eq '10-first.ps1,20-second.ps1,30-failed.ps1') 'Discovery order or extension filtering failed'
        Assert ($hooks[0].Sha256.Length -eq 64) 'Hook hash was not recorded'
        # A run executes its snapshot even if the source file changes after discovery.
        Set-Content -LiteralPath "$scripts/Check-out/10-first.ps1" -Value 'throw "changed source must not run"'
        $result = & (Get-WindowsProcedureHookRunner) -Hooks $hooks -MobileName fixture -Procedure Check-out -RunId fixture-run
        Assert ($result.Actions.Count -eq 3 -and $result.Failures.Count -eq 1) 'PowerShell hooks lost results or failure'
        Assert ($result.Actions[0].Details.Output.Contains('first:fixture')) 'PowerShell snapshot or environment failed'
        Assert ($result.Actions[1].Details.Output.Contains('second:Check-out')) 'PowerShell hook ordering/context failed'
        Assert ($result.Actions[2].Status -eq 'Failed') 'Nonterminating PowerShell error was reported as successful'
        # Explicit exits must not terminate the runner or prevent later hooks from running.
        $exitHooks = @(7, 0 | ForEach-Object {
            [pscustomobject]@{ Name = "exit-$_.ps1"; Sha256 = 'fixture'
                ContentBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Write-Output 'before exit'; exit $_")) }
        })
        $exitResult = & (Get-WindowsProcedureHookRunner) -Hooks $exitHooks -MobileName "fixture's mobile" -Procedure Check-out -RunId fixture-run
        Assert ($exitResult.Actions.Count -eq 2 -and $exitResult.Failures.Count -eq 1) 'Explicit exit interrupted the runner or lost failure'
        Assert ($exitResult.Actions[0].Details.ExitCode -eq 7 -and $exitResult.Actions[1].Details.ExitCode -eq 0) 'Explicit exit codes were lost'
        Assert ($exitResult.Actions[1].Status -eq 'Success') 'Exit zero was reported as failed'
        $returnHooks = @(Get-MobileProcedureHooks -Procedure Check-in -ScriptsRoot $scripts)
        $returnResult = & (Get-WindowsProcedureHookRunner) -Hooks $returnHooks -MobileName fixture -Procedure Check-in -RunId fixture-run
        Assert ($returnResult.Actions[0].Details.Output.Contains('return:Check-in')) 'Check-in hook discovery/execution failed'
        Set-Content -LiteralPath "$scripts/Check-in/bad.ps1" -Value 'if ('
        $rejected = $false
        try { Get-MobileProcedureHooks -Procedure Check-in -ScriptsRoot $scripts | Out-Null } catch { $rejected = $true }
        Assert $rejected 'Invalid PowerShell hook reached execution'
        Remove-Item -LiteralPath "$scripts/Check-in/bad.ps1"

        # Check-in hooks fail before archive/account cleanup begins.
        $script:cleanupStarted = $false
        function Get-LocalUser { $script:cleanupStarted = $true; throw 'Cleanup must not run' }
        $payload = [pscustomobject]@{
            Hooks = @($hooks[2]); HookRunner = (Get-WindowsProcedureHookRunner).ToString()
            MobileName = 'fixture'; Procedure = 'Check-in'; RunId = 'fixture-run'
            AllUsers = @([pscustomobject]@{ Name = 'fixture' }); Archive = $true
        }
        $result = & $script:WindowsUnregisterBlock $payload
        Assert (-not $result.Success -and -not $script:cleanupStarted) 'Check-in failure did not block Windows cleanup'

        # Check-out failure must block disjoin even when existing accounts pass verification.
        $script:departed = $false
        function Get-LocalUser { [CmdletBinding()] param($Name)
            [pscustomobject]@{ Enabled = $true; SID = [pscustomobject]@{ Value = 'fixture-sid' } }
        }
        function Remove-Computer { [CmdletBinding()] param($WorkGroupName, [switch]$Force, $Restart) $script:departed = $true }
        $payload = [pscustomobject]@{
            Hooks = @($hooks[2]); HookRunner = (Get-WindowsProcedureHookRunner).ToString()
            MobileName = 'fixture'; Procedure = 'Check-out'; RunId = 'fixture-run'; Disjoin = $true
            ProvisioningTasks = @(); TaskData = @()
            AllUsers = @([pscustomobject]@{ Name = 'fixture'; WindowsGroups = @(); MustChangePassword = $false })
        }
        $result = & $script:WindowsDeployBlock $payload
        Assert (-not $result.Success -and -not $script:departed) 'Check-out hook failure did not block Windows disjoin'

        $plan = (Import-PowerShellDataFile (Join-Path $root 'MobileManager.psd1')).PrivateData.PSData.DefaultConfig.DeploymentTasks
        $script:Config = [pscustomobject]@{ DeploymentTasks = $plan; MobileDeployments = "$fixture/logs" }
        if ((Get-Command bash -ErrorAction SilentlyContinue) -and (Get-Command jq -ErrorAction SilentlyContinue)) {
            $tools = Join-Path $fixture 'tools'
            New-Item -ItemType Directory -Path $tools | Out-Null
            [IO.File]::WriteAllText("$tools/dzdo", "#!/usr/bin/env bash`nexec `"`$@`"`n")
            & chmod +x "$tools/dzdo"
            $oldPath = $env:PATH
            try {
                $env:PATH = "$tools" + [IO.Path]::PathSeparator + $oldPath
                # Keep both historical Details representations and the common failure ledger.
                $envelopePath = Join-Path $fixture 'result-envelope.sh'
                foreach ($textDetails in @($false,$true)) {
                    $envelope = (Get-LinuxResultHeader -TextDetails:$textDetails) + "`n" + @'
record_action Fixture 'quoted name' Success '{"Value":"quoted detail"}'
record_action Fixture 'no detail' Success
record_failure 'fixture failure'
'@ + "`n" + (Get-LinuxResultFooter)
                    [IO.File]::WriteAllText($envelopePath, $envelope)
                    $envelopeResult = ((& bash $envelopePath) -join "`n") | ConvertFrom-Json
                    Assert (-not $envelopeResult.Success -and $envelopeResult.Failures[0] -eq 'fixture failure' -and $null -eq $envelopeResult.Actions[1].Details) 'Shared Linux logger lost failures or null details'
                    if ($textDetails) { Assert ($envelopeResult.Actions[0].Details -is [string]) 'Check-in text details changed type' }
                    else { Assert ($envelopeResult.Actions[0].Details.Value -eq 'quoted detail') 'Check-out JSON details changed type' }
                }

                [IO.File]::WriteAllText("$scripts/Check-out/10-linux's hook.sh", "echo linux:`$MOBILE_NAME:`$MOBILE_PROCEDURE`n")
                [IO.File]::WriteAllText("$scripts/Check-out/20-failed.sh", "echo fixture-stderr >&2`nexit 7`n")
                [IO.File]::WriteAllText("$scripts/Check-in/10-failed.sh", "exit 9`n")
                $linuxHooks = @(Get-MobileProcedureHooks Check-out -ScriptsRoot $scripts | Where-Object Platform -eq Linux)
                $script:Config.DeploymentTasks.Linux.Provisioning = @()
                $user = [pscustomobject]@{ BaseName = 'fixture'; LinuxAccountType = $null }
                $text = Get-LinuxDeployScript -AllUsers @($user) -Hooks $linuxHooks -MobileName fixture -RunId fixture-run
                $path = Join-Path $fixture 'checkout.sh'
                [IO.File]::WriteAllText($path, $text)
                $json = & bash $path
                $linux = ($json -join "`n") | ConvertFrom-Json
                Assert (-not $linux.Success -and $linux.Actions.Count -eq 2) 'Linux hook result JSON was corrupted or failed hook was ignored'
                Assert ($linux.Actions[0].Details.Output.Trim() -eq 'linux:fixture:Check-out') 'Linux context or quoted filename failed'
                Assert ($linux.Actions[1].Details.ExitCode -eq 7) 'Linux exit code was not recorded'
                $currentUser = (& id -un).Trim()
                $user = [pscustomobject]@{
                    BaseName = 'fixture'; LinuxName = $currentUser
                    LinuxAccountType = [LinuxAccountType]::General; GroupType = [GroupType]::Local
                }
                $text = Get-LinuxDeployScript -AllUsers @($user) -Hooks $linuxHooks -MobileName fixture -RunId fixture-run -Disjoin -b64kt 'YWJj'
                [IO.File]::WriteAllText($path, $text)
                $json = & bash $path
                $linux = ($json -join "`n") | ConvertFrom-Json
                $departure = @($linux.Actions | Where-Object Category -eq DomainDisjoin)
                Assert (-not $linux.Success -and $departure[0].Status -eq 'Skipped') 'Check-out hook failure did not block Linux disjoin'
                $script:cleanupMarker = Join-Path $fixture 'cleanup-ran'
                function New-LinuxUnregisterTask-Users { param($Users, $Archive) 'touch ' + (ConvertTo-BashArgument $script:cleanupMarker) }
                $user = [pscustomobject]@{ BaseName = 'fixture'; LinuxAccountType = [LinuxAccountType]::General; GroupType = [GroupType]::Local }
                $linuxReturnHooks = @(Get-MobileProcedureHooks Check-in -ScriptsRoot $scripts | Where-Object Platform -eq Linux)
                $text = Get-LinuxUnregisterScript -AllUsers @($user) -Hooks $linuxReturnHooks -MobileName fixture -RunId fixture-run
                Assert (-not $text.Contains('mobile-logrotate') -and -not $text.Contains('daemon-reload')) 'Check-in still manages the retired Linux log service'
                [IO.File]::WriteAllText($path, $text)
                $json = & bash $path
                $linux = ($json -join "`n") | ConvertFrom-Json
                Assert (-not $linux.Success -and -not (Test-Path $script:cleanupMarker)) 'Check-in hook failure did not block Linux cleanup'
            } finally { $env:PATH = $oldPath }
        }

        # Exercise both orchestrators with mocked transports, preserving real journal writes.
        function Get-MobileProcedureHooks { param($Procedure) @() }
        function Get-MobileData { param($MobileName)
            [pscustomobject]@{ Windows = @('fixture-host'); Linux = @(); AllUsers = @([pscustomobject]@{ Name = 'fixture' }) }
        }
        function Initialize-Environment { throw 'Routine deployment invoked setup' }
        function Assert-MobileEnvironment { param([switch]$Linux) if ($script:missingSetup) { throw 'fixture missing setup' } }
        function Get-UserCreds { param($MobileName, $AllUsers, $mobileDumpPath) $AllUsers }
        function Get-TaskData { param($hasLinux) @() }
        function Format-DeploymentResults { param($results, $allUsers, [switch]$Unregister) }
        function Invoke-Command { [CmdletBinding()] param($ComputerName, $ScriptBlock, $ArgumentList)
            $script:transportCalls++
            if ($script:transportFails) { throw 'fixture transport failure' }
            [pscustomobject]@{ PSComputerName = 'fixture-host'; Success = $true
                Actions = @([pscustomobject]@{ Category = 'Fixture'; Name = 'Built-in action'; Status = 'Success'; Details = [pscustomobject]@{ Nested = [pscustomobject]@{ Items = @('one', 'two') }; StdOut = "line one`nline two" } }); Failures = @() }
        }
        $script:Config.DeploymentTasks.Windows.PostDeployment = @('UserRights')
        Register-MobileDeployment -MobileName fixture
        Unregister-Deployment -MobileName fixture
        $logs = @(Get-ChildItem "$fixture/logs" -Filter '*.jsonl')
        Assert ($logs.Count -eq 2) 'Procedures did not create separate run logs'
        foreach ($log in $logs) {
            $events = @(Get-Content $log.FullName | ForEach-Object { $_ | ConvertFrom-Json })
            Assert ($events[0].Event -eq 'RunStarted' -and $events[-1].Event -eq 'RunCompleted' -and $events[-1].Data.Success) 'Audit lifecycle did not complete'
            Assert (@($events | Where-Object Event -eq HostResult).Count -eq 1) 'Host actions were not persisted'
            Assert (-not (Get-Content $log.FullName -Raw).Contains('ContentBase64')) 'Audit log contains hook source payload'
        }
        foreach ($log in $logs) {
            $readablePath = [IO.Path]::ChangeExtension($log.FullName, '.log')
            Assert (Test-Path $readablePath) 'Readable companion log was not created'
            $readable = Get-Content $readablePath -Raw
            Assert ($readable.Contains('Windows targets: fixture-host') -and $readable.Contains('Linux targets: (none)')) 'Targets were not expanded in readable log'
            Assert ($readable.Contains('[Success] Fixture / Built-in action') -and $readable.Contains('Details.Nested.Items: one, two')) 'Nested action details were not rendered'
            Assert (-not $readable.Contains('System.Object[]') -and -not $readable.Contains('@{')) 'Readable log contains object placeholders'
            $rendered = (Show-MobileRunLog -Path $log.FullName) -join "`n"
            Assert ($rendered.Contains('Windows targets: fixture-host') -and $rendered.Contains('[Success] Fixture / Built-in action')) 'Existing JSONL viewer lost nested data'
        }
        $fixtureEvent = [pscustomobject]@{
            TimestampUtc = 'fixture'; Procedure = 'Check-out'; MobileName = 'fixture'; Event = 'HostResult'
            Data = [pscustomobject]@{ HostName = 'tree'; Platform = 'Linux'; Success = $false; Actions = @(); Failures = @('first failure', 'second failure') }
        }
        $rendered = (Format-MobileRunEvent $fixtureEvent) -join "`n"
        Assert ($rendered.Contains('ERROR: first failure') -and $rendered.Contains('ERROR: second failure') -and $rendered.Contains('Result: FAILED')) 'Host failure messages were not expanded'
        $before = $script:transportCalls
        $script:missingSetup = $true
        $blocked = $false
        try { Register-MobileDeployment -MobileName missing-setup } catch { $blocked = $_.Exception.Message -eq 'fixture missing setup' }
        $script:missingSetup = $false
        Assert ($blocked -and $script:transportCalls -eq $before) 'Missing setup did not block remote deployment'
        $missingLog = Get-ChildItem "$fixture/logs" -Filter '*-missing-setup-*.jsonl' | Select-Object -First 1
        $missingEvents = @(Get-Content $missingLog.FullName | ForEach-Object { $_ | ConvertFrom-Json })
        Assert (-not $missingEvents[-1].Data.Success -and 'EnvironmentCheckStarted' -in $missingEvents.Event) 'Missing setup failure was not audited'
        $script:transportFails = $true
        try { Register-MobileDeployment -MobileName failed } catch { }
        $failed = Get-ChildItem "$fixture/logs" -Filter '*-failed-*.jsonl' | Select-Object -First 1
        $events = @(Get-Content $failed.FullName | ForEach-Object { $_ | ConvertFrom-Json })
        Assert ($events[-1].Event -eq 'RunCompleted' -and -not $events[-1].Data.Success -and 'RunError' -in $events.Event) 'Transport exception left no failed completion record'
        'PASS: hook snapshots/order, PowerShell and Bash execution/failures, check-in cleanup gates, and both procedure audit lifecycles.'
    } $fixture $root
} finally {
    Remove-Module $module -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
