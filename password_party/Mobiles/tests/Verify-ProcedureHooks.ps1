# Offline hook execution and audit checks. Runs harmless local fixtures only.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobile-hooks-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join '; ') }
$names = @('ConvertTo-MobileLogLines', 'Format-MobileRunEvent', 'Show-MobileRunLog', 'Get-MobileProcedureHooks', 'Write-MobileRunEvent', 'New-MobileRunLog', 'Get-WindowsProcedureHookRunner',
    'Get-LinuxProcedureHookScript', 'ConvertTo-BashArgument', 'Get-LinuxDeployScript', 'Get-LinuxUnregisterScript',
    'New-LinuxTask-LeaveDomain', 'Get-DeploymentTaskSelection', 'Test-DeploymentTaskPlan',
    'Register-MobileDeployment', 'Unregister-Deployment')
$source = $ast.EndBlock.Statements | Where-Object {
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
        Assert ($result.Actions[0].Details.StdOut.Contains('first:fixture')) 'PowerShell snapshot or environment failed'
        Assert ($result.Actions[1].Details.StdOut.Contains('second:Check-out')) 'PowerShell hook ordering/context failed'
        Assert ($result.Actions[2].Status -eq 'Failed') 'Nonterminating PowerShell error was reported as successful'
        $returnHooks = @(Get-MobileProcedureHooks -Procedure Check-in -ScriptsRoot $scripts)
        $returnResult = & (Get-WindowsProcedureHookRunner) -Hooks $returnHooks -MobileName fixture -Procedure Check-in -RunId fixture-run
        Assert ($returnResult.Actions[0].Details.StdOut.Contains('return:Check-in')) 'Check-in hook discovery/execution failed'
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
                Assert ($linux.Actions[0].Details.StdOut.Trim() -eq 'linux:fixture:Check-out') 'Linux context or quoted filename failed'
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
                $text = Get-LinuxUnregisterScript -AllUsers @($user) -Hooks $linuxReturnHooks -MobileName fixture -RunId fixture-run -SkipLogrotate
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
        function Initialize-Environment { $true }
        function Get-UserCreds { param($MobileName, $AllUsers, $mobileDumpPath) $AllUsers }
        function Get-TaskData { param($hasLinux) @() }
        function Format-DeploymentResults { param($results, $allUsers, [switch]$Unregister) }
        function Invoke-Command { [CmdletBinding()] param($ComputerName, $ScriptBlock, $ArgumentList)
            if ($script:transportFails) { throw 'fixture transport failure' }
            [pscustomobject]@{ PSComputerName = 'fixture-host'; Success = $true
                Actions = @([pscustomobject]@{ Category = 'Fixture'; Name = 'Built-in action'; Status = 'Success'; Details = [pscustomobject]@{ Nested = [pscustomobject]@{ Items = @('one', 'two') }; StdOut = "line one`nline two" } }); Failures = @() }
        }
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
