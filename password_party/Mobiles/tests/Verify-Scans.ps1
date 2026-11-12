# Offline preflight checks. Uses fake scanners and mocked transports only.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobile-preflight-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join '; ') }
$names = @('Get-MobileTerminalWidth', 'Write-MobileCenteredText', 'Write-MobileTable', 'Read-WindowsScan','Invoke-MobileScanQuery','Get-MobileScanOutcome','Get-MobileScanEvidence','New-TaskXML', 'ConvertTo-Base64', 'Start-WindowsScanJob', 'Get-WindowsScanWorker', 'Get-WindowsScanState', 'Get-LinuxScanWorker', 'Get-MobileDefinitionAssessment', 'Get-WindowsScanBlock', 'Get-LinuxScanScript', 'Invoke-MobileScan',
    'Get-WindowsCollector-Registry', 'Get-WindowsCollector-Symantec',
    'ConvertTo-BashArgument', 'New-MobileRunLog', 'Write-MobileRunEvent', 'Format-MobileRunEvent', 'ConvertTo-MobileLogLines')
$source = $ast.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -in $names
} | ForEach-Object { $_.Extent.Text }
$module = New-Module -ScriptBlock ([scriptblock]::Create($source -join "`n"))
try {
    & $module {
        param($fixture, $root)
        function Assert($condition, $message) { if (-not $condition) { throw $message } }
        Assert ((Get-WindowsScanBlock).ToString() -notmatch 'Get-IvantiInformation') 'Scan payload still includes unrelated inventory'
        $today = [datetime]::UtcNow.ToString('yyyy-MM-dd')
        Assert ((Get-MobileDefinitionAssessment $today).Status -eq 'Current') 'Current definitions were rejected'
        Assert ((Get-MobileDefinitionAssessment ([datetime]::UtcNow.AddDays(-31).ToString('yyyy-MM-dd'))).Status -eq 'Stale') 'Stale definitions were not flagged'
        Assert ((Get-MobileDefinitionAssessment ([datetime]::UtcNow.AddDays(-30).ToString('yyyy-MM-dd'))).Status -eq 'Current') '30-day boundary was rejected'
        Assert ((Get-MobileDefinitionAssessment 'ambiguous-date').Status -eq 'Unknown') 'Unknown date was guessed'
        Assert ((Get-MobileDefinitionAssessment ([datetime]::UtcNow.AddDays(2).ToString('yyyy-MM-dd'))).Status -eq 'FutureDate') 'Future definition date was not flagged'
        $script:Config = [pscustomobject]@{
            Preflight = (Import-PowerShellDataFile (Join-Path $root 'MobileManager.psd1')).PrivateData.PSData.DefaultConfig.Preflight
            MobileDeployments = "$fixture/logs"; SSHKeyPath = "$fixture/key"
        }
        $options = [pscustomobject]@{
            ScanTimeoutMinutes = 1; Force = $false; DefinitionMaxAgeDays = 30
            LinuxScanPaths = @("/fixture path/with 'quote'"); WindowsScanPaths = @('C:')
            SymantecScanName = ''; SymantecScanExecutable = ''
        }
        Assert ((Get-LinuxScanScript $options).Contains('/usr/local/bin')) 'Older configuration did not receive default tool directories'
        if ((Get-Command bash -ErrorAction SilentlyContinue) -and (Get-Command jq -ErrorAction SilentlyContinue)) {
            $tools = Join-Path $fixture 'tools'
            New-Item -ItemType Directory -Path $tools | Out-Null
            [IO.File]::WriteAllText("$tools/dzdo", "#!/usr/bin/env bash`nexport PATH=/usr/bin:/bin`nexec `"`$@`"`n")
            $realJq = (Get-Command jq -CommandType Application).Source
            [IO.File]::WriteAllText("$tools/jq", "#!/bin/bash`nexec $(ConvertTo-BashArgument $realJq) " + '"$@"' + "`n")
            [IO.File]::WriteAllText("$tools/clamscan", @'
#!/usr/bin/env bash
if [[ "$1" == '--version' ]]; then
    printf 'ClamAV 0.103/12345/%s\n' "${MOBILE_TEST_DEFINITION_DATE:-$(date -u '+%a %b %d 00:00:00 %Y')}"
else
    printf '%s\n' "$@" > "$MOBILE_TEST_SCAN_ARGS"
    sleep "${MOBILE_TEST_SCAN_DELAY:-0}"
    echo 'fixture scanner output'
    exit "${MOBILE_TEST_SCAN_CODE:-0}"
fi
'@)
            [IO.File]::WriteAllText("$tools/systemd-run", @'
#!/usr/bin/env bash
printf 'dispatch\n' >> "$MOBILE_TEST_DISPATCHES"
shift
PATH=/usr/bin:/bin nohup "$@" </dev/null >/dev/null 2>&1 9>&- &
printf '%s' "$!" > "$MOBILE_TEST_WORKER_PID"
'@)
            [IO.File]::WriteAllText("$tools/systemctl", @'
#!/usr/bin/env bash
pid="$(/bin/cat "$MOBILE_TEST_WORKER_PID" 2>/dev/null)"
state="$(ps -o stat= -p "${pid:-0}" 2>/dev/null)"
if [[ -n "$state" && "$state" != Z* ]]; then echo ActiveState=active; else echo ActiveState=inactive; fi
'@)
            [IO.File]::WriteAllText("$tools/DoScan.exe", "#!/usr/bin/env bash`necho fixture-sep-output`nexit `${MOBILE_TEST_SEP_CODE:-0}`n")
            Get-ChildItem $tools -File | ForEach-Object { & chmod +x $_.FullName }
            $environmentNames = @('PATH', 'MOBILE_TEST_SCAN_ARGS', 'MOBILE_TEST_SCAN_CODE', 'MOBILE_TEST_SCAN_DELAY',
                'MOBILE_TEST_DISPATCHES', 'MOBILE_TEST_WORKER_PID', 'MOBILE_TEST_SEP_CODE', 'MOBILE_TEST_DEFINITION_DATE')
            $savedEnvironment = @{}
            foreach ($name in $environmentNames) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }
            try {
                $env:PATH = "$tools" + [IO.Path]::PathSeparator + $env:PATH
                $env:MOBILE_TEST_SCAN_ARGS = "$fixture/scan-args"
                $env:MOBILE_TEST_DISPATCHES = "$fixture/dispatches"
                $env:MOBILE_TEST_WORKER_PID = "$fixture/worker-pid"
                $options | Add-Member -NotePropertyName LinuxToolDirectories -NotePropertyValue @($tools, '/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin')
                $options | Add-Member -NotePropertyName Rescan -NotePropertyValue $false
                $options | Add-Member -NotePropertyName LinuxScanStateDirectory -NotePropertyValue "$fixture/linux-state"
                $options | Add-Member -NotePropertyName WindowsScanStateDirectory -NotePropertyValue "$fixture/windows-state"
                $mountInfoPath = "$fixture/mountinfo"
                @'
20 1 0:1 / / rw - xfs /dev/root rw
21 20 0:2 / /mnt/team\040share.[a]+ rw - nfs server:/team rw
22 20 0:3 / /mnt/nfs4 rw - nfs4 server:/v4 rw
23 20 0:2 /subdir /mnt/bind\134path rw - nfs server:/team rw
24 20 0:4 / /mnt/local rw - ext4 /dev/local rw
25 20 0:5 / /mnt/smb rw - cifs //server/share rw
'@ | Set-Content $mountInfoPath
                $path = "$fixture/preflight.sh"
                function Invoke-Linux {
                    param($Computers,$Script,$KeyPath)
                    [IO.File]::WriteAllText($path, $Script.Replace('/proc/self/mountinfo', $mountInfoPath))
                    & bash -n $path
                    Assert ($LASTEXITCODE -eq 0) 'Generated Linux reader/dispatch script is invalid Bash'
                    $output = & bash $path
                    [pscustomobject]@{ Target=$Computers[0]; ExitCode=$LASTEXITCODE; StdOut=($output -join "`n"); StdErr='' }
                }
                function Query-LinuxScan {
                    $observation=@(Invoke-MobileScanQuery -Platform Linux -Computers @('fixture-linux') -Options $options)[0]
                    Get-MobileScanEvidence -Platform Linux -Observation $observation -Options $options
                }
                foreach ($definitionDate in @([datetime]::UtcNow.AddDays(-31).ToString('yyyy-MM-dd'), 'invalid', [datetime]::UtcNow.AddDays(1).ToString('yyyy-MM-dd'))) {
                    $env:MOBILE_TEST_DEFINITION_DATE = $definitionDate
                    $linux = Query-LinuxScan
                    Assert ($linux.ScanStatus -eq 'BlockedDefinitions' -and -not (Test-Path $env:MOBILE_TEST_DISPATCHES)) 'Linux dispatched with stale/unknown/future definitions'
                }
                $options.Force = $true
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'Starting') 'Force did not override Linux definition gate'
                for ($i = 0; $i -lt 100; $i++) {
                    Start-Sleep -Milliseconds 40
                    $linux = Query-LinuxScan
                    if ($linux.ScanStatus -eq 'Clean') { break }
                }
                Assert ($linux.ScanStatus -eq 'Clean') 'Forced Linux scan did not complete'
                $options.Force = $false
                Remove-Item Env:MOBILE_TEST_DEFINITION_DATE
                Remove-Item $options.LinuxScanStateDirectory -Recurse -Force
                Remove-Item $env:MOBILE_TEST_DISPATCHES
                $env:MOBILE_TEST_SCAN_DELAY = '2'
                $env:MOBILE_TEST_SCAN_CODE = '0'
                $clock = [Diagnostics.Stopwatch]::StartNew()
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'Starting' -and $clock.Elapsed.TotalSeconds -lt 2) 'Preflight waited for the background scan'
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'Running') 'Second preflight did not detect the running scan'
                $options.Rescan = $true
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'Running' -and @(Get-Content $env:MOBILE_TEST_DISPATCHES).Count -eq 1) 'Rescan duplicated an active scan'
                $options.Rescan = $false
                for ($i = 0; $i -lt 100; $i++) {
                    Start-Sleep -Milliseconds 40
                    $linux = Query-LinuxScan
                    if ($linux.ScanStatus -eq 'Clean') { break }
                }
                Assert ($linux.ScanStatus -eq 'Clean' -and $linux.LastScanStatus -eq 'Clean' -and $linux.LastScanCompletedUtc) 'Detached scan completion was not persisted'
                $scanDetails = ($linux.Actions | Where-Object Category -eq AVScan).Details
                $textRun=(Get-Content "$fixture/linux-state/latest" -Raw).Trim()
                Assert ((Get-Content (Join-Path $textRun 'status') -Raw).Trim() -eq 'finished' -and -not (Test-Path (Join-Path $textRun 'result.json'))) 'Linux worker still maintains a JSON state machine'
                Set-Content (Join-Path $textRun 'exit-code') -Value '' -NoNewline
                $incomplete=Query-LinuxScan
                Assert ($incomplete.ScanStatus -eq 'Failed') 'A finished marker without an exit code was accepted as clean'
                '0' | Set-Content (Join-Path $textRun 'exit-code')

                $excluded = @($scanDetails.Current.ExcludedNfsMounts)
                Assert ($excluded.Count -eq 3 -and $excluded -contains '/mnt/team share.[a]+' -and $excluded -contains '/mnt/nfs4' -and $excluded -contains '/mnt/bind\path') 'NFS/NFS4/bind mount discovery or kernel path decoding failed'
                Assert (@($scanDetails.LastCompleted.ExcludedNfsMounts).Count -eq 3) 'Completed history lost NFS exclusions'
                $scanArgs = @(Get-Content $env:MOBILE_TEST_SCAN_ARGS)
                Assert ($scanArgs -contains '--exclude-dir=^/mnt/team share\.\[a\]\+(/|$)' -and $scanArgs -contains '--exclude-dir=^/mnt/bind\\path(/|$)') 'NFS exclusion paths were not regex-escaped or passed as single arguments'
                Assert (-not ($scanArgs -match 'mnt/local|mnt/smb')) 'Local/SMB mounts were excluded as NFS'
                Assert ($linux.DefinitionDate -eq $today) 'Async scan lost definition inventory'
                Assert ('SmbReadiness' -notin $linux.PSObject.Properties.Name -and @($linux.Actions | Where-Object Name -eq 'Workgroup SMB').Count -eq 0) 'Preflight still returned SMB readiness'
                Assert (-not (Get-LinuxScanScript $options).Contains('/proc/sys/crypto/fips_enabled')) 'Preflight still queries FIPS state'
                $linux = Query-LinuxScan
                Assert (@(Get-Content $env:MOBILE_TEST_DISPATCHES).Count -eq 1) 'Status query restarted a completed scan'
                Assert ((Get-Content $env:MOBILE_TEST_SCAN_ARGS) -contains "/fixture path/with 'quote'") 'Scan path quoting changed'
                $originalPaths = $options.LinuxScanPaths
                $options.LinuxScanPaths = @('/different-scope')
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'Clean' -and -not $linux.ScanEvidenceCurrent) 'Historical clean result was accepted for a different scan scope'
                $options.LinuxScanPaths = $originalPaths
                $env:MOBILE_TEST_SCAN_DELAY = '0'
                '20 1 0:1 / / rw - xfs /dev/root rw' | Set-Content $mountInfoPath
                foreach ($code in @(1, 2, 124)) {
                    $env:MOBILE_TEST_SCAN_CODE = [string]$code
                    $options.Rescan = $true
                    $linux = Query-LinuxScan
                    $options.Rescan = $false
                    $expected = @{ 1 = 'ThreatsDetected'; 2 = 'Failed'; 124 = 'TimedOut' }[$code]
                    for ($i = 0; $i -lt 50; $i++) {
                        Start-Sleep -Milliseconds 20
                        $linux = Query-LinuxScan
                        if ($linux.ScanStatus -eq $expected) { break }
                    }
                    Assert ($linux.ScanStatus -eq $expected) 'Background ClamAV exit-code handling failed'
                    Assert (@(($linux.Actions | Where-Object Category -eq AVScan).Details.Current.ExcludedNfsMounts).Count -eq 0) 'Worker reused old NFS exclusions after mounts changed'
                }
                $before = @(Get-Content $env:MOBILE_TEST_DISPATCHES).Count
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'TimedOut' -and @(Get-Content $env:MOBILE_TEST_DISPATCHES).Count -eq $before) 'Status-only mode lost history or dispatched a scan'
                # An inactive unit with an unfinished state is interrupted, not clean/running.
                $plainRun=(Get-Content "$fixture/linux-state/latest" -Raw).Trim()
                'Running' | Set-Content (Join-Path $plainRun 'status')
                $plainInterrupted=Query-LinuxScan
                Assert ($plainInterrupted.ScanStatus -eq 'Interrupted') 'An inactive text-file worker was reported as running'

                $runPath = (Get-Content "$fixture/linux-state/latest" -Raw).Trim()
                Remove-Item (Join-Path $runPath 'status')
                '{"Status":"Running"}' | Set-Content (Join-Path $runPath 'result.json')
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'Interrupted') 'Missing worker was reported as still running'

                Remove-Item $mountInfoPath
                Remove-Item $env:MOBILE_TEST_SCAN_ARGS
                $options.Rescan = $true
                $linux = Query-LinuxScan
                $options.Rescan = $false
                for ($i = 0; $i -lt 50; $i++) {
                    Start-Sleep -Milliseconds 40
                    $linux = Query-LinuxScan
                    if ($linux.ScanStatus -eq 'Failed') { break }
                }
                Assert ($linux.ScanStatus -eq 'Failed' -and -not (Test-Path $env:MOBILE_TEST_SCAN_ARGS)) 'Scanner ran despite failed NFS discovery'

                # Run the actual Windows worker with a fake executable, without Task Scheduler.
                $runDirectory = "$fixture/windows-state/fixture-run"
                New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
                $workerOptions = [pscustomobject]@{
                    SymantecScanExecutable = "$tools/DoScan.exe"; WindowsScanPaths = @('C:')
                    SymantecScanName = ''; ScanTimeoutMinutes = 1
                }
                $workerOptions | ConvertTo-Json | Set-Content "$runDirectory/options.json"
                $env:MOBILE_TEST_SEP_CODE = '0'
                # Exercise dispatch itself, replacing only the Windows-only ACL setup and scheduler.
                # The shared XML builder's real encoding/settings are covered in Verify-TaskXml.
                $dispatchSource = ${function:Start-WindowsScanJob}.ToString()
                $aclStart = $dispatchSource.IndexOf('    $acl =')
                $aclEnd = $dispatchSource.IndexOf('    $runDirectory =', $aclStart)
                $dispatchSource = $dispatchSource.Remove($aclStart, $aclEnd - $aclStart)
                $dispatch = [scriptblock]::Create($dispatchSource)
                $realXmlBuilder = ${function:New-TaskXML}
                function New-TaskXML {
                    param($Description,$ToEncode,$TriggerConfigs,$ExecutionTimeLimit)
                    Assert ($TriggerConfigs.Count -eq 0 -and $ExecutionTimeLimit -eq 'PT6M') 'Preflight XML gained an automatic trigger or lost its timeout'
                    $script:scanInvocation = $ToEncode
                    '<Task>fixture encoded action</Task>'
                }
                function Register-ScheduledTask {
                    [CmdletBinding()] param($TaskName,$Xml,$User,[switch]$Force)
                    Assert ($TaskName -eq 'Mobiles-PreflightAV' -and $Xml -eq '<Task>fixture encoded action</Task>' -and $User -eq 'SYSTEM') 'Preflight did not register the shared XML as SYSTEM'
                    $script:registeredScan = $TaskName
                }
                function Start-ScheduledTask { [CmdletBinding()] param($TaskName)
                    Assert ($TaskName -eq $script:registeredScan) 'Preflight did not explicitly start the registered task'
                }
                function New-ScheduledTaskAction { throw 'Preflight bypassed New-TaskXML' }
                function New-ScheduledTaskSettingsSet { throw 'Preflight bypassed New-TaskXML' }
                $dispatchOptions = [pscustomobject]@{ WindowsScanPaths=@('C:'); SymantecScanName=''; ScanTimeoutMinutes=1 }
                $job = & $dispatch -Options $dispatchOptions -Worker (Get-WindowsScanWorker) -Root "$fixture/windows state's" -Executable "$tools/DoScan.exe"
                Assert ($job.State.Status -eq 'Starting' -and -not (Test-Path (Join-Path $job.RunDirectory 'worker.ps1'))) 'Preflight wrote an executable worker or lost its starting state'
                & ([scriptblock]::Create($script:scanInvocation))
                $dispatchResult = Read-WindowsScan $job.RunDirectory
                $dispatchResult.Status = Get-MobileScanOutcome Windows $dispatchResult
                Assert ($dispatchResult.Status -eq 'CompletedNeedsReview') 'Encoded worker invocation lost its quoted state path or scan result'
                ${function:New-TaskXML} = $realXmlBuilder
                & (Get-WindowsScanWorker) -RunDirectory $runDirectory
                $completed = Read-WindowsScan $runDirectory
                $completed.Status = Get-MobileScanOutcome Windows $completed
                Assert ($completed.Status -eq 'CompletedNeedsReview' -and $completed.CompletedUtc) 'SEP worker exit zero was called clean or not persisted'
                $env:MOBILE_TEST_SEP_CODE = '2'
                & (Get-WindowsScanWorker) -RunDirectory $runDirectory
                $failedWorker = Read-WindowsScan $runDirectory
                $failedWorker.Status = Get-MobileScanOutcome Windows $failedWorker
                Assert ($failedWorker.Status -eq 'Failed' -and $failedWorker.ExitCode -eq 2) 'SEP worker failure was lost'
                # Query real state logic with mocked registry/scheduler observations.
                Remove-Item (Join-Path $runDirectory 'status')
                Remove-Item "$fixture/windows-state/completed"
                $completed | ConvertTo-Json -Depth 8 | Set-Content "$runDirectory/result.json"
                $completed | ConvertTo-Json -Depth 8 | Set-Content "$fixture/windows-state/completed.json"
                @{ RunDirectory = $runDirectory } | ConvertTo-Json | Set-Content "$fixture/windows-state/latest.json"
                $script:nativeScanStatus = 4
                function Get-ItemProperty { [CmdletBinding()] param($LiteralPath)
                    [pscustomobject]@{ LatestVirusDefsDate = $today; LatestVirusDefsRevision = 1; Version = 'fixture'
                        CoreServer = 'core.example.test'; GlobalScanStatus = $script:nativeScanStatus }
                }
                function Get-CimInstance { [CmdletBinding()] param($ClassName) @() }
                function Get-ScheduledTask { [CmdletBinding()] param($TaskName) [pscustomobject]@{ State = 'Ready' } }
                function Invoke-Command {
                    [CmdletBinding()] param($ComputerName,$ScriptBlock,$ArgumentList)
                    $value = & $ScriptBlock $ArgumentList
                    $value | Add-Member PSComputerName $ComputerName[0] -Force
                    $value
                }
                function Query-WindowsScan([string]$Date=$today) {
                    $observation=@(Invoke-MobileScanQuery -Platform Windows -Computers @('fixture-win') -Options $options)[0]
                    $observation.Result.DefinitionDate=$Date
                    Get-MobileScanEvidence -Platform Windows -Observation $observation -Options $options
                }

                $windows = Query-WindowsScan
                Assert ($windows.ScanStatus -eq 'CompletedNeedsReview' -and $windows.LastScanCompletedUtc) 'SEP last completed result was not returned'
                $script:nativeScanStatus = 8
                $options.Rescan = $true
                $windows = Query-WindowsScan
                Assert ($windows.ScanStatus -eq 'Running' -and $windows.LastScanStatus -eq 'CompletedNeedsReview') 'Active native SEP scan was not respected'
                $script:nativeScanStatus = 0
                $options.Rescan = $false
                @{ Status = 'Running'; StartedUtc = [datetime]::UtcNow.AddMinutes(-5).ToString('o') } | ConvertTo-Json | Set-Content "$runDirectory/result.json"
                $windows = Query-WindowsScan
                Assert ($windows.ScanStatus -eq 'Interrupted') 'Stale SEP worker was reported as running'
                # Exercise dispatch decisions with only the native scheduler/ACL writer stubbed.
                . ([scriptblock]::Create((Get-WindowsCollector-Registry)))
                $script:windowsDispatches = 0
                function Start-WindowsScanJob {
                    param($Options, $Worker, $Root, $Executable)
                    $script:windowsDispatches++
                    $directory = Join-Path $Root 'new-job'
                    New-Item -ItemType Directory -Path $directory -Force | Out-Null
                    $state = [pscustomobject]@{ Status = 'Starting'; StartedUtc = [datetime]::UtcNow.ToString('o') }
                    'Starting' | Set-Content (Join-Path $directory 'status')
                    $state.StartedUtc | Set-Content (Join-Path $directory 'started-utc')
                    $directory | Set-Content (Join-Path $Root 'latest')
                    [pscustomobject]@{ State = $state; RunDirectory = $directory }
                }
                $options.WindowsScanStateDirectory = "$fixture/dispatch-state"
                $options.SymantecScanExecutable = "$tools/DoScan.exe"
                foreach ($definitionDate in @([datetime]::UtcNow.AddDays(-31).ToString('yyyy-MM-dd'), '', [datetime]::UtcNow.AddDays(1).ToString('yyyy-MM-dd'))) {
                    $scan = Query-WindowsScan $definitionDate
                    Assert ($scan.ScanStatus -eq 'BlockedDefinitions' -and $script:windowsDispatches -eq 0) 'Windows dispatched with stale/unknown/future definitions'
                }
                $options.Force = $true
                $scan = Query-WindowsScan
                $options.Force = $false
                Assert ($scan.ScanStatus -eq 'Starting' -and $script:windowsDispatches -eq 1) 'Windows did not dispatch a missing scan'
                $scan = Query-WindowsScan
                Assert ($scan.ScanStatus -eq 'Starting' -and $script:windowsDispatches -eq 1) 'Windows duplicated a newly queued scan'
                $options.WindowsScanStateDirectory = "$fixture/current-dispatch-state"
                $scan = Query-WindowsScan ([datetime]::UtcNow.AddDays(-30).ToString('yyyy-MM-dd'))
                Assert ($scan.ScanStatus -eq 'Starting' -and $script:windowsDispatches -eq 2) 'Windows rejected definitions at the 30-day boundary'

            } finally {
                foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name]) }
            }
        }

        function Get-MobileData { param($MobileName) [pscustomobject]@{ Windows = @('win-host'); Linux = @('linux-host', 'offline-host') } }
        function Get-DeploymentTaskSelection { param($Platform, $Phase) @('UserRights') }
        function Invoke-Command { [CmdletBinding()] param($ComputerName, $ScriptBlock, $ArgumentList)
            [pscustomobject]@{ PSComputerName = 'win-host'; DefinitionDate = $today; ScanStatus = 'CompletedNeedsReview'
                Actions = @([pscustomobject]@{ Category = 'AVScan'; Name = 'Symantec'; Status = 'CompletedNeedsReview'; Details = $null }); Failures = @() }
        }
        function Invoke-Linux { param($Computers, $Script, $KeyPath)
            $result = [pscustomobject]@{ DefinitionDate = [datetime]::UtcNow.AddDays(-40).ToString('yyyy-MM-dd'); ScanStatus = 'Clean'
                Actions = @([pscustomobject]@{ Category = 'AVScan'; Name = 'ClamAV'; Status = 'Clean'; Details = $null }); Failures = @() }
            [pscustomobject]@{ Target = 'linux-host'; ExitCode = 0; StdOut = ($result | ConvertTo-Json -Depth 8); StdErr = '' }
        }
        $results = @(Invoke-MobileScan fixture -PassThru)
        Assert ($results.Count -eq 3) 'Missing target disappeared from preflight report'
        Assert ($results[1].Definitions -eq 'Stale' -and $results[2].Scan -eq 'Unknown') 'Preflight normalization lost stale/unreachable status'
        Assert (@($results | Where-Object Success).Count -eq 0) 'Preflight claimed readiness without sufficient evidence'
        $log = Get-ChildItem "$fixture/logs" -Filter '*.jsonl' | Select-Object -First 1
        $events = @(Get-Content $log.FullName | ForEach-Object { $_ | ConvertFrom-Json })
        Assert (@($events | Where-Object Event -eq HostResult).Count -eq 3 -and -not $events[-1].Data.Success) 'Preflight failed to persist per-host evidence'
        function Invoke-Linux { param($Computers, $Script, $KeyPath) throw 'fixture SSH dispatch failure' }
        $results = @(Invoke-MobileScan dispatch-failed -PassThru)
        Assert ($results.Count -eq 3 -and $results[1].Failures[0].Contains('fixture SSH dispatch failure')) 'Dispatch failure removed planned hosts from the report'
        function Get-MobileData { param($MobileName) [pscustomobject]@{ Windows = @(); Linux = @('linux-host') } }
        function Invoke-Linux { param($Computers, $Script, $KeyPath)
            $result = [pscustomobject]@{ DefinitionDate = $today; ScanStatus = 'Clean'; ScanEvidenceCurrent = $true
                Actions = @([pscustomobject]@{ Category = 'AVScan'; Name = 'ClamAV'; Status = 'Clean'; Details = $null }); Failures = @() }
            [pscustomobject]@{ Target = 'linux-host'; ExitCode = 0; StdOut = ($result | ConvertTo-Json -Depth 8); StdErr = '' }
        }
        $results = @(Invoke-MobileScan av-ready -PassThru)
        Assert ($results[0].Success -and $results[0].Readiness -eq 'Ready' -and 'SMB' -notin $results[0].PSObject.Properties.Name) 'AV readiness still depends on SMB checks'
        function Get-MobileData { param($MobileName) [pscustomobject]@{ Windows = @('win-host'); Linux = @() } }
        function Invoke-Command { [CmdletBinding()] param($ComputerName, $ScriptBlock, $ArgumentList)
            [pscustomobject]@{ PSComputerName = 'win-host'; DefinitionDate = $today; ScanStatus = 'Running'
                Actions = @([pscustomobject]@{ Category = 'AVScan'; Name = 'Symantec'; Status = 'Running'; Details = $null }); Failures = @() }
        }
        $results = @(Invoke-MobileScan pending -PassThru)
        Assert ($results[0].Readiness -eq 'Pending') 'Running scan was labeled as failed'
        $pending = Get-ChildItem "$fixture/logs" -Filter '*-pending-*.log' | Select-Object -First 1
        Assert ((Get-Content $pending.FullName -Raw).Contains('Overall result: PENDING')) 'Pending audit summary was labeled as failed'
        $null = Invoke-MobileScan forced-controls -Rescan -Force -PassThru
        $controlLog = Get-ChildItem "$fixture/logs" -Filter '*-forced-controls-*.jsonl' | Select-Object -First 1
        $controlEvents = @(Get-Content $controlLog.FullName | ForEach-Object { $_ | ConvertFrom-Json })
        $controls = ($controlEvents | Where-Object Event -eq ScanOptions).Data
        Assert ($controls.Force -and $controls.Rescan -and $controls.DefinitionMaxAgeDays -eq 30 -and $controls.ScanTimeoutMinutes -eq 240) 'Scan controls or configured policy were not propagated'
        Assert (@($controlEvents | Where-Object Procedure -ne Scan).Count -eq 0) 'New scan audits retained the old procedure name'
        $savedTimeout = $script:Config.Preflight.ScanTimeoutMinutes
        try {
            $script:Config.Preflight.ScanTimeoutMinutes = 0
            $rejected = $false
            try { Invoke-MobileScan invalid-policy } catch { $rejected = $true }
            Assert $rejected 'Invalid configured scan timeout was accepted'
        } finally { $script:Config.Preflight.ScanTimeoutMinutes = $savedTimeout }
        foreach ($retired in @('SkipScans','ForceScan','DefinitionMaxAgeDays','ScanTimeoutMinutes')) {
            $rejected = $false
            try { Invoke-MobileScan -MobileName conflict @{$retired=1} } catch [System.Management.Automation.ParameterBindingException] { $rejected = $true }
            Assert $rejected "Removed public scan option still accepted: $retired"
        }
        'PASS: detached scans, persistent results, duplicate suppression, rescans and repeated status queries, pending/interrupted states, scope checks, AV-only readiness, and audit records.'
    } $fixture $root
} finally {
    Remove-Module $module -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
