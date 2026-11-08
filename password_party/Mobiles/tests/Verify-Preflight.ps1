# Offline preflight checks. Uses fake scanners and mocked transports only.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobile-preflight-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join '; ') }
$names = @('Start-WindowsPreflightScanJob', 'Get-WindowsPreflightScanWorker', 'Get-WindowsPreflightScanState', 'Get-LinuxPreflightScanWorker', 'Get-MobileDefinitionAssessment', 'Get-WindowsPreflightBlock', 'Get-LinuxPreflightScript', 'Invoke-MobilePreflight',
    'Get-WindowsCollector-Registry', 'Get-WindowsCollector-Symantec', 'Get-WindowsCollector-Ivanti',
    'ConvertTo-BashArgument', 'New-MobileRunLog', 'Write-MobileRunEvent', 'Format-MobileRunEvent', 'ConvertTo-MobileLogLines')
$source = $ast.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -in $names
} | ForEach-Object { $_.Extent.Text }
$module = New-Module -ScriptBlock ([scriptblock]::Create($source -join "`n"))
try {
    & $module {
        param($fixture, $root)
        function Assert($condition, $message) { if (-not $condition) { throw $message } }
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
            SkipScans = $false; ScanTimeoutMinutes = 1; ForceScan = $false; DefinitionMaxAgeDays = 30
            LinuxScanPaths = @("/fixture path/with 'quote'"); WindowsScanPaths = @('C:')
            SymantecScanName = ''; SymantecScanExecutable = ''
        }
        Assert ((Get-LinuxPreflightScript $options).Contains('/usr/local/bin')) 'Older configuration did not receive default tool directories'
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
                function Query-LinuxScan {
                    [IO.File]::WriteAllText($path, (Get-LinuxPreflightScript $options).Replace('/proc/self/mountinfo', $mountInfoPath))
                    & bash -n $path
                    Assert ($LASTEXITCODE -eq 0) 'Generated async Linux script is invalid Bash'
                    $output = & bash $path
                    Assert ($LASTEXITCODE -eq 0) 'Linux preflight dispatch/query failed'
                    ($output -join "`n") | ConvertFrom-Json
                }
                foreach ($definitionDate in @([datetime]::UtcNow.AddDays(-31).ToString('yyyy-MM-dd'), 'invalid', [datetime]::UtcNow.AddDays(1).ToString('yyyy-MM-dd'))) {
                    $env:MOBILE_TEST_DEFINITION_DATE = $definitionDate
                    $linux = Query-LinuxScan
                    Assert ($linux.ScanStatus -eq 'BlockedDefinitions' -and -not (Test-Path $env:MOBILE_TEST_DISPATCHES)) 'Linux dispatched with stale/unknown/future definitions'
                }
                $options.ForceScan = $true
                $options.SkipScans = $true
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'NotStarted' -and -not (Test-Path $env:MOBILE_TEST_DISPATCHES)) 'ForceScan overrode query-only mode'
                $options.SkipScans = $false
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'Starting') 'ForceScan did not override Linux definition gate'
                for ($i = 0; $i -lt 100; $i++) {
                    Start-Sleep -Milliseconds 40
                    $linux = Query-LinuxScan
                    if ($linux.ScanStatus -eq 'Clean') { break }
                }
                Assert ($linux.ScanStatus -eq 'Clean') 'Forced Linux scan did not complete'
                $options.ForceScan = $false
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
                $excluded = @($scanDetails.Current.ExcludedNfsMounts)
                Assert ($excluded.Count -eq 3 -and $excluded -contains '/mnt/team share.[a]+' -and $excluded -contains '/mnt/nfs4' -and $excluded -contains '/mnt/bind\path') 'NFS/NFS4/bind mount discovery or kernel path decoding failed'
                Assert (@($scanDetails.LastCompleted.ExcludedNfsMounts).Count -eq 3) 'Completed history lost NFS exclusions'
                $scanArgs = @(Get-Content $env:MOBILE_TEST_SCAN_ARGS)
                Assert ($scanArgs -contains '--exclude-dir=^/mnt/team share\.\[a\]\+(/|$)' -and $scanArgs -contains '--exclude-dir=^/mnt/bind\\path(/|$)') 'NFS exclusion paths were not regex-escaped or passed as single arguments'
                Assert (-not ($scanArgs -match 'mnt/local|mnt/smb')) 'Local/SMB mounts were excluded as NFS'
                Assert ($linux.DefinitionDate -eq $today) 'Async scan lost definition inventory'
                Assert ('SmbReadiness' -notin $linux.PSObject.Properties.Name -and @($linux.Actions | Where-Object Name -eq 'Workgroup SMB').Count -eq 0) 'Preflight still returned SMB readiness'
                Assert (-not (Get-LinuxPreflightScript $options).Contains('/proc/sys/crypto/fips_enabled')) 'Preflight still queries FIPS state'
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
                $options.SkipScans = $true
                $before = @(Get-Content $env:MOBILE_TEST_DISPATCHES).Count
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'TimedOut' -and @(Get-Content $env:MOBILE_TEST_DISPATCHES).Count -eq $before) 'Status-only mode lost history or dispatched a scan'
                # An inactive unit with an unfinished state is interrupted, not clean/running.
                $pointer = Get-Content "$fixture/linux-state/latest.json" -Raw | ConvertFrom-Json
                '{"Status":"Running"}' | Set-Content (Join-Path $pointer.RunDirectory 'result.json')
                $linux = Query-LinuxScan
                Assert ($linux.ScanStatus -eq 'Interrupted') 'Missing worker was reported as still running'
                $options.SkipScans = $false

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
                & (Get-WindowsPreflightScanWorker) -RunDirectory $runDirectory
                $completed = Get-Content "$runDirectory/result.json" -Raw | ConvertFrom-Json
                Assert ($completed.Status -eq 'CompletedNeedsReview' -and $completed.CompletedUtc) 'SEP worker exit zero was called clean or not persisted'
                $env:MOBILE_TEST_SEP_CODE = '2'
                & (Get-WindowsPreflightScanWorker) -RunDirectory $runDirectory
                $failedWorker = Get-Content "$runDirectory/result.json" -Raw | ConvertFrom-Json
                Assert ($failedWorker.Status -eq 'Failed' -and $failedWorker.ExitCode -eq 2) 'SEP worker failure was lost'
                # Query real state logic with mocked registry/scheduler observations.
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
                $windows = & (Get-WindowsPreflightBlock) $options
                Assert ($windows.ScanStatus -eq 'CompletedNeedsReview' -and $windows.LastScanCompletedUtc) 'SEP last completed result was not returned'
                $script:nativeScanStatus = 8
                $options.Rescan = $true
                $windows = & (Get-WindowsPreflightBlock) $options
                Assert ($windows.ScanStatus -eq 'Running' -and $windows.LastScanStatus -eq 'CompletedNeedsReview') 'Active native SEP scan was not respected'
                $script:nativeScanStatus = 0
                $options.Rescan = $false
                @{ Status = 'Running'; StartedUtc = [datetime]::UtcNow.AddMinutes(-5).ToString('o') } | ConvertTo-Json | Set-Content "$runDirectory/result.json"
                $windows = & (Get-WindowsPreflightBlock) $options
                Assert ($windows.ScanStatus -eq 'Interrupted') 'Stale SEP worker was reported as running'
                # Exercise dispatch decisions with only the native scheduler/ACL writer stubbed.
                . ([scriptblock]::Create((Get-WindowsCollector-Registry)))
                $script:windowsDispatches = 0
                function Start-WindowsPreflightScanJob {
                    param($Options, $Worker, $Root, $Executable)
                    $script:windowsDispatches++
                    $directory = Join-Path $Root 'new-job'
                    New-Item -ItemType Directory -Path $directory -Force | Out-Null
                    $state = [pscustomobject]@{ Status = 'Starting'; StartedUtc = [datetime]::UtcNow.ToString('o') }
                    $state | ConvertTo-Json | Set-Content (Join-Path $directory 'result.json')
                    @{ RunDirectory = $directory } | ConvertTo-Json | Set-Content (Join-Path $Root 'latest.json')
                    [pscustomobject]@{ State = $state; RunDirectory = $directory }
                }
                $options.WindowsScanStateDirectory = "$fixture/dispatch-state"
                $options.SymantecScanExecutable = "$tools/DoScan.exe"
                foreach ($definitionDate in @([datetime]::UtcNow.AddDays(-31).ToString('yyyy-MM-dd'), '', [datetime]::UtcNow.AddDays(1).ToString('yyyy-MM-dd'))) {
                    $scan = Get-WindowsPreflightScanState -Options $options -Worker (Get-WindowsPreflightScanWorker) -DefinitionDate $definitionDate
                    Assert ($scan.Status -eq 'BlockedDefinitions' -and $script:windowsDispatches -eq 0) 'Windows dispatched with stale/unknown/future definitions'
                }
                $options.ForceScan = $true
                $scan = Get-WindowsPreflightScanState -Options $options -Worker (Get-WindowsPreflightScanWorker)
                $options.ForceScan = $false
                Assert ($scan.Status -eq 'Starting' -and $script:windowsDispatches -eq 1) 'Windows did not dispatch a missing scan'
                $scan = Get-WindowsPreflightScanState -Options $options -Worker (Get-WindowsPreflightScanWorker)
                Assert ($scan.Status -eq 'Starting' -and $script:windowsDispatches -eq 1) 'Windows duplicated a newly queued scan'
                $options.WindowsScanStateDirectory = "$fixture/current-dispatch-state"
                $scan = Get-WindowsPreflightScanState -Options $options -Worker (Get-WindowsPreflightScanWorker) -DefinitionDate ([datetime]::UtcNow.AddDays(-30).ToString('yyyy-MM-dd'))
                Assert ($scan.Status -eq 'Starting' -and $script:windowsDispatches -eq 2) 'Windows rejected definitions at the 30-day boundary'

            } finally {
                foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name]) }
            }
        }

        function Get-MobileData { param($MobileName) [pscustomobject]@{ Windows = @('win-host'); Linux = @('linux-host', 'offline-host') } }
        function Get-DeploymentTaskSelection { param($Platform, $Phase) @('NetworkSharing') }
        function Invoke-Command { [CmdletBinding()] param($ComputerName, $ScriptBlock, $ArgumentList)
            [pscustomobject]@{ PSComputerName = 'win-host'; DefinitionDate = $today; ScanStatus = 'CompletedNeedsReview'
                Actions = @([pscustomobject]@{ Category = 'AVScan'; Name = 'Symantec'; Status = 'CompletedNeedsReview'; Details = $null }); Failures = @() }
        }
        function Invoke-Linux { param($Computers, $Script, $KeyPath)
            $result = [pscustomobject]@{ DefinitionDate = [datetime]::UtcNow.AddDays(-40).ToString('yyyy-MM-dd'); ScanStatus = 'Clean'
                Actions = @([pscustomobject]@{ Category = 'AVScan'; Name = 'ClamAV'; Status = 'Clean'; Details = $null }); Failures = @() }
            [pscustomobject]@{ Target = 'linux-host'; ExitCode = 0; StdOut = ($result | ConvertTo-Json -Depth 8); StdErr = '' }
        }
        $results = @(Invoke-MobilePreflight fixture -PassThru)
        Assert ($results.Count -eq 3) 'Missing target disappeared from preflight report'
        Assert ($results[1].Definitions -eq 'Stale' -and $results[2].Scan -eq 'Unknown') 'Preflight normalization lost stale/unreachable status'
        Assert (@($results | Where-Object Success).Count -eq 0) 'Preflight claimed readiness without sufficient evidence'
        $log = Get-ChildItem "$fixture/logs" -Filter '*.jsonl' | Select-Object -First 1
        $events = @(Get-Content $log.FullName | ForEach-Object { $_ | ConvertFrom-Json })
        Assert (@($events | Where-Object Event -eq HostResult).Count -eq 3 -and -not $events[-1].Data.Success) 'Preflight failed to persist per-host evidence'
        function Invoke-Linux { param($Computers, $Script, $KeyPath) throw 'fixture SSH dispatch failure' }
        $results = @(Invoke-MobilePreflight dispatch-failed -PassThru)
        Assert ($results.Count -eq 3 -and $results[1].Failures[0].Contains('fixture SSH dispatch failure')) 'Dispatch failure removed planned hosts from the report'
        function Get-MobileData { param($MobileName) [pscustomobject]@{ Windows = @(); Linux = @('linux-host') } }
        function Invoke-Linux { param($Computers, $Script, $KeyPath)
            $result = [pscustomobject]@{ DefinitionDate = $today; ScanStatus = 'Clean'; ScanEvidenceCurrent = $true
                Actions = @([pscustomobject]@{ Category = 'AVScan'; Name = 'ClamAV'; Status = 'Clean'; Details = $null }); Failures = @() }
            [pscustomobject]@{ Target = 'linux-host'; ExitCode = 0; StdOut = ($result | ConvertTo-Json -Depth 8); StdErr = '' }
        }
        $results = @(Invoke-MobilePreflight av-ready -PassThru)
        Assert ($results[0].Success -and $results[0].Readiness -eq 'Ready' -and 'SMB' -notin $results[0].PSObject.Properties.Name) 'AV readiness still depends on SMB checks'
        function Get-MobileData { param($MobileName) [pscustomobject]@{ Windows = @('win-host'); Linux = @() } }
        function Invoke-Command { [CmdletBinding()] param($ComputerName, $ScriptBlock, $ArgumentList)
            [pscustomobject]@{ PSComputerName = 'win-host'; DefinitionDate = $today; ScanStatus = 'Running'
                Actions = @([pscustomobject]@{ Category = 'AVScan'; Name = 'Symantec'; Status = 'Running'; Details = $null }); Failures = @() }
        }
        $results = @(Invoke-MobilePreflight pending -PassThru)
        Assert ($results[0].Readiness -eq 'Pending') 'Running scan was labeled as failed'
        $pending = Get-ChildItem "$fixture/logs" -Filter '*-pending-*.log' | Select-Object -First 1
        Assert ((Get-Content $pending.FullName -Raw).Contains('Overall result: PENDING')) 'Pending audit summary was labeled as failed'
        $rejected = $false
        try { Invoke-MobilePreflight conflict -SkipScans -Rescan } catch { $rejected = $true }
        Assert $rejected 'Conflicting scan options were accepted'
        'PASS: detached scans, persistent results, duplicate suppression, rescan/status-only modes, pending/interrupted states, scope checks, AV-only readiness, and audit records.'
    } $fixture $root
} finally {
    Remove-Module $module -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
