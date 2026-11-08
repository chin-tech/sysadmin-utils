# Offline preflight checks. Uses fake scanners and mocked transports only.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobile-preflight-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join '; ') }
$names = @('Get-MobileDefinitionAssessment', 'Get-WindowsPreflightBlock', 'Get-LinuxPreflightScript', 'Invoke-MobilePreflight',
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
        Assert ((Get-MobileDefinitionAssessment ([datetime]::UtcNow.AddDays(-10).ToString('yyyy-MM-dd'))).Status -eq 'Stale') 'Stale definitions were not flagged'
        Assert ((Get-MobileDefinitionAssessment 'ambiguous-date').Status -eq 'Unknown') 'Unknown date was guessed'
        Assert ((Get-MobileDefinitionAssessment ([datetime]::UtcNow.AddDays(2).ToString('yyyy-MM-dd'))).Status -eq 'FutureDate') 'Future definition date was not flagged'
        $script:Config = [pscustomobject]@{
            Preflight = (Import-PowerShellDataFile (Join-Path $root 'MobileManager.psd1')).PrivateData.PSData.DefaultConfig.Preflight
            MobileDeployments = "$fixture/logs"; SSHKeyPath = "$fixture/key"
        }
        $options = [pscustomobject]@{
            SkipScans = $false; ScanTimeoutMinutes = 1; SmbEnabled = $true
            LinuxScanPaths = @("/fixture path/with 'quote'"); WindowsScanPaths = @('C:')
            SymantecScanName = ''; SymantecScanExecutable = ''
        }
        if ((Get-Command bash -ErrorAction SilentlyContinue) -and (Get-Command jq -ErrorAction SilentlyContinue)) {
            $tools = Join-Path $fixture 'tools'
            New-Item -ItemType Directory -Path $tools | Out-Null
            [IO.File]::WriteAllText("$tools/dzdo", "#!/usr/bin/env bash`nexec `"`$@`"`n")
            [IO.File]::WriteAllText("$tools/clamscan", @'
#!/usr/bin/env bash
if [[ "$1" == '--version' ]]; then
    printf 'ClamAV 0.103/12345/%s\n' "$(date -u '+%a %b %d %T %Y')"
else
    printf '%s\n' "$@" > "$MOBILE_TEST_SCAN_ARGS"
    echo 'fixture scanner output'
    exit "${MOBILE_TEST_SCAN_CODE:-0}"
fi
'@)
            [IO.File]::WriteAllText("$tools/cat", @'
#!/usr/bin/env bash
if [[ "$1" == '/proc/sys/crypto/fips_enabled' ]]; then echo 1; else exec /bin/cat "$@"; fi
'@)
            [IO.File]::WriteAllText("$tools/update-crypto-policies", "#!/usr/bin/env bash`necho FIPS`n")
            & chmod +x "$tools/dzdo" "$tools/clamscan" "$tools/cat" "$tools/update-crypto-policies"
            $oldPath = $env:PATH
            $oldArgs = $env:MOBILE_TEST_SCAN_ARGS
            $oldCode = $env:MOBILE_TEST_SCAN_CODE
            try {
                $env:PATH = "$tools" + [IO.Path]::PathSeparator + $oldPath
                $env:MOBILE_TEST_SCAN_ARGS = "$fixture/scan-args"
                foreach ($code in @(0, 1, 2, 124)) {
                    $env:MOBILE_TEST_SCAN_CODE = [string]$code
                    $text = Get-LinuxPreflightScript $options
                    $path = "$fixture/preflight.sh"
                    [IO.File]::WriteAllText($path, $text)
                    & bash -n $path
                    Assert ($LASTEXITCODE -eq 0) 'Linux preflight script is invalid Bash'
                    $output = & bash $path
                    $linux = ($output -join "`n") | ConvertFrom-Json
                    $expected = @{ 0 = 'Clean'; 1 = 'ThreatsDetected'; 2 = 'Failed'; 124 = 'TimedOut' }[$code]
                    Assert ($linux.ScanStatus -eq $expected -and $linux.SmbReadiness -eq 'BlockedByFips') 'Linux scan/FIPS status was incorrect'
                    Assert ($linux.DefinitionDate -eq $today) 'ClamAV definition date was not normalized'
                }
                Assert ((Get-Content $env:MOBILE_TEST_SCAN_ARGS) -contains "/fixture path/with 'quote'") 'Linux scan path quoting changed the path'
                Remove-Item $env:MOBILE_TEST_SCAN_ARGS
                $options.SkipScans = $true
                [IO.File]::WriteAllText($path, (Get-LinuxPreflightScript $options))
                $output = & bash $path
                $linux = ($output -join "`n") | ConvertFrom-Json
                Assert ($linux.ScanStatus -eq 'Skipped' -and -not (Test-Path $env:MOBILE_TEST_SCAN_ARGS)) 'SkipScans executed a scan'
                $options.SkipScans = $false

                # Fake SEP launcher: exit zero must never be called clean.
                [IO.File]::WriteAllText("$tools/DoScan.exe", "#!/usr/bin/env bash`necho fixture-sep-output`nexit 0`n")
                & chmod +x "$tools/DoScan.exe"
                $options.SymantecScanExecutable = "$tools/DoScan.exe"
                function Get-ItemProperty { [CmdletBinding()] param($LiteralPath)
                    [pscustomobject]@{ LatestVirusDefsDate = $today; LatestVirusDefsRevision = 1; Version = 'fixture'; CoreServer = 'core.example.test' }
                }
                function Get-CimInstance { [CmdletBinding()] param($ClassName) @() }
                $windows = & (Get-WindowsPreflightBlock) $options
                Assert ($windows.ScanStatus -eq 'CompletedNeedsReview') 'SEP exit zero was incorrectly called a clean scan'
            } finally {
                $env:PATH = $oldPath
                $env:MOBILE_TEST_SCAN_ARGS = $oldArgs
                $env:MOBILE_TEST_SCAN_CODE = $oldCode
            }
        }

        function Get-MobileData { param($MobileName) [pscustomobject]@{ Windows = @('win-host'); Linux = @('linux-host', 'offline-host') } }
        function Get-DeploymentTaskSelection { param($Platform, $Phase) @('NetworkSharing') }
        function Invoke-Command { [CmdletBinding()] param($ComputerName, $ScriptBlock, $ArgumentList)
            [pscustomobject]@{ PSComputerName = 'win-host'; DefinitionDate = $today; ScanStatus = 'CompletedNeedsReview'; SmbReadiness = 'NotApplicable'
                Actions = @([pscustomobject]@{ Category = 'AVScan'; Name = 'Symantec'; Status = 'CompletedNeedsReview'; Details = $null }); Failures = @() }
        }
        function Invoke-Linux { param($Computers, $Script, $KeyPath)
            $result = [pscustomobject]@{ DefinitionDate = [datetime]::UtcNow.AddDays(-20).ToString('yyyy-MM-dd'); ScanStatus = 'Clean'; SmbReadiness = 'BlockedByFips'
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
        'PASS: definition age, fake ClamAV/SEP scans, FIPS reporting, skip mode, quoting, unreachable hosts, and audit records.'
    } $fixture $root
} finally {
    Remove-Module $module -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
