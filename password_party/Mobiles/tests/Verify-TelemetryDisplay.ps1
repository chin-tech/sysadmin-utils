# Capture the real telemetry renderer without contacting remote machines.
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot -Parent) 'MobileManager.psm1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
$source=$ast.EndBlock.Statements | Where-Object {$_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -in @('Get-MobileTerminalWidth','Write-MobileCenteredText','Write-MobileTable','Format-HostCollector','Format-DeploymentResults','Get-MobileOverview')} | ForEach-Object {$_.Extent.Text}
$module=New-Module -ScriptBlock ([scriptblock]::Create($source -join "`n"))
try {
    & $module {
        function Assert($condition,$message){if(-not $condition){throw $message}}
        $script:lines=[Collections.Generic.List[string]]::new()
        function Write-Host {param($Object,$ForegroundColor,[switch]$NoNewline) $script:lines.Add([string]$Object)}
        function Get-MobileTerminalWidth { 240 }
        $summary=[pscustomobject]@{Kernel='fixture-kernel';AVDefs='2026-11-10';DiskFreeGB=0;AdminRotateVersion='present';IvantiVersion='fixture-agent';IvantiCoreServer='core.example';License='Licensed'}
        $windows=[pscustomobject]@{HostName='win-a';Platform='WIN11';Success=$true;Summary=$summary;Failures=@()}
        $linux=[pscustomobject]@{HostName='linux-a';Platform='RHEL-8.10';PlatformFamily='Linux';Success=$true;Summary=$summary;Failures=@()}
        $badWindows=[pscustomobject]@{HostName='win-offline';Platform='Windows';PlatformFamily='Windows';Success=$false;Summary=$null;Failures=@('Windows connection failed')}
        $badLinux=[pscustomobject]@{HostName='linux-offline';Platform='Linux';PlatformFamily='Linux';Success=$false;Summary=$null;Failures=@('Linux connection failed')}
        @($linux,$windows,$badLinux,$badWindows) | Format-HostCollector
        $display=$script:lines -join "`n"
        $split=$display.IndexOf('Linux hosts')
        Assert ($split -gt $display.IndexOf('Windows hosts')) 'Platform sections missing or unordered'
        $winText=$display.Substring(0,$split)
        $linuxText=$display.Substring($split)
        Assert ($winText.Contains('WIN-A') -and -not $winText.Contains('LINUX-A') -and $linuxText.Contains('LINUX-A') -and -not $linuxText.Contains('WIN-A')) 'Hosts leaked between platform tables'
        Assert ($winText.Contains('IVANTI CORE') -and $winText.Contains('LICENSE') -and -not $linuxText.Contains('IVANTI') -and -not $linuxText.Contains('LICENSE')) 'Windows-only fields leaked into the Linux table'
        foreach($header in @('HOST','OS','KERNEL','AV DEFS','FREE GB','LAPS')){
            Assert ($winText.Contains($header) -and $linuxText.Contains($header)) "Shared column missing: $header"
        }
        Assert ($winText.Contains('Windows connection failed') -and -not $winText.Contains('Linux connection failed') -and $linuxText.Contains('Linux connection failed')) 'Failures were not grouped with their platform'
        $zeroRow=$script:lines | Where-Object {$_ -match '^\s+LINUX-A\s'}
        Assert ([regex]::Matches($zeroRow,'\b0\b').Count -eq 1) 'Zero free space was displayed as unknown'
        $script:lines.Clear()
        Format-HostCollector -InputObject @($windows)
        Assert (-not (($script:lines -join "`n").Contains('Linux hosts'))) 'Empty platform table was rendered'
        Assert (-not (($script:lines -join "`n") -match 'LAST UPDATE|PKGS')) 'Unused telemetry columns remain'

        # Check centering of both the table and each cell at different terminal widths.
        $fixtureRows = @([pscustomobject]@{A='a';B='longer'}; [pscustomobject]@{A='abcdef';B='x'})
        foreach ($terminalWidth in @(40,80,120)) {
            $script:terminalWidth = $terminalWidth
            function Get-MobileTerminalWidth { $script:terminalWidth }
            $script:lines.Clear()
            Write-MobileTable $fixtureRows @('A','B')
            foreach ($line in $script:lines | Where-Object { $_ -notmatch '-\+-' }) {
                Assert ($line.Length -le $terminalWidth) 'Table exceeded the terminal width'
                # Natural table width is 15; the remainder is its left margin.
                $margin = [int][math]::Floor(($terminalWidth - 15) / 2)
                Assert ($line.StartsWith(' ' * $margin)) 'Table was not centered'
                $cells = $line.Substring($margin) -split ' \| '
                foreach ($cell in $cells) {
                    $left = $cell.Length - $cell.TrimStart().Length
                    $right = $cell.Length - $cell.TrimEnd().Length
                    Assert ([math]::Abs($left-$right) -le 1) 'A table cell was not centered'
                }
            }
            $script:lines.Clear()
            @($linux,$windows,$badLinux,$badWindows) | Format-HostCollector
            Assert (@($script:lines | Where-Object Length -gt $terminalWidth).Count -eq 0) 'Telemetry overflowed a narrow terminal'
        }
        $script:terminalWidth = 40
        $script:lines.Clear()
        Write-MobileTable @([pscustomobject]@{A=('x'*70);B="first`nsecond"}) @('A','B')
        Assert ((($script:lines -join '').Replace(' ','').Replace('|','').Replace('-','').Replace('+','') -split 'x').Count -eq 71) 'Wrapped content was lost'
        $script:terminalWidth = 15
        $script:lines.Clear()
        Write-MobileTable @([pscustomobject]@{A='alpha';B='beta';C='gamma'}) @('A','B','C')
        Assert (@($script:lines | Where-Object Length -gt 15).Count -eq 0) 'Small-terminal record fallback overflowed'

        # Exercise deployment and overview reports through their real renderers.
        $script:terminalWidth = 120
        $script:lines.Clear()
        $users = @([pscustomobject]@{BaseName='alice';Name='alice';LinuxName='alice';GroupType='User';MustChangePassword=$false})
        $deployment = @(
            [pscustomobject]@{HostName='win-a.example';Platform='Windows';Actions=@([pscustomobject]@{Category='User';Name='alice';Status='Failed'});Failures=@('account failed')}
            [pscustomobject]@{HostName='linux-a';Platform='Linux';Actions=@([pscustomobject]@{Category='User';Name='alice';Status='Created'});Failures=@()}
        )
        Format-DeploymentResults $deployment $users
        $report = $script:lines -join "`n"
        Assert ($report -match 'win-a.*FAILED' -and $report -match 'linux-a.*OK') 'Per-host account statuses were lost'
        Assert ($report.Contains('[FAILURES]') -and $report.Contains('account failed')) 'Deployment failures were lost'
        $script:lines.Clear()
        function Get-MobileData {
            [pscustomobject]@{AllMobiles=@('demo');MobileUsers=@([pscustomobject]@{Username='alice';Groups=@('users');Name='Alice Example'});Windows=@('win-a');Linux=@('linux-a');AllUsers=$users}
        }
        Get-MobileOverview -MobileName demo -mobileDumpPath ''
        $report = $script:lines -join "`n"
        Assert ($report.Contains('Alice Example') -and $report.Contains('[-] PENDING') -and $report.Contains('MOBILE: demo')) 'Overview information was lost'
        Assert (@($script:lines | Where-Object Length -gt 120).Count -eq 0) 'Overview exceeded terminal width'
        'PASS: centered tables/cells, narrow-terminal wrapping, platform telemetry, zero values, deployment statuses and overview.'
    }
} finally {Remove-Module $module -ErrorAction SilentlyContinue}
