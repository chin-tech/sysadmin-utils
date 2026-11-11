# Capture the real telemetry renderer without contacting remote machines.
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot -Parent) 'MobileManager.psm1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
$source=$ast.EndBlock.Statements | Where-Object {$_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Format-HostCollector'} | ForEach-Object {$_.Extent.Text}
$module=New-Module -ScriptBlock ([scriptblock]::Create($source))
try {
    & $module {
        function Assert($condition,$message){if(-not $condition){throw $message}}
        $script:lines=[Collections.Generic.List[string]]::new()
        function Write-Host {param($Object,$ForegroundColor,[switch]$NoNewline) $script:lines.Add([string]$Object)}
        $summary=[pscustomobject]@{Kernel='fixture-kernel';AVDefs='2026-11-10';LastUpdate='2026-11-09';DiskFreeGB=0;PackageCount=0;AdminRotateVersion='present';IvantiVersion='fixture-agent';IvantiCoreServer='core.example';License='Licensed'}
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
        foreach($header in @('HOST','OS','KERNEL','AV DEFS','LAST UPDATE','FREE GB','LAPS','PKGS')){
            Assert ($winText.Contains($header) -and $linuxText.Contains($header)) "Shared column missing: $header"
        }
        Assert ($winText.Contains('Windows connection failed') -and -not $winText.Contains('Linux connection failed') -and $linuxText.Contains('Linux connection failed')) 'Failures were not grouped with their platform'
        $zeroRow=$script:lines | Where-Object {$_ -match '^\s+LINUX-A\s'}
        Assert ([regex]::Matches($zeroRow,'\b0\b').Count -eq 2) 'Zero free space/package count was displayed as unknown'
        $script:lines.Clear()
        Format-HostCollector -InputObject @($windows)
        Assert (-not (($script:lines -join "`n").Contains('Linux hosts'))) 'Empty platform table was rendered'
        'PASS: platform-separated telemetry, shared/platform-only columns, legacy OS labels, failures, zero values and pipeline input.'
    }
} finally {Remove-Module $module -ErrorAction SilentlyContinue}
