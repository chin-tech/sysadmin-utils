# Offline regression checks. No domain, remote machine, proprietary software, or Pester required.
# Run: pwsh -NoProfile -File ./tests/Verify-MobileChanges.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mobile-review-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $fixture | Out-Null

# Extract the actual implementation under test without executing module initialization.
$tokens = $null
$issues = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $root 'MobileManager.psm1'), [ref]$tokens, [ref]$issues)
if ($issues.Count) { throw ($issues.Message -join "`n") }
$names = @('Set-MobileConfig', 'Write-MobileFile', 'Get-MobileData', 'Set-Groups',
    'Resolve-GroupType', 'Get-LinuxDeployScript', 'New-LinuxTask-LeaveDomain', 'ConvertTo-BashArgument')
$parts = @($ast.FindAll({ param($node)
    ($node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names) -or
    ($node -is [System.Management.Automation.Language.TypeDefinitionAst] -and $node.Name -in @('GroupType', 'LinuxAccountType')) -or
    ($node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -in @('$script:GroupMetadata', '$script:WindowsDeployBlock'))
}, $false) | ForEach-Object { $_.Extent.Text })
$testModule = New-Module -ScriptBlock ([scriptblock]::Create($parts -join "`n"))
try {
    & $testModule {
        param($fixture, $root)
        function Assert($condition, $message) { if (-not $condition) { throw $message } }
        $script:Config = [pscustomobject]@{
            nfsHomeRoot = $fixture; NfsHome = "$fixture/home"; MobileRoot = "$fixture/mobiles"
            MobileEntries = "$fixture/entries"; mobileDefaultUsers = "$fixture/default"
            MobileDump = "$fixture/dump"; MobileDeployments = "$fixture/deployments"
            SshKeyName = 'deployer'; SSHKeyPath = "$fixture/key"; GpoID = [guid]::Empty.ToString()
            fallbackPass = 'fixture-only'; curLuks = 'fixture-only'; encryptionPin = 'fixture-only'
        }
        Set-MobileConfig @{ MobileRoot = "$fixture/new-root"; MobileDump = "$fixture/explicit-dump" }
        Assert ($script:Config.MobileEntries -eq "$fixture/new-root/entries") 'Derived entry path was not updated'
        Assert ($script:Config.MobileDump -eq "$fixture/explicit-dump") 'Explicit path was overwritten'
        Set-MobileConfig @{ NfsHome = "$fixture/new-home"; SshKeyName = 'custom-key' }
        Assert ($script:Config.SSHKeyPath -eq "$fixture/new-home/.ssh/custom-key") 'SSH path was not derived'
        $previous = $script:Config
        $rejected = $false
        try { Set-MobileConfig @{ GpoID = 'invalid' } } catch { $rejected = $true }
        Assert ($rejected -and [object]::ReferenceEquals($previous, $script:Config)) 'Invalid configuration changed module state'

        # Stub only dependencies outside the definition reader/writer.
        function Get-UserFullName($UserName, $FullName) { $FullName }
        Add-Type 'public class Sha512Crypt { public static string Crypt(string value) { return "fixture-hash"; } }'
        $entries = Join-Path $fixture 'entries'
        $defaults = Join-Path $fixture 'defaults'
        New-Item -ItemType Directory -Path $entries, $defaults | Out-Null
        $mobile = [pscustomobject]@{
            MobileName = 'roundtrip'; WindowsComputers = @('WIN01'); LinuxComputers = @('LNX01')
            Users = @([pscustomobject]@{ username = 'alice'; groups = 'priv;dtrw'; fullname = 'Doe, "Alice"' })
        }
        Write-MobileFile $mobile -mobilesPath $entries
        $data = Get-MobileData 'roundtrip' -mobileEntriesPath $entries -defaultUserpath $defaults -fallbackPass 'fixture'
        Assert ($data.Windows -contains 'WIN01' -and $data.Linux -contains 'LNX01') 'Host lists did not round-trip'
        Assert ($data.AllUsers[0].FullName -eq 'Doe, "Alice"') 'CSV full name did not round-trip'
        Assert ($data.AllUsers.Count -eq 3) 'Roles did not round-trip'
        $mobile.MobileName = '../escape'
        $rejected = $false
        try { Write-MobileFile $mobile -mobilesPath $entries } catch { $rejected = $true }
        Assert $rejected 'Unsafe mobile filename accepted'
        @'
[users]
username,groups,name
legacy,,Legacy User
'@ | Set-Content (Join-Path $entries 'legacy')
        $legacy = Get-MobileData 'legacy' -mobileEntriesPath $entries -defaultUserpath $defaults -fallbackPass 'fixture'
        Assert ($legacy.AllUsers[0].FullName -eq 'Legacy User') 'Legacy name column lost compatibility'

        function Get-LocalUser { [CmdletBinding()] param($Name)
            if ($script:mode -eq 'missing') { if ($ErrorActionPreference -eq 'Stop') { throw 'Missing' }; return }
            [pscustomobject]@{ Enabled = ($script:mode -ne 'disabled'); SID = [pscustomobject]@{ Value = 'fixture-sid' } }
        }
        function Set-LocalUser { [CmdletBinding()] param($Name, $FullName, $Password, $Description) }
        function New-LocalUser { [CmdletBinding()] param($Name, $FullName, $Password, $Description) throw 'Creation failed' }
        function Get-LocalGroup { [CmdletBinding()] param($Name) [pscustomobject]@{ Name = $Name } }
        function Get-LocalGroupMember { [CmdletBinding()] param($Group)
            if ($script:mode -ne 'membership') { [pscustomobject]@{ SID = [pscustomobject]@{ Value = 'fixture-sid' } } }
        }
        function Add-LocalGroupMember { [CmdletBinding()] param($Group, $Member) }
        function Get-BitLockerVolume { }
        function Get-Tpm { [pscustomobject]@{ IsPresent = $false; IsEnabled = $false } }
        function Remove-Computer { [CmdletBinding()] param($WorkGroupName, [switch]$Force, $Restart) $script:departures++ }
        $payload = [pscustomobject]@{
            MobileName = 'fixture'; Disjoin = $true; TaskData = @()
            AllUsers = @([pscustomobject]@{ Name = 'alice.local'; FullName = 'Alice'; Password = $null
                Description = 'Fixture'; MustChangePassword = $false; WindowsGroups = @('Users') })
        }
        foreach ($mode in @('ready', 'missing', 'disabled', 'membership')) {
            $script:mode = $mode
            $script:departures = 0
            $result = & $script:WindowsDeployBlock $payload
            Assert ($script:departures -eq $(if ($mode -eq 'ready') { 1 } else { 0 })) "Incorrect disjoin behavior: $mode"
            Assert ($result.Success -eq ($mode -eq 'ready')) "Incorrect success result: $mode"
        }

        function New-LinuxTask-CreateDirectory { '# create directory' }
        function New-LinuxTask-AddUsers { param($Users, $HomeBase) '# account creation marker' }
        $linux = Get-LinuxDeployScript -AllUsers $data.AllUsers -Disjoin -b64kt 'YWJj' -SkipLuks -SkipLogrotate
        Assert ($linux.IndexOf('# account creation marker') -lt $linux.IndexOf('# Verify the account')) 'Linux verification precedes account creation'
        Assert ($linux.IndexOf('# Verify the account') -lt $linux.IndexOf('# Task: Domain Departure')) 'Linux departure precedes verification'
        $linuxPath = Join-Path $fixture 'linux.sh'
        [IO.File]::WriteAllText($linuxPath, $linux)
        if (Get-Command bash -ErrorAction SilentlyContinue) {
            & bash -n $linuxPath
            Assert ($LASTEXITCODE -eq 0) 'Generated Linux script is invalid Bash'
            $departure = New-LinuxTask-LeaveDomain 'YWJj'
            $guard = @'
declare -a failures=('provisioning failed')
record_action() { printf '%s\n' "$3"; }
record_failure() { exit 10; }
dzdo() { exit 11; }
'@ + "`n" + $departure
            $guardPath = Join-Path $fixture 'guard.sh'
            [IO.File]::WriteAllText($guardPath, $guard)
            $output = & bash $guardPath
            Assert ($LASTEXITCODE -eq 0 -and $output -eq 'Skipped') 'Linux failure did not block domain departure'
        }
        'PASS: configuration, definition round trips, Windows readiness gates, and Linux departure ordering/gate.'
    } $fixture $root
} finally {
    Remove-Module $testModule -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
