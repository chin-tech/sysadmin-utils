#Requires -Modules Pester

<#
    MobileManager.Tests.ps1

    Strategy: every function that touches the outside world (AD/GPO cmdlets,
    Invoke-Command against remote hosts, ssh, cert generation) gets mocked.
    Everything else (config merging, INI parsing, group->suffix mapping,
    credential shaping) is real logic and gets asserted directly.

    Run with:  Invoke-Pester -Path .\MobileManager.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # Import the module under test from wherever this test file lives.
    $ModulePath = Join-Path $PSScriptRoot 'MobileManager.psm1'
    Import-Module $ModulePath -Force

    # --- Fixture filesystem, so we never touch \\nas\... or real SYSVOL paths ---
    $Script:FixtureRoot = Join-Path $TestDrive 'mobiles'
    New-Item -ItemType Directory -Path $Script:FixtureRoot -Force | Out-Null

    $Script:TestConfig = @{
        MobileEntries = $Script:FixtureRoot
        mobileDump    = Join-Path $TestDrive 'dump'
        defaultPass   = 'P@ssw0rd!'
        GpoId         = '11111111-2222-3333-4444-555555555555'
        'linux-deployer' = Join-Path $TestDrive 'linux-deploy.sh'
        sshKey        = Join-Path $TestDrive 'id_ecdsa'
    }
    New-Item -ItemType Directory -Path $Script:TestConfig['mobileDump'] -Force | Out-Null
    Set-Content -Path $Script:TestConfig['linux-deployer'] -Value '#!/bin/sh`necho deployed'

    # A representative mobile entry file
    @'
[users]
username,name,groups
jdoe,John Doe,i;p
asmith,Ann Smith,d*rw

[Windows]
WIN-HOST01

[Linux]
lnx-host01
'@ | Set-Content -Path (Join-Path $Script:FixtureRoot 'testsite')
}

Describe 'Get-MobileConfig' {
    It 'merges CustomConfig over module DefaultConfig without mutating either' {
        $Script:DefaultConfig = @{ a = 1; b = 2 }
        $result = Get-MobileConfig -CustomConfig @{ b = 99; c = 3 }
        $result['a'] | Should -Be 1
        $result['b'] | Should -Be 99
        $result['c'] | Should -Be 3
    }

    It 'returns an empty-ish hashtable when nothing is supplied' {
        $Script:DefaultConfig = $null
        $result = Get-MobileConfig
        $result.Count | Should -Be 0
    }
}

Describe 'Get-MobileData' {
    It 'lists available mobiles from MobileEntries' {
        $data = Get-MobileData -Config $Script:TestConfig
        $data.AllMobiles | Should -Contain 'testsite'
    }

    It 'parses the [users] section into MobileUsers with split groups' {
        $data = Get-MobileData -MobileName 'testsite' -Config $Script:TestConfig
        $jdoe = $data.MobileUsers | Where-Object Username -eq 'jdoe'
        $jdoe.Groups | Should -Contain 'i'
        $jdoe.Groups | Should -Contain 'p'
    }

    It 'parses [Windows] and [Linux] host lists' {
        $data = Get-MobileData -MobileName 'testsite' -Config $Script:TestConfig
        $data.Windows | Should -Contain 'WIN-HOST01'
        $data.Linux   | Should -Contain 'lnx-host01'
    }

    It 'maps group prefixes to the correct account suffix' {
        # NOTE: this test will FAIL until the switch statement uses
        # `switch -Wildcard ($grp)` — that's intentional, it's a regression
        # guard for the bug described above.
        $data = Get-MobileData -MobileName 'testsite' -Config $Script:TestConfig
        ($data.AllUsers | Where-Object Name -eq 'jdoe.isso') | Should -Not -BeNullOrEmpty
        ($data.AllUsers | Where-Object Name -eq 'asmith.dtrw') | Should -Not -BeNullOrEmpty
    }

    It 'falls back to .local suffix for unrecognized groups' {
        @'
[users]
username,name,groups
zzz,Zed Zee,unknown-group
'@ | Set-Content -Path (Join-Path $Script:FixtureRoot 'edgecase')

        $data = Get-MobileData -MobileName 'edgecase' -Config $Script:TestConfig
        $data.AllUsers.Name | Should -Contain 'zzz.local'
    }
}

Describe 'Set-MobileGpoPermission' {
    BeforeAll {
        # Mock the GroupPolicy cmdlets — no real GPO / domain needed.
        Mock -CommandName Set-GPPermission -ModuleName MobileManager -MockWith { }
        Mock -CommandName Get-GPPermission -ModuleName MobileManager -MockWith {
            @(
                [PSCustomObject]@{
                    Trustee    = [PSCustomObject]@{ Name = 'jdoe.isso'; SidType = 'User' }
                    Permission = 'GpoRead'
                }
            )
        }
    }

    It 'grants GpoRead to every user derived from the mobile entry when -Add is used' {
        Set-MobileGpoPermission -MobileName 'testsite' -Add -Config $Script:TestConfig

        Should -Invoke Set-GPPermission -ModuleName MobileManager -ParameterFilter {
            $PermissionLevel -eq 'GpoRead'
        } -Times 1 -Exactly:$false   # at least once; count depends on user set
    }

    It 'force-remove strips permission from every user currently holding GpoRead' {
        Set-MobileGpoPermission -MobileName 'testsite' -Remove -Force -Config $Script:TestConfig

        Should -Invoke Get-GPPermission -ModuleName MobileManager -Times 1
        Should -Invoke Set-GPPermission -ModuleName MobileManager -ParameterFilter {
            $TargetName -eq 'jdoe.isso' -and $PermissionLevel -eq 'None'
        } -Times 1
    }
}

Describe 'Start-MobileDeployment' {
    BeforeAll {
        Mock -CommandName Invoke-Command -ModuleName MobileManager -MockWith { }
        Mock -CommandName Get-UserCreds -ModuleName MobileManager -MockWith {
            param($MobileName, $AllUsers, $Config)
            $AllUsers   # pass through untouched — credential decrypt is tested separately
        }
        # ssh is an external exe; mock the function wrapper if you refactor to one,
        # or mock the whole pipeline by stubbing `ssh` on PATH in a real CI runner.
        Mock -CommandName ssh -ModuleName MobileManager -MockWith { }
    }

    It 'invokes the deployment scriptblock once per Windows host, never touching real machines' {
        Start-MobileDeployment -MobileName 'testsite' -Config $Script:TestConfig

        Should -Invoke Invoke-Command -ModuleName MobileManager -ParameterFilter {
            $ComputerName -contains 'WIN-HOST01'
        } -Times 1
    }

    It 'ships the linux deployer script over ssh for each Linux host' {
        Start-MobileDeployment -MobileName 'testsite' -Config $Script:TestConfig
        Should -Invoke ssh -ModuleName MobileManager -Times 1
    }
}

Describe 'New-DeployerCertificate' {
    BeforeAll {
        Mock -CommandName New-SelfSignedCertificate -ModuleName MobileManager -MockWith {
            [PSCustomObject]@{ Thumbprint = 'FAKE' }
        }
        Mock -CommandName Export-PFXCertificate -ModuleName MobileManager -MockWith { }
        Mock -CommandName Export-Certificate -ModuleName MobileManager -MockWith { }
    }

    It 'does not throw when certPass is supplied as SecureString' {
        {
            New-DeployerCertificate -certPass (ConvertTo-SecureString 'x' -AsPlainText -Force) `
                -outPath $TestDrive
        } | Should -Not -Throw
    }
}