# Offline prompt/generation wiring; does not execute ktpass, WinRM, or Centrify.
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join "`n") }
$node = $ast.Find({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Resolve-LinuxDisjoinKeytab'
}, $false)
$module = New-Module -ScriptBlock ([scriptblock]::Create($node.Extent.Text))
try {
    & $module {
        function Assert($condition, $message) { if (-not $condition) { throw $message } }
        function Read-Host {
            param($Prompt, [switch]$AsSecureString)
            $script:prompts++
            if ($AsSecureString) {
                $script:securePrompt = $true
                ConvertTo-SecureString 'fixture-password' -AsPlainText -Force
            } elseif ($Prompt -like '*principal*') { 'deployer@EXAMPLE.TEST' }
            else { '7' }
        }
        function New-RemoteKeytabBase64 {
            param($DomainController, $Principal, $Kvno, $SecurePassword)
            $script:generations++
            Assert ($SecurePassword -is [securestring] -and $SecurePassword.Length -gt 0) 'Generator received a plaintext or empty password'
            Assert ($Principal -eq 'deployer@EXAMPLE.TEST' -and $Kvno -eq 7 -and $DomainController -eq 'dc.example.test') 'Generator arguments did not match inputs'
            if ($script:failGeneration) { throw 'Fixture generation failed' }
            'YWJj'
        }
        $script:prompts = 0
        $script:generations = 0
        $script:securePrompt = $false
        $result = Resolve-LinuxDisjoinKeytab -Keytab 'YWJj'
        Assert ($result -eq 'YWJj' -and $script:prompts -eq 0 -and $script:generations -eq 0) 'Supplied keytab triggered a prompt'
        $result = Resolve-LinuxDisjoinKeytab -DomainController 'dc.example.test'
        Assert ($result -eq 'YWJj' -and $script:prompts -eq 3 -and $script:securePrompt) 'Interactive principal/version/password flow failed'
        $script:prompts = 0
        $result = Resolve-LinuxDisjoinKeytab -DomainController 'dc.example.test' -Principal 'deployer@EXAMPLE.TEST' -Kvno 7
        Assert ($result -eq 'YWJj' -and $script:prompts -eq 1) 'Explicit inputs did not reduce prompting to the secure password'
        $script:failGeneration = $true
        $rejected = $false
        try { Resolve-LinuxDisjoinKeytab -DomainController 'dc.example.test' -Principal 'deployer@EXAMPLE.TEST' -Kvno 7 } catch { $rejected = $true }
        Assert $rejected 'Generation failure was swallowed'
        $before = $script:generations
        $rejected = $false
        try { Resolve-LinuxDisjoinKeytab -Principal 'invalid principal' -Kvno 7 } catch { $rejected = $true }
        Assert ($rejected -and $script:generations -eq $before) 'Invalid principal reached generator'
        'PASS: secure prompting, explicit inputs, supplied-keytab bypass, and failure propagation.'
    }
} finally { Remove-Module $module -ErrorAction SilentlyContinue }
