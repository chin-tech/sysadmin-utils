# Exercise the shared XML builder's configuration with an in-memory COM substitute.
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot -Parent) 'MobileManager.psm1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors.Message -join '; ') }
$source = $ast.EndBlock.Statements | Where-Object {
    ($_ -is [System.Management.Automation.Language.TypeDefinitionAst] -and $_.Name -eq 'TaskTriggerType') -or
    ($_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -in @('New-TaskXML','ConvertTo-Base64'))
} | ForEach-Object { $_.Extent.Text }
$module = New-Module -ScriptBlock ([scriptblock]::Create($source -join "`n"))
try {
    & $module {
        function Assert($condition,$message) { if (-not $condition) { throw $message } }
        function New-Object {
            param($ComObject)
            Assert ($ComObject -eq 'Schedule.Service') 'Unexpected COM service'
            $settings = [pscustomobject]@{ Enabled=$false; Hidden=$false; StartWhenAvailable=$false; AllowDemandStart=$false; WakeToRun=$false; DisallowStartIfOnBatteries=$true; StopIfGoingOnBatteries=$true; ExecutionTimeLimit=''; DeleteExpiredTaskAfter=$null }
            $triggers = [pscustomobject]@{ Last=$null }
            $triggers | Add-Member ScriptMethod Create {
                param($type)
                $this.Last = [pscustomobject]@{ Type=$type; Enabled=$false; Delay=''; EndBoundary=$null }
                $this.Last
            }
            $actions = [pscustomobject]@{ Last=$null }
            $actions | Add-Member ScriptMethod Create {
                param($type)
                $this.Last = [pscustomobject]@{ Path=''; Arguments='' }
                $this.Last
            }
            $script:task = [pscustomobject]@{
                RegistrationInfo=[pscustomobject]@{ Description=''; Author=''; Version='' }
                Settings=$settings; Principal=[pscustomobject]@{ UserId=''; LogonType=0; RunLevel=0 }
                Triggers=$triggers; Actions=$actions; XmlText='<Task />'
            }
            $service = [pscustomobject]@{ Definition=$script:task }
            $service | Add-Member ScriptMethod Connect { }
            $service | Add-Member ScriptMethod NewTask { param($flags) $this.Definition }
            $service
        }
        $arguments = '-NoProfile -File "C:\ProgramData\Mobiles\Smb\fixture\boot.ps1" -Mode Activate -Root "C:\ProgramData\Mobiles\Smb\fixture"'
        $xml = New-TaskXML -Execute powershell.exe -Arguments $arguments -TriggerConfigs @(@{ Type=8; Delay='PT30S'; EndBoundary='' }) -ExecutionTimeLimit PT2M
        Assert ($xml -eq '<Task />' -and $script:task.Actions.Last.Arguments.EndsWith($arguments)) 'Task arguments were corrupted'
        Assert ([regex]::Matches($script:task.Actions.Last.Arguments, '-File ').Count -eq 1) 'Explicit arguments were duplicated'
        Assert ($null -eq $script:task.Triggers.Last.EndBoundary -and $null -eq $script:task.Settings.DeleteExpiredTaskAfter) 'Persistent boot task received expiry settings'
        Assert ($script:task.Triggers.Last.Type -eq 8 -and $script:task.Principal.UserId -eq 'NT AUTHORITY\SYSTEM' -and $script:task.Settings.ExecutionTimeLimit -eq 'PT2M') 'Boot task settings changed'
        $null = New-TaskXML -Execute powershell.exe -ToEncode 'Write-Output "fixture"' -TriggerConfigs @(@{ Type=8 })
        Assert ($script:task.Triggers.Last.EndBoundary -and $script:task.Settings.DeleteExpiredTaskAfter -eq 'PT0S') 'Existing one-time boot tasks lost their default expiry'
        Assert ($script:task.Actions.Last.Arguments.Contains('-Encoded ')) 'Existing encoded task actions changed'
        'PASS: shared task builder arguments, persistent boot trigger, SYSTEM settings and existing expiring/encoded tasks.'
    }
} finally { Remove-Module $module -ErrorAction SilentlyContinue }
