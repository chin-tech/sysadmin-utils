enum TaskTriggerType {
    Time         = 1
    Daily        = 2
    Weekly       = 3
    Registration = 7
    Boot         = 8
    Logon        = 9
}

function ConvertTo-Base64 ($x) { [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($x)) }
function ConvertFrom-Base64 ($x) { [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($x)) }

function New-TaskXML {
    [CmdletBinding()]
    param(
        [string]$Description = "Automated Task",
        [string]$Author = "SYSTEM",
        [string]$Execute = 'powershell.exe',
        [string]$ToEncode,
        [string]$Arguments = "",
        [hashtable[]]$TriggerConfigs = @(@{ Type = [TaskTriggerType]::Registration }),
        [string]$UserId = "NT AUTHORITY\SYSTEM",
        [int]$LogonType = 5, # TASK_LOGON_SERVICE
        [int]$RunLevel = 1,  # TASK_RUNLEVEL_HIGHEST
        [bool]$Hidden = $true,
        [string]$ExecutionTimeLimit = "PT72H"
    )

    # 1. Resolve Command & Arguments
    if (-not [string]::IsNullOrWhiteSpace($ToEncode)) {
        $Execute = 'powershell.exe'
        $Arguments = @('-Hidden', '-NonInteractive', '-NoProfile', '-EncodedCommand', (ConvertTo-Base64 $ToEncode), $Arguments) -join ' '
    }

    # 2. Initialize COM Task
    $ts = New-Object -ComObject "Schedule.Service"
    $ts.Connect()
    $taskDef = $ts.NewTask(0)

    # 3. Registration Info & Principal
    $taskDef.RegistrationInfo.Description = $Description
    $taskDef.RegistrationInfo.Author      = $Author

    $taskDef.Principal.UserId    = $UserId
    $taskDef.Principal.LogonType = $LogonType
    $taskDef.Principal.RunLevel  = $RunLevel

    # 4. Settings Configuration
    $settings = @{
        Enabled                    = $true
        Hidden                     = $Hidden
        StartWhenAvailable         = $true
        AllowDemandStart           = $true
        WakeToRun                  = $true
        DisallowStartIfOnBatteries = $false
        StopIfGoingOnBatteries     = $false
        ExecutionTimeLimit         = $ExecutionTimeLimit
    }
    foreach ($k in $settings.Keys) { $taskDef.Settings.$k = $settings[$k] }

    # 5. Triggers Configuration
    $nowIso = (Get-Date).ToString("s")

    foreach ($cfg in $TriggerConfigs) {
        $tType   = [TaskTriggerType]($cfg.Type ?? [TaskTriggerType]::Registration)
        $trigger = $taskDef.Triggers.Create([int]$tType)
        $trigger.Enabled = if ($cfg.ContainsKey('Enabled')) { $cfg.Enabled } else { $true }

        # Dynamically bind any matching COM properties supplied in the hashtable (e.g., Delay, UserId, DaysInterval)
        foreach ($key in $cfg.Keys) {
            if ($key -notin 'Type', 'Enabled' -and $trigger.PSObject.Properties[$key]) {
                $trigger.$key = $cfg[$key]
            }
        }

        # Handle type-specific defaults only when omitted
        switch ($tType) {
            ([TaskTriggerType]::Daily) {
                if (-not $cfg.DaysInterval)  { $trigger.DaysInterval = 1 }
                if (-not $cfg.StartBoundary) { $trigger.StartBoundary = $nowIso }
            }
            ([TaskTriggerType]::Weekly) {
                if (-not $cfg.WeeksInterval) { $trigger.WeeksInterval = 1 }
                if (-not $cfg.DaysOfWeek)    { $trigger.DaysOfWeek = 2 } # Monday default (bitmask)
                if (-not $cfg.StartBoundary) { $trigger.StartBoundary = $nowIso }
            }
            ([TaskTriggerType]::Time) {
                if (-not $cfg.StartBoundary) {
                    $trigger.StartBoundary = (Get-Date).AddMinutes(5).ToString("s")
                }
            }
        }
    }

    # 6. Action Configuration (0 = ExecAction)
    $action = $taskDef.Actions.Create(0)
    $action.Path = $Execute
    $action.Arguments = $Arguments.Trim()

    return $taskDef.XmlText
}


## Use case:
$xml = New-TaskXML `
    -Description "System Maintenance Routine" `
    -Execute "powershell.exe" `
    -Arguments "-NoProfile -ExecutionPolicy Bypass -Command Write-Host 'Running Maintenance'" `
    -TriggerConfigs @(
    @{ Type = [TaskTriggerType]::Boot; Delay = "PT1M" },
    @{ 
        Type          = [TaskTriggerType]::Daily
        StartBoundary = (Get-Date "03:00:00").ToString("yyyy-MM-ddTHH:mm:ss")
        DaysInterval  = 1
    }
)
# Directly register the generated XML
Register-ScheduledTask `
    -TaskName "CustomMaintenance" `
    -TaskPath "\CompanyTasks\" `
    -Xml $xml `
    -Force
