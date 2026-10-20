enum TaskTriggerType
{
    Time         = 1
    Daily        = 2
    Weekly       = 3
    Registration = 7
    Boot         = 8
    Logon        = 9
}

function New-TaskXML
{
    [CmdletBinding()]
    param(
        [Parameter()][string]$Description = "Automated Task",
        [Parameter()][string]$Author = "SYSTEM",
        
        [Parameter(Mandatory=$true)]
        [string]$Execute,
        
        [Parameter()]
        [string]$Arguments = "",
        
        # Pass a hashtable or array of hashtables describing triggers
        [Parameter()]
        [hashtable[]]$TriggerConfigs = @(@{ Type = [TaskTriggerType]::Boot }),
        
        [Parameter()][string]$UserId = "NT AUTHORITY\SYSTEM",
        [Parameter()][int]$LogonType = 5, # 5 = TASK_LOGON_SERVICE / SYSTEM
        [Parameter()][int]$RunLevel = 1,  # 1 = TASK_RUNLEVEL_HIGHEST
        
        [Parameter()][bool]$Hidden = $true,
        [Parameter()][string]$ExecutionTimeLimit = "PT72H"
    )

    $ts = New-Object -ComObject "Schedule.Service"
    $ts.Connect()

    # 0 = TASK_CREATE (Task Definition)
    $taskDef = $ts.NewTask(0)
    
    # 1. Registration Info
    $taskDef.RegistrationInfo.Description = $Description
    $taskDef.RegistrationInfo.Author = $Author

    # 2. Task Settings
    $taskDef.Settings.Enabled = $true
    $taskDef.Settings.Hidden = $Hidden
    $taskDef.Settings.StartWhenAvailable = $true
    $taskDef.Settings.AllowDemandStart = $true
    $taskDef.Settings.WakeToRun = $true
    $taskDef.Settings.DisallowStartIfOnBatteries = $false
    $taskDef.Settings.StopIfGoingOnBatteries = $false
    $taskDef.Settings.ExecutionTimeLimit = $ExecutionTimeLimit

    # 3. Principal Configuration
    $taskDef.Principal.UserId = $UserId
    $taskDef.Principal.LogonType = $LogonType
    $taskDef.Principal.RunLevel = $RunLevel

    # 4. Triggers Configuration
    foreach ($cfg in $TriggerConfigs)
    {
        $tType = [TaskTriggerType]$cfg.Type
        $trigger = $taskDef.Triggers.Create([int]$tType)
        $trigger.Enabled = if ($cfg.ContainsKey('Enabled'))
        { $cfg.Enabled 
        } else
        { $true 
        }
        
        if ($cfg.ContainsKey('StartBoundary'))
        {
            $trigger.StartBoundary = $cfg.StartBoundary
        }

        switch ($tType)
        {
            ([TaskTriggerType]::Logon)
            {
                # Specific user or $null / empty string for all users
                if ($cfg.ContainsKey('UserId'))
                {
                    $trigger.UserId = $cfg.UserId
                }
                if ($cfg.ContainsKey('Delay'))
                {
                    $trigger.Delay = $cfg.Delay # e.g. "PT30S"
                }
            }
            ([TaskTriggerType]::Boot)
            {
                if ($cfg.ContainsKey('Delay'))
                {
                    $trigger.Delay = $cfg.Delay # e.g. "PT1M"
                }
            }
            ([TaskTriggerType]::Daily)
            {
                $trigger.DaysInterval = if ($cfg.ContainsKey('DaysInterval'))
                { $cfg.DaysInterval 
                } else
                { 1 
                }
                if (-not $trigger.StartBoundary)
                {
                    $trigger.StartBoundary = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
                }
            }
            ([TaskTriggerType]::Weekly)
            {
                $trigger.WeeksInterval = if ($cfg.ContainsKey('WeeksInterval'))
                { $cfg.WeeksInterval 
                } else
                { 1 
                }
                # DaysOfWeek bitmask: 1=Sun, 2=Mon, 4=Tue, 8=Wed, 16=Thu, 32=Fri, 64=Sat
                $trigger.DaysOfWeek = if ($cfg.ContainsKey('DaysOfWeek'))
                { $cfg.DaysOfWeek 
                } else
                { 2 
                } # Monday default
                if (-not $trigger.StartBoundary)
                {
                    $trigger.StartBoundary = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
                }
            }
            ([TaskTriggerType]::Time)
            {
                if (-not $trigger.StartBoundary)
                {
                    $trigger.StartBoundary = (Get-Date).AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss")
                }
            }
            ([TaskTriggerType]::Registration)
            {
                if ($cfg.ContainsKey('Delay'))
                {
                    $trigger.Delay = $cfg.Delay
                }
            }
        }
    }

    # 5. Action Configuration (0 = ExecAction)
    $action = $taskDef.Actions.Create(0)
    $action.Path = $Execute
    $action.Arguments = $Arguments

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
