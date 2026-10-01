
enum TaskTriggerType {
    Time         = 1
    Daily        = 2
    Weekly       = 3
    Registration = 7
    Boot         = 8
    Logon        = 9
}

function New-TaskXML {
    [CmdletBinding()]
    param(
        [string]$Description = "Automated Task",
        [string]$Author = "SYSTEM",
        [string]$ToEncode,
        [string]$Execute = "powershell.exe",
        [string]$Arguments = "",
        [string]$UserId = "NT AUTHORITY\SYSTEM",
        [string]$ExecutionTimeLimit = "PT72H",
        [int]$LogonType = 5, # 5 = TASK_LOGON_SERVICE
        [int]$RunLevel = 1,  # 1 = TASK_RUNLEVEL_HIGHEST
        [bool]$Hidden = $true,
        [hashtable[]]$TriggerConfigs = @(@{ Type = [TaskTriggerType]::Registration; Delay = 'PT10S' })
    )

    $defaultPSArgs = if ($Execute.ToLower().Contains('powershell')) { "-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass " } else { "" }
    
    $encoded = if (-not [string]::IsNullOrWhiteSpace($ToEncode)) { 
        $b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ToEncode))
        "-EncodedCommand $b64 "
    } else { "" }

    $fullArguments = ($defaultPSArgs + $encoded + $Arguments).Trim()

    $ts = New-Object -ComObject "Schedule.Service"
    $ts.Connect()

    $taskDef = $ts.NewTask(0)
    
    # 1. Registration & Principal
    $taskDef.RegistrationInfo.Description = $Description
    $taskDef.RegistrationInfo.Author      = $Author
    $taskDef.Principal.UserId             = $UserId
    $taskDef.Principal.LogonType          = $LogonType
    $taskDef.Principal.RunLevel           = $RunLevel

    # 2. Task Settings
    @{
        Hidden                     = $Hidden
        Enabled                    = $true
        StartWhenAvailable         = $true
        WakeToRun                  = $true
        DisallowStartIfOnBatteries = $false
        StopIfGoingOnBatteries     = $false
        ExecutionTimeLimit         = $ExecutionTimeLimit
    }.GetEnumerator() | ForEach-Object { $taskDef.Settings.$($_.Key) = $_.Value }

    # 3. Triggers Configuration
    foreach ($cfg in $TriggerConfigs) {
        $tType   = [TaskTriggerType]$cfg.Type
        $trigger = $taskDef.Triggers.Create([int]$tType)

        $trigger.Enabled       = if ($cfg.ContainsKey('Enabled')) { $cfg.Enabled } else { $true }
        $trigger.StartBoundary = if ($cfg.ContainsKey('StartBoundary')) { $cfg.StartBoundary } else { (Get-Date).AddSeconds(5).ToString('s') }

        $defaults = switch ($tType) {
            ([TaskTriggerType]::Logon)        { @{ Delay = 'PT1M' } }
            ([TaskTriggerType]::Boot)         { @{ Delay = 'PT10S' } }
            ([TaskTriggerType]::Daily)        { @{ DaysInterval = 1 } }
            ([TaskTriggerType]::Weekly)       { @{ WeeksInterval = 1; DaysOfWeek = 1 } }
            ([TaskTriggerType]::Registration) { @{ Delay = 'PT10S' } }
            Default                           { @{} }
        }

        foreach ($prop in $defaults.Keys) {
            if (-not $cfg.ContainsKey($prop)) { $trigger.$prop = $defaults[$prop] }
        }
        foreach ($p in $cfg.Keys) {
            if ($p -notin @('Type', 'Enabled', 'StartBoundary')) { 
                $trigger.$p = $cfg[$p] 
            }
        }
    }

    # 4. Action Configuration
    $action           = $taskDef.Actions.Create(0)
    $action.Path      = $Execute
    $action.Arguments = $fullArguments

    return $taskDef.XmlText
}


$InitBlock = {
    $d = "C:\Laps"
    $FILE = Join-Path $d "X"
    function ConvertFrom-Base64 { param($s); [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($s));}
    [System.Net.NetworkCredential]::new('',(ConvertFrom-Base64 "ENCODED-PASS")).SecurePassword | Export-Clixml $FILE
    attrib.exe +H /S /D C:\Laps
    icacls  $d /inheritance:r /grant:r 'domain admins':F Administrator:F System:F /T
}

$RotateBlock = {
    $d = "C:\Laps"
    $s = Import-CliXml (Join-Path $d "X")
    $refFile = Join-Path $d "Next"
    $curMonth = Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0
    $suffix = $curMonth.ToString('MMYY')
    function R {
        $I = "PREFIX"
        $D = $suffix
        $sX = ConvertTo-SecureString -AsPlainText -Force ($I + [System.Net.NetworkCredential]::new('',$s).Password + $D )
        $params = @{ Name = 'ADMIN' ; Description = 'ADMIN - RECOVERY'; FullName = 'ADMIN - RECOVERY'; Password = $sX}
        if (-not (Get-LocalUser Admin)) { New-Localuser @params} else { Set-Localuser @params }
        if (-not (Get-LocalGroupMember Administrators Admin)) { Add-LocalGroupMember Administrators Admin}
        $curMonth.AddMonths(1).ToString('s') | Set-Content -Path $refFile
    }
    if (-not (Test-Path $refFile)) { R }
    $rDate = [DateTime]::new((Get-Content $refFile))
    if ($curMonth -gt $rDate) { R }
}

$iTask = New-TaskXML -ToEncode $InitBlock.ToString() -Execute 'powershell.exe'
$triggers = @(
    @{Type = [TaskTriggerType]::Daily},
    @{ Type = [TaskTriggerType]::Boot }
)
$rTask = New-TaskXML -ToEncode $RotateBlock.ToString() -Execute 'powershell.exe' -TriggerConfigs $triggers

$runBlock = {
    param($iT, $rT)
    Register-ScheduledTask -TaskName Init -Xml $iT -Force
    Register-ScheduledTask -TaskName Laps -Xml $rT -Force
}
Invoke-Command -ComputerName $computers -ScriptBlock $runBlock -ArgumentList $iTask,$rTask

