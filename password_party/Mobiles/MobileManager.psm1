# --- Configuration Loader ---
$Script:DefaultConfig = $MyInvocation.MyCommand.Module.PrivateData.PSData.DefaultConfig

function Get-MobileConfig
{
    [CmdletBinding()]
    param([hashtable]$CustomConfig)
    
    $merged = @{}
    if ($Script:DefaultConfig)
    {
        foreach ($k in $Script:DefaultConfig.Keys)
        { $merged[$k] = $Script:DefaultConfig[$k] 
        }
    }
    if ($CustomConfig)
    {
        foreach ($k in $CustomConfig.Keys)
        { $merged[$k] = $CustomConfig[$k] 
        }
    }
    return $merged
}

# --- Private Helper Functions (Not Exported) ---

function Get-EncryptedCredRSA
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PassFile,
        [Parameter(Mandatory = $true)][string]$DefaultPass,
        [Parameter(Mandatory = $true)][string]$PfxPath
    )

    if (-not (Test-Path $PassFile) -or -not (Test-Path $PfxPath))
    {
        return $DefaultPass
    }

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath)
    $rsa  = $cert.GetRSAPrivateKey()

    try
    {
        $eBytes  = [System.Convert]::FromBase64String((Get-Content $PassFile -Raw).Trim())
        $padding = [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1
        $dBytes  = $rsa.Decrypt($eBytes, $padding)
        return [System.Text.Encoding]::UTF8.GetString($dBytes)
    } catch
    {
        Write-Warning "Decryption failed for $PassFile. Returning default password."
        return $DefaultPass
    } finally
    {
        if ($rsa)
        { $rsa.Dispose() 
        }
        if ($cert)
        { $cert.Dispose() 
        }
    }
}

function Get-UserCreds
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MobileName,
        [Parameter(Mandatory = $true)][array]$AllUsers,
        [Parameter(Mandatory = $true)][hashtable]$Config
    )

    $ADUsers = $AllUsers.Name | ForEach-Object { ($_ -split '\.')[0] } | Sort-Object -unique
    foreach ($u in $ADUsers)
    {
        $PwFile = Join-Path $config['mobileDump'] $u
        if ( (Test-Path $PwFile ))
        {
            $content = Unprotect-CmsMessage -Content (Get-Content $PwFile)
            foreach ($line in $content.Split('\r?\n'))
            {
                $timestamp, $username, $pw = $line -split (':')
                $AllUsers[$username] = ConvertTo-SecureString -AsPlainText -Force $pw
            }

        }
    }
    $pw = $null
    [System.GC]::Collect()
    return $AllUsers
}

# --- Public Exported Functions ---

function Get-UserFullName
{
    [CmdLetBinding()]
    param(
        [Parameter()][string]$UserName,
        [Parameter()][string]$FullName
    )

    if ([String]::IsNullOrWhiteSpace($FullName))
    {
        $uData = Get-ADUser -Filter "SamAccountName -eq '$UserName'" -Properties Name,DisplayName,GivenName,Surname 
        if (! ([string]::IsNullOrWhiteSpace($uData.DisplayName)))
        { 
            return $uData.DisplayName 
        }
        if (! ([string]::IsNullOrWhiteSpace($uData.GivenName) -and [string]::IsNullOrWhiteSpace($uData.SurName)))
        { 
            return $uData.GivenName + $uData.Surname 
        }
    }

    return $FullName

}

function Set-Groups
{
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [array]$Groups
    )

    $grps = @("local")
    if ($Groups.Length -eq 0)
    {
        return $grps
    }

    foreach ($g in $Groups)
    {
        switch -WildCard ($g)
        {
            'i*'
            { return @('isso')
            }
            't*'
            { return @('adm')
            }
            'p*'
            {$grps += @("priv")
            }
            'd*rw'
            { $grps += @("dtrw")
            }
            'd*ro'
            { $grps += @("dtro")
            }
        }
    }
    return $grps
}





function Get-MobileData
{
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$MobileName,
        
        [string]$defaultUserpath,
        [string]$mobileEntriesPath,
        [securestring]$defaultPass
    )


    $result = [ordered]@{
        AllMobiles   = @()
        MobileUsers  = @()
        DefaultUsers = @()
        AllUsers     = @()
        Linux        = @()
        Windows      = @()
    }

    if (Test-Path $mobileEntriesPath)
    {
        $result.AllMobiles = Get-ChildItem -Path $mobileEntriesPath  |
            Select-Object -ExpandProperty BaseName -Unique
    }

    if ([string]::IsNullOrWhiteSpace($MobileName))
    {
        return [PSCustomObject]$result
    }
    ## Default users
    $result.DefaultUsers = Get-ChildItem -Force -Path $defaultUserpath | Get-Content | ConvertFrom-CSV 


    ## Actual Mobile Data
    $path = Join-Path $mobileEntriesPath $MobileName

    $currentSection = $null
    $sections = @{}

    foreach ($line in Get-Content $path)
    {
        $trimmed = $line.Trim()

        if (
            [string]::IsNullOrWhiteSpace($trimmed) -or
            $trimmed.StartsWith('#') -or
            $trimmed.StartsWith(';')
        )
        {
            continue
        }

        if ($trimmed -match '^\[(?<Header>.+)\]$')
        {
            $currentSection = $Matches.Header

            if (-not $sections.ContainsKey($currentSection))
            {
                $sections[$currentSection] =
                [System.Collections.Generic.List[string]]::new()
            }

            continue
        }

        if ($null -ne $currentSection)
        {
            $sections[$currentSection].Add($trimmed)
        }
    }

    if ($sections.ContainsKey('users'))
    {
        $result.MobileUsers = @(
            $sections['users'] |
                ConvertFrom-Csv |
                ForEach-Object {
                    [PSCustomObject]@{
                        Username = $_.username
                        Groups   = if ($_.groups)
                        {
                            $_.groups -split ';'
                        } else
                        {
                            @()
                        }
                        Name = $_.name
                    }
                }
        )
    }

    if ($sections.ContainsKey('Windows'))
    {
        $result.Windows = @($sections['Windows'])
    }

    if ($sections.ContainsKey('Linux'))
    {
        $result.Linux = @($sections['Linux'])
    }
    $tmp = @($result.DefaultUsers) + @($result.MobileUsers)

    $allUsers = [System.Collections.Generic.List[object]]::new()

    foreach ($u in $tmp)
    {
        $fullName = Get-UserFullName $u.Username $u.Name
        $grps = Set-Groups $u.Groups
        foreach ($grp in $grps)
        {
            $desc = "[Mobile] $($u.Name) - "
            switch -Regex ($grp)
            {
                '^a.*'
                {$desc += 'System Administrator'
                }
                '^i.*'
                {$desc += 'Cybersecurity'
                }
                '^l.*'
                {$desc += 'General User'
                }
                '^d.*'
                {$desc += 'Data Transfer'
                }
                '^p.*'
                {$desc += 'Privileged User'
                }
            }

            $uData = [PSCustomObject]@{
                Name     = $u.Username
                FullName = $fullName
                Password = $defaultPass
                Description = "$desc"
                MustChangePassword = $false
            }
            $uData.Name += ".$grp"


            $allUsers.Add($uData)
        }
    }
    $allUsers = $allUsers | Sort-Object Name -Unique

    $result.AllUsers = $allUsers

    [PSCustomObject]$result
}

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


function Get-TaskData
{
    param(
        [string]$tasksPath
    )

    $taskData = @()
    $disjoinB64 = [Convert]::ToBase64String((Get-Content $disjoinPath))
    $domainDisjoinTask = New-TaskXML -Description 'Runs once after domain disjoin' `
        -Author '[Mobile Administration]' -Execute 'powershell.exe' `
        -Arguments "-NoProfile -ExecutionPolicyBypass -Encoded $disjoinB64" `
        -TriggerConfigs @(
        @{
            Type = [TaskTriggerType]::Boot
            Delay = 'PT1M'
        }


    )


    $logCollect = New-TaskXML -Description 'Mobile Auto Log Collecot' `
        -Author '[Mobile Administration]' -Execute 'C:\Supportbin\logcollect' `
        -TriggerConfigs @(
        @{
            Type = [TaskTriggerType]::Weekly
            DaysOfWeek = 1
            StartBoundary = (Get-Date "00:00:00").AddDays(1).ToString('s')                   
        }


    )

    $taskData += @([PsCustomObject]@{Taskname = "Mobile-LogCollect"; TaskXml = $logCollect})
    $taskData += @([PsCustomObject]@{Taskname = "Mobile-DisjoinTask"; TaskXml = $domainDisjoinTask})
    
    return $taskData
}


function Get-MobileOverview
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Config,

        [Parameter()]
        [string]$MobileName
    )

    $data = Get-MobileData -MobileName $MobileName -defaultUserpath $cfg.DefaultUsers -mobileEntriesPath $Config.MobileEntries -defaultPass $config.DefaultPass

    # Overall display width
    $width = 72

    function Write-CenteredHeader
    {
        param(
            [string]$Text,
            [ConsoleColor]$Color = 'Cyan'
        )

        $border = '=' * $width
        $padding = [Math]::Max(0, [Math]::Floor(($width - $Text.Length) / 2))

        Write-Host $border -ForegroundColor $Color
        Write-Host (' ' * $padding + $Text) -ForegroundColor $Color
        Write-Host $border -ForegroundColor $Color
    }

    function Write-Section
    {
        param(
            [string]$Text,
            [ConsoleColor]$Color = 'DarkYellow'
        )

        Write-Host ""
        Write-Host ("[{0}]" -f $Text) -ForegroundColor $Color
        Write-Host ('-' * $width) -ForegroundColor DarkGray
    }

    if ($data.AllMobiles.Count -eq 0)
    {
        Write-Host "No available mobiles found." -ForegroundColor Yellow
        return
    }

    Write-Host ""

    if ([string]::IsNullOrWhiteSpace($MobileName))
    {
        Write-CenteredHeader -Text 'AVAILABLE MOBILES'

        foreach ($name in $data.AllMobiles)
        {
            Write-Host ("  {0,-30}" -f $name) -ForegroundColor Green
        }

        Write-Host ""
        return
    }

    Write-CenteredHeader -Text "MOBILE: $MobileName"

    Write-Section -Text 'USERS' -Color DarkYellow
    Write-Host (
        "  {0,-20} {1,-20} {2}" -f
        'USERNAME',
        'GROUPS',
        'FULL NAME'
    ) -ForegroundColor DarkYellow

    foreach ($u in ($data.MobileUsers| Sort-Object Username))
    {
        $groups = $u.Groups -join ', '

        Write-Host (
            "  {0,-20} {1,-20} {2}" -f
            $u.Username,
            $groups,
            $u.Name
        ) -ForegroundColor Yellow
    }

    if ($data.Windows.Count -gt 0)
    {
        Write-Section -Text 'WINDOWS' -Color DarkBlue

        foreach ($c in ($data.Windows| Sort-Object))
        {
            Write-Host ("  {0}" -f $c) -ForegroundColor Blue
        }
    }

    if ($data.Linux.Count -gt 0)
    {
        Write-Section -Text 'LINUX' -Color DarkRed

        foreach ($c in ($data.Linux | Sort-Object))
        {
            Write-Host ("  {0}" -f $c) -ForegroundColor Red
        }
    }

    Write-Section -Text 'SIMULATED DEPLOY' -Color Gray

    Write-Host (
        "  {0,-22} {1,-25} {2}" -f
        'USERNAME',
        'FULL NAME',
        'DESCRIPTION'
    ) -ForegroundColor DarkGreen

    foreach ($u in $data.AllUsers)
    {
        Write-Host (
            "  {0,-22} {1,-25} {2}" -f
            $u.Name,
            $u.FullName,
            $u.Description
        ) -ForegroundColor Green
    }

    Write-Host ""
}


function Set-MobileGpoPermission
{
    [CmdletBinding(DefaultParameterSetName = 'Add')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$MobileName,

        [Parameter(Mandatory = $true)]
        [string]$GpoID,

        [Parameter(Mandatory = $true, ParameterSetName = 'Add')]
        [switch]$Add,

        [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
        [switch]$Remove,

        [Parameter(ParameterSetName = 'Remove')]
        [switch]$Force

    )


    if ($Force -and $Remove)
    {
        Get-GPPermission -Guid $gpoId -All |
            Where-Object { $_.Trustee.SidType -eq 'User' -and $_.Permission -eq 'GpoRead' } |
            ForEach-Object {
                Set-GPPermission -Guid $gpoId -TargetName $_.Trustee.Name -TargetType User -PermissionLevel None -Confirm:$false
            }
        Write-Host "[+] Force removed all user permissions from GPO ($gpoId)" -ForegroundColor Yellow
        return
    }

    $mobileData = Get-MobileData -MobileName $MobileName -Config $cfg
    $targetUsers = if ($Add)
    { 
        $mobileData.AllUsers 
    } else
    { 
        $mobileData.MobileUsers 
    }

    foreach ($u in $targetUsers)
    {
        $permLevel = if ($Add)
        { 
            'GpoRead' 
        } else
        { 
            'None' 
        }
        Set-GPPermission -Guid $gpoId -TargetName $u.Name -TargetType User -PermissionLevel $permLevel -Confirm:$false -ErrorAction SilentlyContinue
    }

    $actionText = if ($Add)
    { 
        "Added" 
    } else
    {
        "Removed" 
    }
    Write-Host "[+] $actionText users from '$MobileName' for GPO ($gpoId)" -ForegroundColor Green
}

function ConvertTo-BashArgument
{
    param([string]$v)
    "'" + $v.Replace("'","'\''") + "'"
}

function Invoke-Linux
{
    param(
        [string]$mobileName,
        [string]$bastionHost,
        [string]$sshKeyPath,
        [string]$scriptName,
        [string[]]$extraArgs
    )
    $a = @($mobileName) + $extraArgs
    $remoteArgs = ($a | ForEach-Object { ConvertTo-BashArgument $_}) -join ' '


    (Get-Content $scriptName -Raw) -replace "`r`n","`n" | ssh -i $sshKeyPath -q $bastionHost "bash -s -- $remoteArgs"
}

function Start-MobileDeployment
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$MobileName,
        [Parameter()][string]$EncryptPass = 'defaultPin',
        [Parameter()][string]$UserPass    = 'defaultPassword',
        [Parameter()][hashtable]$Config
    )

    $cfg = Get-MobileConfig $Config
    $mobileData = Get-MobileData -MobileName $MobileName -Config $cfg
    $mobileData.AllUsers  = Get-UserCreds -MobileName $MobileName -AllUsers $mobileData.AllUsers -Config $cfg
    $groupDict = @{
        'Administrators' = @("isso","adm","priv")
        'ISSO' = @("isso")
        'DTRW' = @("dtrw")
        'DTRO' = @("dtro")
    }
    $disJoin = $true

    $scriptBlock = {
        param($allusers, $taskData, $groupDict,$mobileName, $disJoin)

        foreach ($u in $allUsers)
        {
            $uParams = @{Name = $u.Name; FullName =$u.FullName; Password = $u.Password; Description = $u.Description}
            New-LocalUser @uParams -ErrorAction SilentlyContinue

            if ($u.MustChangePassword)
            {
                $a = [ADSI]"WinNT://./$($u.Name),user"
                $a.PasswordExpired = 1
                $a.SetInfo()
            }

        }

        foreach ($grp in $groupDict.Keys)
        {
            Get-Localuser | Where-Object {$_.Name -match "($($groupDict[$grp] -join '|'))$"} | Add-LocalGroupMember -Group $grp
        }

        foreach ($t in $taskData)
        {
            Register-ScheduledTask -TaskName $t.TaskName -xml $t.XmlData -User System -Force
        }

        if ($disJoin)
        {
            Remove-Computer -Force -Restart -WorkGroupName "$mobileName"
        }

    }
    Invoke-Command -ComputerName $mobileData.Windows -ScriptBlock $scriptBlock -ArgumentList $mobileData.AllUsers,$taskData,$groupDict,$mobileName,$disJoin
    $sshKeyPath = Join-Path $cfg['netAppHome'] "${env:USERNAME}\.ssh\$($cfg['sshKeyName'])"
    Invoke-Linux -mobileName $MobileName -sshKeyPath $sshKeyPath -bastionHost $cfg['LinuxBastion'] -scriptName $cfg['LinuxDeploy'] -extraArgs "FILLIN"


}


function New-DeployerCertificate
{
    [CmdletBinding()]
    param(
        [Parameter()][securestring]$certPass = (ConvertTo-SecureString -AsPlainText -Force 'deployer'),
        [Parameter()][string]$outPath = "\\nas\home\$env:USERNAME"
    )
    $c = New-SelfSignedCertificate -Subject 'CN=MobileDeployer' -Type DocumentEncryptionCert -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5)
    Export-PFXCertificate -Cert $c -FilePath (Join-Path $outPath "Deployer.pfx") -Password $certPass
    Export-Certificate -Cert $c -FilePath (Join-Path $outPath "Deployer.cer") 
    
}

function Unregister-Deployment
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MobileName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [Parameter()]
        [string]$archiveDir = "C:\Mobiles\"

    )

    $cfg = Get-MobileConfig $config
    $mobileData = Get-MobileData  -MobileName $MobileName -defaultUserpath $cfg.DefaultUsers -mobileEntriesPath $cfg.MobileEntries -defaultPass $cfg.DefaultPass

    $scriptBlock = {
        param([hashtable]$AllUsers, [hashtable]$Tasks, [string]$archiveDir)

        $curDate = Get-Date
        $archivePath = Join-Path $archiveDir "$($curDate.Year)"
        if (-not (Test-Path $archivePath))
        {
            New-Item -ItemType Directory -Force $archivePath
        }



        foreach ($u in $AllUsers.Keys)
        {
            $sid = (Get-LocalUser -Name $u -ErrorAction SilentlyContinue).Sid.Value

            $profilePath = "C:\Users\$u"
            if (Test-Path $profilePath)
            {
                $ts = (Get-Date).ToString('yyyyMMdd')
                $archiveFile = Join-Path $archivePath "$($u)_${ts}.zip"
                Compress-Archive -Path $profilePath -DestinationPath $archiveFile -CompressionLevel Optimal

            }
            $profileObject = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $sid -or $_.LocalPath -ieq $profilePath }

            if ($profileObject)
            {$profileObject | Remove-CimInstance
            } elseif (Test-Path $profilePath)
            { Remove-Item -Force -Recurse -Path $profilePath -ErrorAction SilentlyContinue
            }
            Remove-LocalUser $u -ErrorAction SilentlyContinue
        }

    }


    Invoke-Command -ComputerName $mobileData.Windows -ScriptBlock $scriptBlock -ArgumentList $mobileData.AllUsers,$taskData,$archiveDir
    Invoke-Linux -mobileName $MobileName -sshKeyPath $cfg['sshKey'] -bastionHost $cfg['BastionHost'] -scriptName $cfg['Linux-Clean'] -extraArgs "FILLIN"





    





}



function Test-SshEnvironment
{
    [CmdletBinding()]
    param(
        [Parameter()][string]$KeyName = 'deployer',
        [Parameter()][string]$NasHome = "\\nas\home\$env:USERNAME"
    )

    $nasSshPath    = Join-Path $NasHome '.ssh'
    $nasConfigFile = Join-Path $nasSshPath 'config'
    $nasKeyPath    = Join-Path $nasSshPath $KeyName
    $nasAuthFile   = Join-Path $NasSshPath 'authorized_keys'


    @($nasSshPath, $localSshPath) | Where-Object { -not (Test-Path $_) } | ForEach-Object {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }

    if (-not (Select-String -Pattern $KeyName -Path $nasConfigFile -Quiet))
    {
        if (-not (Test-Path $nasKeyPath))
        {
            ssh-keygen -f "$nasKeyPath" -C "''" -N "''" -t ecdsa -q
        }
        $pubKey = ssh-keygen -yf $nasKeyPath

        if (-not (Select-String -Pattern $pubKey -Path $nasAuthFile))
        {
            $pubKey | Add-Content -Encoding UTF8 -Path $nasAuthFile
        }
        
    }

}
