[CmdletBinding(DefaultParameterSetName = 'Info')]
param(
   # --- Mode Switches ---
   [Parameter(Mandatory = $true, ParameterSetName = 'Info')]
   [switch]$Info,

   [Parameter(Mandatory = $true, ParameterSetName = 'Deploy')]
   [switch]$Deploy,

   [Parameter(Mandatory = $true, ParameterSetName = 'GPOAdd')]
   [Parameter(Mandatory = $true, ParameterSetName = 'GPORemove')]
   [switch]$GPO,

   # --- Sub-Action Switches (GPO) ---
   [Parameter(Mandatory = $true, ParameterSetName = 'GPOAdd')]
   [switch]$Add,

   [Parameter(Mandatory = $true, ParameterSetName = 'GPORemove')]
   [switch]$Remove,

   # --- Target Mobile Name ---
   # Optional for 'Info' (defaults to overview if omitted), Mandatory for all others
   [Parameter(Mandatory = $false, ParameterSetName = 'Info', Position = 0)]
   [Parameter(Mandatory = $true, ParameterSetName = 'Deploy', Position = 0)]
   [Parameter(Mandatory = $true, ParameterSetName = 'GPOAdd', Position = 0)]
   [Parameter(Mandatory = $true, ParameterSetName = 'GPORemove', Position = 0)]
   [string]$Name,

   # --- Force Switch (Restricted to GPO Actions) ---
   [Parameter(ParameterSetName = 'GPOAdd')]
   [Parameter(ParameterSetName = 'GPORemove')]
   [switch]$Force
)

begin 
{

   $CONSTANTS = @{}
   $CONSTANTS['GPO-ID'] = ''


   $PATHS = @{}
   $PATHS['Utils'] = '\\nas2\admin\utils'
   $PATHS['ppSolution'] = Join-Path $PATHS['Utils'] 'password_party_solution'
   $PATHS['EncryptionPFX'] = Join-Path $PATHS['ppSolution'] 'encryption.pfx'


   ## MobileDump Paths
   $PATHS['mobileFolder'] = '\\netapp\home\.mobileFolder' 
   $PATHS['mobileDump'] = Join-Path $PATHS['mobileFolder'] '.dump'
   $PATHS['mobileDefault'] = Join-Path $PATHS['mobileFolder'] '.default'
   $PATHS['mobileEntries'] = Join-Path $PATHS['mobileFolder'] '.mobile'

   ## Tasks
   $PATHS['TaskFolder'] = Join-Path $PATHS['Utils'] 'Tasks'
   $PATHS['disjoinTask'] = Join-Path $PATHS['TaskFolder'] 'disJoinTask.xml'
   $PATHS['avTask'] = Join-Path $PATHS['TaskFolder'] 'avTask.xml'


   $OutTasks = @{
      'disjoinTask'= @{'Data' = ''; 'xmlPath'= 'C:\Temp\djtask.xml'; 'taskName' = 'disjoinTask'}
      'avTask'= @{'Data' = ''; 'xmlPath'= 'C:\Temp\avtask.xml'; 'taskName' = 'avTask'}
   }


   function Get-FileBytes
   {
      [CmdletBinding()]
      param(
         [Parameter(Mandatory = $true, Position= 0, ValueFromPipeline= $true, ValueFromRemainingArguments = $true)]
         [string[]]$filePaths
      )

      process
      {
         $res = @()
         foreach ($p in $filePaths)
         {
            $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p)

            if (Test-Path $fullPath -PathType Leaf)
            {
               $res += [System.Io.File]::ReadAllBytes("\\?\$fullPath")
            } else
            {
               Write-Error "[!] - File not found $p"
            }
         }
         return $res
      }
   }



   function New-CustomXmlTask
   {
      [CmdletBinding()]
      param(
         [Parameter(Mandatory=$true)][string]$TaskName,
         [Parameter(Mandatory=$true)][string]$TaskPath,
         [Parameter(Mandatory=$true)][string]$Command,
         [Parameter()][string]$Arguments = "",
         [Parameter()][string]$ExecutionTimeLimit = "PT72H", # 72 hours
         [bool]$IsHidden = $true
      )

      # Step 1: Generate base task definition via PowerShell cmdlets
      $action    = New-ScheduledTaskAction -Execute $Command -Argument $Arguments
      $trigger   = New-ScheduledTaskTrigger -AtLogOn
      $settings  = New-ScheduledTaskSettingsSet -Hidden:$IsHidden -AllowStartIfOnBatteries
      $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

      $taskDef = New-ScheduledTaskDefinition -Action $action -Trigger $trigger -Settings $settings -Principal $principal

      # Step 2: Convert to XML DOM for fine-grained editing
      [xml]$xmlDoc = $taskDef.Xml

      # Manage XML Namespaces for XPath queries
      $nsmgr = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
      $nsmgr.AddNamespace("task", "http://schemas.microsoft.com/windows/2004/02/mit/task")

      # Step 3: Inject custom XML elements or modify existing nodes
       
      # Example A: Modify/Ensure ExecutionTimeLimit under <Settings>
      $settingsNode = $xmlDoc.SelectSingleNode("//task:Settings", $nsmgr)
      $timeLimitNode = $settingsNode.SelectSingleNode("task:ExecutionTimeLimit", $nsmgr)
      if ($null -eq $timeLimitNode)
      {
         $timeLimitNode = $xmlDoc.CreateElement("ExecutionTimeLimit", "http://schemas.microsoft.com/windows/2004/02/mit/task")
         $settingsNode.AppendChild($timeLimitNode) | Out-Null
      }
      $timeLimitNode.InnerText = $ExecutionTimeLimit

      # Example B: Add a custom Description in <RegistrationInfo>
      $regInfoNode = $xmlDoc.SelectSingleNode("//task:RegistrationInfo", $nsmgr)
      if ($null -eq $regInfoNode)
      {
         $regInfoNode = $xmlDoc.CreateElement("RegistrationInfo", "http://schemas.microsoft.com/windows/2004/02/mit/task")
         $xmlDoc.Task.PrependChild($regInfoNode) | Out-Null
      }
      $descNode = $xmlDoc.CreateElement("Description", "http://schemas.microsoft.com/windows/2004/02/mit/task")
      $descNode.InnerText = "Dynamically built XML task."
      $regInfoNode.AppendChild($descNode) | Out-Null

      # Step 4: Register the modified XML string
      $finalXmlString = $xmlDoc.OuterXml

      Register-ScheduledTask `
         -TaskName $TaskName `
         -TaskPath $TaskPath `
         -Xml $finalXmlString `
         -Force
   }


   function New-Tasks 
   {
      [CmdletBinding()]
      param(
         [Parameter(Mandatory = $true, Position= 0, ValueFromPipeline= $true, ValueFromRemainingArguments = $true)]
         [Dictionary]$items
      )

      foreach ($key in $items.Keys)
      {
         Register-ScheduledTask -TaskName $items[$key]['taskName'] -xml $items[$key]['xmlData']
      }
   }


   function Get-MobileData
   {
      param([string]$mobileName)
      $mobileData = [ordered]@{}
      $mobileData['AllMobiles'] = Get-ChildItem -force -path $PATHS['mobileEntries'] -include "*.csv" | Select-Object Name | Sort-Object -Unique -Property Name
      if (([string]::IsNullOrWhiteSpace($mobileName)))
      { return $mobileData
      }
      $curSection = $null
      $mobileContent = Get-Content $PATHS['mobileEntries']
      foreach ($line in $mobileContent)
      {
         $trimmed = $line.Trim()
         if ([string]::IsNulllOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#') -or $trimmed.StartsWith(';')) 
         {
            continue
         }
         if ($trimmed -match '^\[?<Header>.+\]$') 
         {
            $curSection = $Matches['Header']
            $mobileData[$curSection] = [System.Collections.Generic.List[string]]::new()

         } elseif ($null -ne $curSection)
         {
            $mobileData[$curSection].Add($trimmed)
         }
      }
      $mobileData['mobileUsers'] = $mobileData['Users'] | ConvertFrom-Csv
      $mobileData['defaultUsers'] = Import-Csv $PATHS['defaultUsers'] 
      $mobileData['AllUsers'] = $mobileData['Users'] + $mobileData['defaultUsers']
      return $mobileData
   }


   function Get-MobileOverview 
   {
      $mobileData = Get-MobileData
      if ($mobileData['AllMobiles'].lenth -eq 0 )
      {
         Write-Host "--------------------"
         Write-Host "No Available Mobiles"
         Write-Host "--------------------"
         return
      }
      Write-Host "---------------------"
      Write-Host "- Available Mobiles -"
      Write-Host "---------------------"
      foreach ($m in $mobileData['AllMobiles'])
      {
         Write-Host "`t$m"
      }



   }

   function Set-MobileGPO 
   {
      param(
         [string]$mobileName, [switch]$Add, [switch]$Remove, [switch]$Force
      )

      if (!([string]::IsNullOrWhiteSpace($mobileName)) -and $Force -eq $true -and $Remove) 
      {
         Get-GPPermission -GUID $CONSTANTS['GPO-ID'] -All | ?{ $_.Trustee.SidType -eq 'User' -and $_.Permission -eq 'GpoRead'} | %{ Set-GPPermission -Guid $CONSTANTS['GPO-ID'] -TargetName $_.Trustee.Name -TargetType User -PermissionLevel None -Confirm $false}
         Write-Host '[+] Removed all users from the MobileGPO'
         return
      }
      $mobileData = Get-MobileData $mobileName 
      $allUsers = $mobileName.defaultUsers + $mobileName.mobileUsers
      if ($Add)
      {
         foreach ($u in $allUsers)
         {
            Set-GPPermission -GUID $CONSTANTS['GPO-ID'] -TargetName $u.Name -TargetType User -PermissionLevel GpoRead -Confirm $false -ErrorAction SilentlyContinue

         }
         Write-Host "[+] Added all users from $mobileName to the MobileGPO"
         return
      }
      if ($Remove)
      {
         foreach ($u in $mobileData.mobileUsers)
         {
            Set-GPPermission -GUID $CONSTANTS['GPO-ID'] -TargetName $u.Name -TargetType User -PermissionLevel GpoRead -Confirm $false -ErrorAction SilentlyContinue

         }
         Write-Host "[+] Removed all users from $mobileName to the MobileGPO"
         return

      }

   }

   function Test-SSH
   {
      [CmdletBinding()]
      param()
      # Path setup
      $keyName = "deployer"
      $nasHome = "\\nas\home\$env:USERNAME"
      $nasSshPath = Join-Path $nasHome ".ssh"
      $nasConfigFile = Join-Path $nasSshPath "config"
      $nasKeyPath = Join-Path $nasSshPath $keyName

      $localSshPath = Join-Path $env:USERPROFILE ".ssh"
      $localConfigFile = Join-Path $localSshPath "config"
      $localKeyPath = Join-Path $localSshPath $keyName

      # 1. Ensure directories exist
      if (-not (Test-Path $nasSshPath))
      { 
         New-Item -ItemType Directory -Path $nasSshPath -Force | Out-Null 
      }
      if (-not (Test-Path $localSshPath))
      { 
         New-Item -ItemType Directory -Path $localSshPath -Force | Out-Null 
      }

      # 2. Ensure config file exists on NAS
      if (-not (Test-Path $nasConfigFile))
      { 
         New-Item -ItemType File -Path $nasConfigFile -Force | Out-Null 
      }

      # 3. Check if key entry already exists in the config
      $keyConfigured = Select-String -Pattern $keyName -Path $nasConfigFile -Quiet

      if (-not $keyConfigured)
      {
         # Generate the SSH key on the NAS if it doesn't already exist on disk
         if (-not (Test-Path $nasKeyPath))
         {
            ssh-keygen -f "$nasKeyPath" -C "''" -N "''" -t ecdsa -q
         }

         # Append IdentityFile to NAS config (appends without overwriting)
         $configBlock = @"

# Auto-added deployer key
Host *
    IdentityFile ~/.ssh/$keyName
"@
         Add-Content -Path $nasConfigFile -Value $configBlock -Encoding utf8
      }

      # 4. Sync NAS .ssh directory to local Windows ~/.ssh
      # (Windows OpenSSH often fails on UNC network paths due to strict NTFS ACL checks)
      Get-ChildItem -Path $nasSshPath -Recurse | ForEach-Object {
         $destination = Join-Path $localSshPath $_.Name
         Copy-Item -Path $_.FullName -Destination $destination -Force
      }

      # 5. Fix Windows local ACL permissions on private key (OpenSSH requirement)
      if (Test-Path $localKeyPath)
      {
         $acl = Get-Acl $localKeyPath
         $acl.SetAccessRuleProtection($true, $false) # Disable inheritance
         $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $env:USERNAME, "FullControl", "Allow"
         )
         $acl.SetAccessRule($rule)
         Set-Acl -Path $localKeyPath -AclObject $acl
      }
   }


   function Get-EncryptedCred  
   {
      param(
         [parameter(Mandatory = $true)][string]$passwordFile,
         [parameter(Mandatory = $true)][string]$defaultPass
      )
      $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PATHS['EncryptionPFX'])
      $rsa = $cert.GetRSAPrivateKey()

      try
      {
         $eBytes = [System.Convert]::FromBase64String((Get-Content $passwordFile))
         $padding = [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1
         $dBytes = $rsa.Decrypt($eBytes, $padding)
         return [System.Text.Encoding]::UTF8.GetString($dBytes)

      } catch
      {
         return $defaultPass
      } finally
      {
         $rsa.Dispose()
         $cert.Dispose()
      }

   }

   function Get-UserCreds 
   {
      param(
         [Parameter(Mandatory=$true)]
         [string]$mobileName,
         [array]$userList,
         [securestring]$defaultPass
      )

      $userCreds = @{}
      foreach ($u in $userList)
      {
         $pwFile = Get-ChildItem -Path $PATHS['mobileDump'] -Filter "$($u.Name)*"
         
         {
            foreach ($g in ($u.Groups -split ','))
            {
               $userCreds[$u.Name][$g] = Get-EncryptedCred $pwFile
            }

         } 
         

      }
   }

   function Deploy-Windows 
   {
      param(
         [Parameter(Mandatory=$true)]
         [string]$mobileName,
         [string]$encryptPass = 'defaultPin',
         [string]$userPass = 'defaultPassword'
      )

      $bitLockerPin = ConvertTo-SecureString -AsPlainText -Force $encryptPass
      $defaultPass = ConvertTo-SecureString -AsPlainText -Force $userPass

      $mobileData = Get-MobileData $mobileName
      $allUsers = $mobileData.defaultUsers + $mobileData.mobileUsers
      $userCreds = Get-UserCreds -userList $allUsers -defaultPass $defaultPass -mobileName $mobileName


   }




   


}
process
{
   switch ($PSCmdlet.ParameterSetName)
   {
      'Info'
      {
         Write-Host "Info Selected"
         return
         if ([string]::IsNullOrWhiteSpace($mobileName))
         {
            Get-MobileOverview
         } else
         {
            Get-MobileInfo -MobileName $mobileName
         }

      }
      'GPOAdd'
      {
         Write-Host "GPOAdd Selected with $add"
         # Set-MobileGPO -Add:$Add -Remove:$Remove -Force:$Force -mobileName $mobileName
      }

      'GPORemove'
      {
         Write-Host "GPORemove Selected with $remove and $force "
         # Set-MobileGPO -Add:$Add -Remove:$Remove -Force:$Force -mobileName $mobileName
      }
      'Deploy'
      { 
         Write-Host "Deploy Selected"
         # Deploy-Mobile -mobileName $mobileName 
      }
   }
}
