## Windows Updater
## You may be in an environment where you havev to manually execute updates.
## Doing so is pretty terrible via the gui.


<#
.SYNOPSIS
    Installs pending Windows Updates via COM API as SYSTEM, suspends BitLocker, and reboots.
.DESCRIPTION
    - Creates a Microsoft.Update.Session instance.
    - Searches for non-installed, non-hidden updates.
    - Downloads pending updates and verifies download success.
    - Installs the updates and inspects HRESULT / OperationResultCode.
    - If reboot is required and allowed, suspends BitLocker for 1 reboot and restarts.
#>

[CmdletBinding()]
param(
   [Parameter()]
   [bool]$AllowReboot = $true,

   [Parameter()]
   [int]$RebootDelaySeconds = 60,

   [Parameter()]
   [string]$LogPath = "$env:ProgramData\MicrosoftUpdate_Script.log"
)

# --- Logging Helper ---
function Write-Log {
   param([string]$Message, [string]$Level = "INFO")
   $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
   $entry = "[$timestamp] [$Level] $Message"
   Write-Output $entry
   try {
      Add-Content -Path $LogPath -Value $entry -ErrorAction SilentlyContinue
   } catch {}
}

Write-Log "================ Windows Update Run Started ================"

# 1. Verify SYSTEM / Administrator Privileges
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
   Write-Log "Script must be run as Administrator or SYSTEM." "ERROR"
   exit 1
}

try {
   # 2. Initialize Update Session
   Write-Log "Initializing Microsoft.Update.Session COM Object..."
   $updateSession = New-Object -ComObject Microsoft.Update.Session
   $updateSearcher = $updateSession.CreateUpdateSearcher()

   # Search criteria: Not installed and not hidden
   # "IsInstalled=0 and Type='Software' and IsHidden=0" (Can include drivers if needed)
   $searchCriteria = "IsInstalled=0 and IsHidden=0"
   Write-Log "Searching for pending updates using criteria: '$searchCriteria'..."
    
   $searchResult = $updateSearcher.Search($searchCriteria)
   $updatesCount = $searchResult.Updates.Count

   if ($updatesCount -eq 0) {
      Write-Log "No pending updates found. System is up to date."
      exit 0
   }

   Write-Log "Found $updatesCount update(s) to process:"
   foreach ($update in $searchResult.Updates) {
      Write-Log " - $($update.Title) (KB: $(($update.KBArticleIDs -join ', ')))"
   }

   # 3. Create Update Collection & Accept EULAs
   $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
   foreach ($update in $searchResult.Updates) {
      if (-not $update.EulaAccepted) {
         $update.AcceptEula()
      }
      $updatesToDownload.Add($update) | Out-Null
   }

   # 4. Download Updates
   Write-Log "Downloading updates..."
   $downloader = $updateSession.CreateUpdateDownloader()
   $downloader.Updates = $updatesToDownload
   $downloadResult = $downloader.Download()

   Write-Log "Download phase completed with ResultCode: $($downloadResult.ResultCode) (2=Succeeded, 3=SucceededWithErrors, 5=Failed)"

   # Filter only successfully downloaded updates
   $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
   for ($i = 0; $i -lt $updatesToDownload.Count; $i++) {
      $u = $updatesToDownload.Item($i)
      if ($u.IsDownloaded) {
         $updatesToInstall.Add($u) | Out-Null
      } else {
         Write-Log "Update failed to download: $($u.Title)" "WARN"
      }
   }

   if ($updatesToInstall.Count -eq 0) {
      Write-Log "None of the applicable updates were downloaded successfully." "ERROR"
      exit 2
   }

   # 5. Install Updates
   Write-Log "Installing $($updatesToInstall.Count) update(s)..."
   $installer = $updateSession.CreateUpdateInstaller()
   $installer.Updates = $updatesToInstall
    
   # Force installation flags
   $installer.ForceQuiet = $true

   $installResult = $installer.Install()

   # 6. Parse and Report Installation Results
   # Result codes: 2 = Succeeded, 3 = SucceededWithErrors, 4 = Failed, 5 = Aborted
   Write-Log "Installation completed. Overall ResultCode: $($installResult.ResultCode)"

   $hasSuccess = $false
   for ($i = 0; $i -lt $updatesToInstall.Count; $i++) {
      $update = $updatesToInstall.Item($i)
      $indivResult = $installResult.GetUpdateResult($i)
      $code = $indivResult.ResultCode
      $hresult = "0x{0:X8}" -f $indivResult.HResult

      $statusStr = switch ($code) {
         2 { "Succeeded"; $hasSuccess = $true }
         3 { "Succeeded with Errors"; $hasSuccess = $true }
         4 { "Failed" }
         5 { "Aborted" }
         default { "Unknown ($code)" }
      }

      Write-Log " -> [$statusStr | HRESULT: $hresult] $($update.Title)"
   }

   # 7. Check for Pending Reboot
   $rebootRequired = $installResult.RebootRequired

   # Supplementary check: registry pending reboot keys
   if (-not $rebootRequired) {
      $cbsReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
      $wuReboot  = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
      if ($cbsReboot -or $wuReboot) {
         Write-Log "A reboot is required according to system registry flags."
         $rebootRequired = $true
      }
   }

   # 8. BitLocker Suspension & System Reboot
   if ($rebootRequired) {
      Write-Log "Reboot is required."
        
      if ($AllowReboot) {
         # Check BitLocker status on OS drive
         Write-Log "Checking BitLocker status for OS drive..."
         try {
            $osDrive = $env:SystemDrive
            $blStatus = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction Stop

            if ($blStatus.ProtectionStatus -eq 'On') {
               Write-Log "BitLocker protection is ON for $osDrive. Suspending for 1 reboot..."
               Suspend-BitLocker -MountPoint $osDrive -RebootCount 1 -ErrorAction Stop
               Write-Log "BitLocker successfully suspended for 1 reboot."
            } else {
               Write-Log "BitLocker is not enabled/active on $osDrive (Status: $($blStatus.ProtectionStatus)). Skipping suspension."
            }
         } catch {
            Write-Log "Warning/Error checking or suspending BitLocker: $_" "WARN"
            # If Suspend-BitLocker cmdlet is unavailable, attempt manage-bde fallback:
            try {
               Write-Log "Attempting fallback via manage-bde.exe..."
               & manage-bde.exe -protectors -disable $env:SystemDrive -rebootcount 1
            } catch {
               Write-Log "Fallback manage-bde also failed: $_" "ERROR"
            }
         }

         Write-Log "Initiating system reboot in $RebootDelaySeconds seconds..."
         & shutdown.exe /r /t $RebootDelaySeconds /c "System restarting after installing Windows Updates." /f
      } else {
         Write-Log "Reboot is required, but AllowReboot is set to `$false. Skipping reboot." "WARN"
      }
   } else {
      Write-Log "No reboot is required at this time."
   }

} catch {
   Write-Log "An unexpected fatal exception occurred: $($_.Exception.Message)" "ERROR"
   Write-Log "$($_.ScriptStackTrace)" "ERROR"
   exit 1
} finally {
   Write-Log "================ Windows Update Run Finished ==============="
}
