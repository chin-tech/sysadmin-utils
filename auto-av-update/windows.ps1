# Identify device
#
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like "*USB*" } | Select-Object FriendlyName, InstanceId
### example output

##
# USB\VID_0781&PID_5567\001A4D5E6F7G8H9I
#    ^^^^     ^^^^   ^^^^^^^^^^^^^^^^
#    VID      PID       Serial
# ### Script to run, probably not entirely relevant for us
# C:\Scripts\USB-Action.ps1

$LogPath = "C:\ProgramData\usb-action.log"
$Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
Add-Content -Path $LogPath -Value "[$Timestamp] USB Device Event Triggered"

# 1. Bypass disabled USB storage driver (if restricted to Start=4)
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
$currentStart = (Get-ItemProperty -Path $regPath -Name Start -ErrorAction SilentlyContinue).Start

if ($currentStart -eq 4) {
   Add-Content -Path $LogPath -Value "[$Timestamp] USBSTOR is disabled (4). Enabling on the fly..."
   Set-ItemProperty -Path $regPath -Name "Start" -Value 3
   Start-Service USBSTOR -ErrorAction SilentlyContinue
    
   # Optional: trigger device manager hardware rescan if needed
   # (requires devcon.exe or pnputil)
   pnputil /scan-devices
}

# 2. Wait up to 10 seconds for the volume/disk to become available
$timeout = 10
$drive = $null
while ($timeout -gt 0) {
   # Match on specific volume label, partition, or target USB disk
   $drive = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | Select-Object -First 1
   if ($drive) { break }
   Start-Sleep -Seconds 1
   $timeout--
}

if ($drive) {
   Add-Content -Path $LogPath -Value "[$Timestamp] Target Drive mounted at $($drive.DriveLetter):"
    
   # -------------------------------------------------------------
   # YOUR CUSTOM ACTION HERE
   # -------------------------------------------------------------
   # Example: Run a script from the drive, copy files, etc.
} else {
   Add-Content -Path $LogPath -Value "[$Timestamp] Drive letter failed to mount within timeout."
}

####

#Event Trigger

# Define the XML event query matching your specific VID and PID
$vendorId  = "0781"
$productId = "5567"

$query = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Kernel-PnP/Configuration">
    <Select Path="Microsoft-Windows-Kernel-PnP/Configuration">
      *[System[(EventID=410)]] 
      and 
      *[EventData[Data[@Name='DeviceInstanceId'] and (contains(., 'VID_$vendorId') and contains(., 'PID_$productId'))]]
    </Select>
  </Query>
</QueryList>
"@

$action = New-ScheduledTaskAction `
   -Execute 'powershell.exe' `
   -Argument '-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Scripts\USB-Action.ps1'

$trigger = New-ScheduledTaskTrigger -AtStartup # placeholder
$trigger.Subscription =$query
$trigger.Enabled =$true

$principal = New-ScheduledTaskPrincipal `
   -UserId "NT AUTHORITY\SYSTEM" `
   -LogonType ServiceAccount `
   -RunLevel Highest

Register-ScheduledTask `
   -TaskName "USB-Action-Trigger" `
   -Action $action `
   -Trigger $trigger `
   -Principal $principal `
   -Force

## 
