# Com arbiter offsetting:
#This is a binary REG_BINARY array where each bit represents a COM port (bit 0 of byte 0 is COM1, bit 1 is COM2, etc.).

#If byte 0 is set to 0x7F (01111111 in binary), Windows considers COM1 through COM7 occupied. Any newly plugged-in generic device will skip directly to COM8.
## Reserve COM1 through COM7 so PnP auto-assignment starts at COM8
$arbiterKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\COM Name Arbiter'
$currentDb = (Get-ItemProperty -Path $arbiterKey).ComDB

if ($currentDb) {
   # Set the first 7 bits (0x7F = 0111 1111b)
   $currentDb[0] = $currentDb[0] -bor 0x7F
   Set-ItemProperty -Path $arbiterKey -Name 'ComDB' -Value $currentDb
}


# Com setting bia regisry:
#
#
function Set-DeviceComPort {
   param(
      [Parameter(Mandatory=$true)][string]$DeviceInstanceId,
      [Parameter(Mandatory=$true)][string]$TargetComPort # e.g. "COM1"
   )

   # Note: SYSTEM ownership by default on Enum keys. Run as SYSTEM or take ownership.
   $deviceParamPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$DeviceInstanceId\Device Parameters"
   $parentPath      = "HKLM:\SYSTEM\CurrentControlSet\Enum\$DeviceInstanceId"

   if (Test-Path $deviceParamPath) {
      # 1. Update the functional port assignment
      Set-ItemProperty -Path $deviceParamPath -Name "PortName" -Value $TargetComPort

      # 2. Update the Friendly Name display (e.g., "USB Serial Port (COM1)")
      $currentName = (Get-ItemProperty -Path $parentPath).FriendlyName
      if ($currentName -match '^(.*?)\s*\(COM\d+\)$') {
         $baseName = $Matches[1]
         Set-ItemProperty -Path $parentPath -Name "FriendlyName" -Value "$baseName ($TargetComPort)"
      }

      # 3. Mark the port in the Arbiter database
      $portNum = [int]($TargetComPort -replace '\D')
      # (Update bit position in ComDB corresponding to $portNum)
   }
}

### Udev-like scheduled task detection:
# Query your specific device class or Hardware ID
$targetHardwareId = "VID_0403&PID_6001" # Example: FTDI Serial
$desiredPort      = "COM1"

$devices = Get-CimInstance Win32_PnPEntity | Where-Object { 
   $_.HardwareID -like "*$targetHardwareId*" -or $_.Caption -like "*MyCustomHardware*" 
}

foreach ($dev in $devices) {
   $instanceId = $dev.DeviceID
   $paramKey   = "HKLM:\SYSTEM\CurrentControlSet\Enum\$instanceId\Device Parameters"

   $currentPort = (Get-ItemProperty -Path $paramKey -ErrorAction SilentlyContinue).PortName
   if ($currentPort -ne $desiredPort) {
      # Change PortName
      Set-ItemProperty -Path $paramKey -Name "PortName" -Value $desiredPort

      # Restart device to reload driver stack with new port
      pnputil /restart-device "$instanceId"
   }
}

### Look for events 64016 or 20001 in Windows-Kernel-PnP/Configuration
