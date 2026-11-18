

function Get-RegistryComPorts($Root = 'hklm:\system\currencontrolset') {
   Get-ChildItem "$Root\Enum" -Recurse -ErrorAction SilentlyContinue | ? PSChildName -eq 'Device Parameters' | % {
      $p = $_.GetValue('PortName')
      if ($p -match '^COM') {
         [PSCustomObject]@{
            Port = $p
            InstanceID = $_.Parent.Name
            Registry = $_.Name
         }
      }
   }
}

## Compare

$oldControl = (Get-ItemProperty 'HKLM:\OFFLINE\Select').Current
$oldRoot = 'HKLM:\OFFLINE\ControlSet{0:D3}' -f $oldControl

$old = Get-RegistryComPorts -Root $oldRoot
$new = Get-RegistryComPorts

$comparison = foreach ($d in $old) {
   $m = $new | ? InstanceID -eq $d.InstanceId
   [PSCusotmObject]@{
      InstanceID = $d.InstanceID
      OldPort = $d.Port
      NewPort = ($m.Port -Join ', ')
      Match = if ($m) { 'Found' } else {'Missing'}
   }
}


$comparison | Format-Table -Autosize
