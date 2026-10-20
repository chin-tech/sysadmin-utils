function ConvertTo-ColorRef {
   param(
      [string]$Hex
   )

   $hex = $Hex.TrimStart('#')

   $r = [Convert]::ToInt32($hex.Substring(0, 2), 16)
   $g = [Convert]::ToInt32($hex.Substring(2, 2), 16)
   $b = [Convert]::ToInt32($hex.Substring(4, 2), 16)

   return ($b -shl 16) -bor ($g -shl 8) -bor $r
}

HKCU\Console\VirtualTerminalLevel = 1

0..15 | ForEach-Object {
   $name = 'ColorTable{0:D2}' -f $_
   $value = [uint32](Get-ItemPropertyValue `
         -Path 'HKCU:\Console' `
         -Name $name)

   [PSCustomObject]@{
      Index = $_
      Name  = $name
      Hex   = '0x{0:X8}' -f $value
      RGB   = '#{0:X2}{1:X2}{2:X2}' -f `
      ($value -band 0xFF), `
      (($value -shr 8) -band 0xFF), `
      (($value -shr 16) -band 0xFF)
   }
} | Format-Table -AutoSize

function Show-Color {
   param([Parameter(Mandatory, ValueFromPipeline)][string]$Hex)
   process {
      $h = $Hex.TrimStart('#')
      $r, $g, $b = 0, 2, 4 | ForEach-Object { [Convert]::ToInt32($h.Substring($_, 2), 16) }
      $e = [char]27
      "$e[48;2;$r;$g;${b}m        $e[0m  #$h  ($r, $g, $b)"
   }
}

'FF8000', '#00A0FF', '2E7D32' | Show-Color


## GRADIENT
$e = [char]27
-join (0..63 | ForEach-Object { $r = $_ * 4; "$e[48;2;$r;0;$(255 - $r)m $e[0m" })




