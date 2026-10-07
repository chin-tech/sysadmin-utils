
function Test-IPRange {
   param([string]$IP)
   $i = ($IP -split '\.',4)[0..2] -join '.'

   $pings = 1..254 | %{
      $range = "$i.$_"
      $p = [System.Net.NetworkInformation.Ping]::new()
      [PSCustomObject]@{ IP = $range ; Ping = $p; Task = $p.SendPingAsync($range,1000)}
   }

   try {[void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$pings.Task)} catch {}

   foreach ($x in $pings) {
      if ($x.Task.Result.Status -eq 'Success') {[PSCustomObject]@{ Host = $x.IP}}
      $x.Ping.Dispose()
   }
}


function Test-Ports {
   param(
      [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
      [string[]]$ComputerName,
      [Parameter(Mandatory, Position = 1)][int]$Port,
      [int]$TimeoutMs = 1000,
      [int]$BatchSize = 256
   )

   begin   { $names = [System.Collections.Generic.List[string]]::new() }

   process { foreach ($t in $ComputerName) { $names.Add($t) } }

   end {
      for ($i = 0; $i -lt $names.Count; $i += $BatchSize) {
         $last  = [Math]::Min($i + $BatchSize, $names.Count) - 1
         $batch = foreach ($t in $names[$i..$last]) {
            $c = [System.Net.Sockets.TcpClient]::new()
            [PSCustomObject]@{ ComputerName = $t; Client = $c; Task = $c.ConnectAsync($t, $Port) }
         }

         try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($batch.Task), $TimeoutMs) } catch {}

         foreach ($x in $batch) {
            [PSCustomObject]@{
               ComputerName = $x.ComputerName
               Port         = $Port
               Open         = ($x.Task.Status -eq 'RanToCompletion' -and $x.Client.Connected)
            }
            $x.Client.Dispose()
         }
      }
   }
}
