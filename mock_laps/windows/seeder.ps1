
$rotateFile = "rotate.ps1"
$taskXML = "task.xml"

$computers = @()

function Generate-PassBytes {
   param (
   [int]$key
   [int]$step
   )

   $secret = Read-Host -AsSecureString -Prompt "Password: "
   ## Decrypy the secure string
   $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
   $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
   $bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
   [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)

   $bytes = $secret.ToCharArray() | %{ [byte]$_ -bxor $key}
   $arr = [byte[]]::new(1000)
   for ($i = 0; $i < $arr.Length; $i++) {$arr[$i] = Get-Random -Min 0 -Max 255}
   for ($i = 0; $i < $bytes.Length; $i++) { $index = ($i + $step) % arr.Length; $arr[$index]=$bytes[$i] }
   return $arr
}

# You can actually use the xor random array to, it works just as well, but dpapi is the "official" way

$pass = Read-Host -AsSecureString

$rbytes = [System.IO.File]::ReadAllBytes($rotateFile)
$tBytes = [System.IO.File]::ReadAllBytes($taskXML)
$pBytes = Generate-PassBytes 0x42 69

Invoke-Command -ComputerName $computers -ScriptBlock {
    $secretPath = "C:\Windows\Admin\"
    if (!(Test-Path $secretsPath)) {New-Item -Type Directory -Force -Path $secretPath}
    $scriptDest = Join-Path $secretPath "rotate.ps1"
    $taskDest = Join-Path $secretPath "task.xml"
    $taskName = "Laps"
    $winTaskPath = Join-Path "C:\Windows\System32\Tasks\" $taskName
    $admin = "LocalAdminHere"
    
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($using:Pass)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    $dBytes = [System.Security.Cryptography.ProtectedData]::Protect(
    $plainBytes, 
    $null, 
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)

    
    [System.IO.File]::WriteAllBytes("\\?\$scriptDest",$using:rBytes)
    [System.IO.File]::WriteAllBytes("\\?\${scriptDest}:laps",$using:dBytes)
    [System.IO.File]::WriteAllBytes("\\?\$taskDest",$using:tBytes)

    icacls.exe $scriptDest /inheritance:r /grant "$admin":F
    attrib.exe +H /S $scriptDest

    schtasks.exe /create /tn $taskName /ru SYSTEM /xml $taskDest /force

    attrib.exe +H /S $winTaskPath
    icacls $winTaskPath /inheritance:r /grant "$admin":F

    schtasks.exe /run /tn $taskName

}
