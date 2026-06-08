

$prefix = "DesiredPrefixHere"
$PostFix = Get-Date -Format 'MMYY'

$cipherBytes = [System.IO.File]::ReadAllBytes("$PSCommandPath:laps")
$unwrappedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $cipherBytes, 
    $null, 
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)
$password = [System.Text.Encoding]::UTF8.GetString($unwrappedBytes)

$p = $prefix + $password + $postFix | ConvertTo-SecureString -AsPlainText -Force
Set-LocalUser -Name $admin -Password $p
if (! (glgm -name administrators -member $admin -ErrorAction SilentlyContinue)) { algm -name administrators -member $admin}
