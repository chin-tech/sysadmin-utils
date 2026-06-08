

$certName  
$windowsComputers = @()
$LinuxDeployReference = @()
$users = @{}

$cert = Get-ChildItem "Cert:\currentuser\my" | ? { $_.Subject -match $certName }




if (! ( Test-Path $cert )) {
    Write-Error "[!] Certificate failed to be found"
    return
}

if (! ($cert.HasPrivateKey )) {
    Write-Error "[!] Wrong Cert Buddy...."
}

$files = Get-ChildItem -Force -Recurse $pathToSearch
### Decryption
$p = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$pad = [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256

foreach ($f in $files) {
    $content = Get-Content $f
    $content | % { 
        $b = [System.Convert]::FromBase64String($_)
        $d = $p.Decrypt($b, $pad)
        $dMsg = [System.Text.Encoding]::UTF8.GetString($d)
        ## Format specific things here

        $user, $pass = $dMsg -Split ':'
        $users[$user] = ConvertTo-SecureString -Force -AsPlainText $pass
        }
}
$p.Dispose()


$windowsScriptBlock = {
    $hostName = (hostname)
    $userDict = $using:users
    foreach ($u in $userDict.keys) {
        if (! (Get-LocalUser -Name $u -ErrorAction SilentlyContinue )) { 
            New-LocalUser -Name $u -Password $userDict[$u]
        } else {
            Set-LocalUser -Name $u -Password $userDict[$u]
        }
    }
    Write-Host "[+] $hostName ... Users created "
}

$linuxScript = "
./deploy.sh
"
    


Invoke-Command -ComputerName $windowsComputers -ScriptBlock $windowsScriptBlock

$key_path = "C:\Users\$env:Username\.ssh\key"
$nas_ssh = "\\nas_path\home\$env:Username\.ssh\"
$ssh_auth = Join-Path $nash_ssh "authorized_keys"
if (! ( Test-Path $key_path ) ) {
    ssh-keygen -f $key_path -N "" -C "local_accounts" -t ecdsa
    Get-Content $key_path.pub >> $ssh_auth
}

ssh -q $LinuxDeployReference "./deploy.sh"

