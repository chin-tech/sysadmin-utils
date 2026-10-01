
# Code Signing Cert
#
# Create a self-signed certificate with Code Signing EKU (1.3.6.1.5.5.7.3.3)
$cert = New-SelfSignedCertificate `
   -Type CodeSigningCert `
   -Subject "CN=Custom Kernel Driver Root" `
   -CertStoreLocation "Cert:\LocalMachine\My" `
   -KeyExportPolicy Exportable `
   -KeyLength 2048 `
   -HashAlgorithm SHA256

# Export the public certificate
Export-Certificate -Cert $cert -FilePath C:\certs\driver_signer.cer


## Sign Binary
signtool.exe sign /v /fd sha256 /s My /n "Custom Kernel Driver Root" /t http://timestamp.digicert.com driver.sys


# Generate base policy from template
New-CIPolicy -Level Publisher -FilePath C:\certs\DriverPolicy.xml -DriverFiles C:\certs\driver.sys -UserPEs:$false

# Convert the XML policy to binary format
ConvertFrom-CIPolicy -XmlFilePath C:\certs\DriverPolicy.xml -BinaryFilePath C:\certs\DriverPolicy.bin


## Then Deploy the policy
# Copy DriverPolicy.bin to C:\Windows\System32\CodeIntegrity\SiPolicy.p7b (legacy/single-policy mode) or deploy via CiTool.exe -up C:\certs\DriverPolicy.bin (Windows 11 multi-policy engine).

# Reboot the machine. The kernel code integrity engine will evaluate your driver against the active WDAC policy and permit it to load alongside standard Microsoft-signed modules.
