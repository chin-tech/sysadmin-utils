mkdir C:\ProgramData\JitBroker
@"
admin1
admin2
admin3
"@ | Set-Content C:\ProgramData\JitBroker\allowed_users.txt

icacls C:\ProgramData\JitBroker /inheritance:r /grant:r "NT AUTHORITY\SYSTEM":(OI)(CI)F /grant:r "BUILTIN\Administrators":(OI)(CI)F /grant:r "ADMIN_ACC_HERE":(OI)(CI)F /deny "BUILTIN\Users":(OI)(CI)RXW

## Compile service
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /out:C:\ProgramData\JitBroker\JitBroker.exe /r:System.DirectoryServices.AccountManagement.dll /r:System.ServiceProcess.dll JitBroker.cs


# Service create:
sc.exe create JitBroker binPath= "C:\ProgramData\JitBroker\JitBroker.exe" start= auto
sc.exe start JitBroker

