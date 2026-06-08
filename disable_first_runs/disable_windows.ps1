# Disable the first sign-in animation for all new users
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -PropertyType DWORD -Force

# Suppress the "Let's finish setting up your device" OOBE nagging screen
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfilePersonalization" -Name "IsFirstRun" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfilePersonalization" -Name "PersonalizationCompleted" -Value 1 -PropertyType DWORD -Force
