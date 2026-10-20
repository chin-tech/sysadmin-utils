# Disable the first sign-in animation for all new users
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -PropertyType DWORD -Force

# Suppress the "Let's finish setting up your device" OOBE nagging screen
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfilePersonalization" -Name "IsFirstRun" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfilePersonalization" -Name "PersonalizationCompleted" -Value 1 -PropertyType DWORD -Force


## Edge
$EdgeKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $EdgeKey)) { New-Item -Path $EdgeKey -Force | Out-Null }

# Completely bypass the first run experience and splash screen
Set-ItemProperty -Path $EdgeKey -Name "HideFirstRunExperience" -Value 1 -Type DWord

# Prevent Edge from auto-importing browsing data from other browsers on first run
Set-ItemProperty -Path $EdgeKey -Name "AutoImportAtFirstRun" -Value 4 -Type DWord

# Suppress the "Make Edge your default browser" prompt
Set-ItemProperty -Path $EdgeKey -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWord

# Optional: Disable promotional splash pages / welcome tabs on updates
Set-ItemProperty -Path $EdgeKey -Name "PromotionalTabsEnabled" -Value 0 -Type DWord



## Chrome
$ChromeKey = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $ChromeKey)) { New-Item -Path $ChromeKey -Force | Out-Null }

# Suppress first-run bubbles, welcome screen, and sign-in prompts
Set-ItemProperty -Path $ChromeKey -Name "PromotionalTabsEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path $ChromeKey -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path $ChromeKey -Name "SyncDisabled" -Value 1 -Type DWord  # Skips sign-in / sync nag
Set-ItemProperty -Path $ChromeKey -Name "ImportAutofillFormData" -Value 0 -Type DWord
Set-ItemProperty -Path $ChromeKey -Name "ImportBookmarks" -Value 0 -Type DWord
Set-ItemProperty -Path $ChromeKey -Name "ImportHistory" -Value 0 -Type DWord
Set-ItemProperty -Path $ChromeKey -Name "ImportSavedPasswords" -Value 0 -Type DWord
Set-ItemProperty -Path $ChromeKey -Name "ImportSearchEngine" -Value 0 -Type DWord


$init_prefs = @'
{
  "distribution": {
    "skip_first_run_ui": true,
    "show_welcome_page": false,
    "import_bookmarks": false,
    "import_history": false,
    "import_search_engine": false,
    "make_chrome_default": false,
    "do_not_create_desktop_shortcut": true
  }
}
'@

Set-Content -Path "C:\Program Files\Google\Chrome\Application\initial_preferences" -value $init_prefs

"" > "C:\Program Data\Microsoft\Edge\User Data\First Run"

chrome.exe --no-first-run --no-default-browser-check
msedge.exe --no-first-run --no-default-browser-check
