#Requires -RunAsAdministrator 
# The Requires statement above is used to prevent the script from being ran by non-administrator users. Administrator priviledges are necessary for the bulk of the below commands to succesfully execute. 

# The Execution Policy must be set to unrestricted for the local machine in order for nixAndFixFreshWin11.ps1 to be allowed to properly execute.
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force

Start-Sleep 1

# Start
Write-Output "~~~Xx~~~XH~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~"
Write-Output "~~~~~~~~This script should be ran after the inital setup process for a new install of Windows 11.~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Write-Output "~~~~~~~~A local account should have been created.~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Write-Output "~~~~~~~~Cortana and privacy options should have all been set to 'No' or 'Off'.~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Write-Output "~~~~~~~~Starting the process for a good-ol-fashioned  NIixN &  FIixN for Windows 11.~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Write-Output "~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~Xx~~~"

Start-Sleep 5

Write-Output "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nSetting Default Desktop Wallpaper`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n"
# Set Desktop Wallpaper
$curDir = Get-Location
$parDir = Split-Path -Path $curDir -Parent
$defaultWallpaper = $parDir + "\img\Wallpaper.BMP"
Copy-Item -Path $defaultWallpaper -Destination "C:\Windows\Web\Wallpaper"
echo y | cmd /C reg add "HKEY_CURRENT_USER\control panel\desktop" /v wallpaper /t REG_SZ /d "" /f 
reg add "HKEY_CURRENT_USER\control panel\desktop" /v wallpaper /t REG_SZ /d C:\Windows\Web\Wallpaper\Wallpaper.BMP /f
reg add "HKEY_CURRENT_USER\control panel\desktop" /v WallpaperStyle /t REG_SZ /d 2 /f
RUNDLL32.EXE user32.dll, UpdatePerUserSystemParameters 

Write-Output "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nDisabling VBS, Credential Guard, and HVCI`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n"
# Disables Virtualization Based Security (VBS), Credential Guard and HVCI.
# "VBS uses hardware virtualization features to create and isolate a secure region of memory from the normal operating system. Windows can use this 'virtual secure mode' to host a number of security solutions, providing them with greatly increased protection from vulnerabilities in the operating system, and preventing the use of malicious exploits which attempt to defeat protections." 
Set-Itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0
Set-Itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0
Set-Itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" -Name "Enabled" -Value 0

Write-Output "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nRunning NTFS Performance Tweaks`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n"
# New Techology File System tweaks for performance
# Thank you to the wonderful human who provided this information - https://notes.ponderworthy.com/fsutil-tweaks-for-ntfs-performance-and-reliability
# Increases RAM cache devoted to NTFS
fsutil behavior set memoryusage 2

# Turns off disable last access file timestamp storage for files. Disindicated for some older backup systems
fsutil behavior set disablelastaccess 1

# Set the MFT zone to use two-eighths (25 percent)
fsutil behavior set mftzone 2
$DriveLetters = (Get-WmiObject -Class Win32_Volume).DriveLetter
ForEach ($Drive in $DriveLetters){
    If (-not ([string]::IsNullOrEmpty($Drive))){
        Write-Host Optimizing "$Drive" Drive
        fsutil resource setavailable "$Drive":\
        fsutil resource setlog shrink 10 "$Drive":\
    }
}

Write-Output "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nDisabling NetBIOS over TCP/IP Service`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n"
# Disable NetBIOS over TCP/IP service
# This legacy service (< Win2k) is vulnerable and shouldn't be used anymore.
# Do not remove if your computer belongs to your organization's network and you are not sure.
Set-Itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT" -Name "Start" -Value 4

Write-Output "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nDisabling UAC`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n"
# Disable UAC via Registry
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f

Write-Output "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nShow Hidden Files and Folder for File Explorer`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n"
# Enabling Show Hidden Files and Folders within the File Explorer via Registry Key
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

Write-Output "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nShow File Extensions in File Explorer`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n"
# Enable Show File Extension type within File Explorer via Registry Key
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f

Write-Output "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nRDISM Online cleanup image StartComponentCleanup`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n"
# Cleanup the component store clears temp files with updates leftover in WinSxS - automatically cleans up components when the system isn't in use
Invoke-Command -ScriptBlock { DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase }

Write-Output "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nRemoving Preinstalled AppX Programs`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n"

$global:whitelistedApps = @(
        "1527c705-839a-4832-9118-54d4Bd6a0c89"
        "c5e2524a-ea46-4f67-841f-6a9465d9d515"
        "E2A4F912-2574-4A75-9BB0-0D023378592B"
        "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE"
        "InputApp"
        "Microsoft.AAD.BrokerPlugin"
        "Microsoft.AccountsControl"
        "Microsoft.BioEnrollment"
        "Microsoft.CredDialogHost"
        "Microsoft.ECApp"
        "Microsoft.LockApp"
        "Microsoft.MicrosoftEdgeDevToolsClient"
        "Microsoft.MicrosoftEdge"
        "Microsoft.PPIProjection"
        "Microsoft.Win32WebViewHost"
        "Microsoft.Windows.Apprep.ChxApp"
        "Microsoft.Windows.AssignedAccessLockApp"
        "Microsoft.Windows.CapturePicker"
        "Microsoft.Windows.CloudExperienceHost"
        "Microsoft.Windows.ContentDeliveryManager"
        "Microsoft.Windows.HolographicFirstRun" 
        "Microsoft.Windows.NarratorQuickStart"
        "Microsoft.Windows.OOBENetworkCaptivePortal"
        "Microsoft.Windows.OOBENetworkConnectionFlow"
        "Microsoft.Windows.ParentalControls"
        "Microsoft.Windows.PeopleExperienceHost"
        "Microsoft.Windows.PinningConfirmationDialog"
        "Microsoft.Windows.SecHealthUI"
        "Microsoft.Windows.SecondaryTileExperience"
        "Microsoft.Windows.SecureAssessmentBrowser"
        "Microsoft.Windows.ShellExperienceHost"
        "Microsoft.Windows.XGpuEjectDialog"
        "Windows.CBSPreview"
        "windows.immersivecontrolpanel"
        "Windows.PrintDialog"
        "Microsoft.VCLibs.140.00"
        "Microsoft.Services.Store.Engagement"
        "Microsoft.UI.Xaml.2.0"
)

$global:debloatBlackList = @(
    "Microsoft.549981C3F5F10"
    "Microsoft.3DBuilder"
    "Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe"
    "Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe"
    "Microsoft.BingNews"
    "Microsoft.WindowsCalculator"
    "Clipchamp.Clipchamp"
    "Microsoft.GamingApp"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "MicrosoftCorporationII.MicrosoftFamily"
    "MicrosoftCorporationII.QuickAssist"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.OneNote"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.MSPaint"
    "Microsoft.People"
    "Microsoft.PPIProjection"
    "Microsoft.PowerAutomateDesktop"
    "Microsoft.Print3D"
    "Microsoft.RemoteDesktop"
    "Microsoft.ScreenSketch"
    "Microsoft.SkypeApp"
    "Microsoft.WindowsStore"
    "Microsoft.StorePurchaseApp"
    "Microsoft.ScreenSketch"
    "Microsoft.Todos"
    "MicrosoftTeams"
    "Microsoft.Office.Todo.List"
    "Microsoft.Whiteboard" 
    "Microsoft.WindowsAlarms"
    "Microsoft.Windows.Photos"
    "WindowsCamera"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.BingWeather"
    "Microsoft.WebMediaExtensions"  
    "Microsoft.WebpImageExtension"  
    "Microsoft.DesktopAppInstaller" 
    "WindSynthBerry"
    "MIDIBerry"
    "Slack"
    "Microsoft.MixedReality.Portal"
    "EclipseManager"
    "ActiproSoftwareLLC"
    "AdobeSystemsIncorporated.AdobePhotoshopExpress"
    "Duolingo-LearnLanguagesforFree"
    "PandoraMediaInc"
    "CandyCrush"
    "BubbleWitch3Saga"
    "Wunderlist"
    "Flipboard"
    "Twitter"
    "Facebook"
    "Spotify"
    "Minecraft"
    "Royal Revolt"
    "Sway"
    "Dolby"
)

Foreach ($app in $global:debloatBlackList) {
    Write-Verbose -Message ('Removing Package {0}' -f $app)
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $app } | Remove-AppxPackage
    Get-AppxPackage | Where-Object { $_.Name -like $app } | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object { $_.Name -like $app } | Remove-AppxProvisionedPackage -Online
}

Auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable
Auditpol /set /subcategory:"IPsec Driver" /success:disable /failure:enable
Auditpol /set /subcategory:"Other System Events" /success:disable /failure:enable
Auditpol /set /subcategory:"Process Termination" /success:disable /failure:enable
Auditpol /set /subcategory:"RPC Events" /success:disable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:disable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:disable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:disable /failure:enable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
DEL /q C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
reg add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "AllowTelemetry" /D 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-310093Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-314559Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-314563Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-338393Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-353694Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-353696Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "Subsc.exeribedContent-353698Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /t REG_DWORD /v Start_TrackProgs /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "sc.exeoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v NoExplicitFeedback /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v ConfigureWindowsSpotlight /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "DisableOptinExperience" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:cortana;crossdevice;easeofaccess-speechrecognition;holographic-audio;mobile-devices;privacy-automaticfiledownloads;privacy-feedback;recovery;remotedesktop;speech;sync;sync;easeofaccess-closedcaptioning;easeofaccess-highcontrast;easeofaccess-keyboard;easeofaccess-magnifier;easeofaccess-mouse;easeofaccess-narrator;easeofaccess-otheroptions;privacy-location;backup;findmydevice;quiethours;tabletmode" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Compatibility-Infrastructure-Debug" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Inventory" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bUpdater" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\DeviceHealthAttestationService" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d 00000000 /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DiagnosticData" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PromotionalTabsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "TrackingPrevention" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d 127.0.0.1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableWizard" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "SbEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "VDMDisallowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsc.exeonsumerFeatures" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d 00000000 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 00000000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 00000000 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 00000000 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d 00000000 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartsc.exereen" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "sc.exeenarioExecutionEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Audio" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\FaceRecoTel" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\FaceUnlock" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\NtfsLog" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\ReadyBoot" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManager" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\StorSvc" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\TokenBroker" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d 4 /f
REG ADD "HKLM\SYSTEM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d 25165824 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subsc.exeriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags" /v "UpgradeEligible" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f
Remove-Item -Path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\*" -Recurse
Remove-ItemProperty -Path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\" -Name "SubscribedContent-*Enabled"
sc.exe config "DcpSvc" start=disabled
sc.exe config diagnosticshub.standardcollector.service start= disabled
sc.exe config dmwappushservice start= disabled
sc.exe.exe config dmwappushservice start= disabled
schtasks /Change /TN "\Microsoft\Windows\AppID\Smartsc.exereenSpecific" /Disable
schtasks /Change /TN "\Microsoft\Windows\Application Experience\AitAgent" /Disable
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" /Disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\appuriverifierinstall" /Disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" /Disable
schtasks /Change /TN "\Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesc.exelient\UserTask-Roam" /Disable
schtasks /Change /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "\Microsoft\Windows\Data Integrity sc.exean\Data Integrity sc.exean for Crash Recovery" /Disable
schtasks /Change /TN "\Microsoft\Windows\Data Integrity sc.exean\Data Integrity sc.exean" /Disable
schtasks /Change /TN "\Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingsc.exeanner" /Disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\sc.exeheduled" /Disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "\Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "\Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "\Microsoft\Windows\ErrorDetails\ErrorDetailsUpdate" /Disable
schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnsc.exeenarioDownload" /Disable
schtasks /Change /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /Disable
schtasks /Change /TN "\Microsoft\Windows\FileHistory\File History `(maintenance mode`)" /Disable
schtasks /Change /TN "\Microsoft\Windows\IME\SQM data sender" /Disable
schtasks /Change /TN "\Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable
schtasks /Change /TN "\Microsoft\Windows\Location\WindowsActionDialog" /Disable
schtasks /Change /TN "\Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "\Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\ActivateWindowsSearch" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\ConfigureInternetTimeService" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\DispatchRecoveryTasks" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\ehDRMInit" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\InstallPlayReady" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\mcupdate" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\MediaCenterRecoveryTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\ObjectStoreRecoveryTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\OCURActivate" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\OCURDisc.exeovery" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\PBDADisc.exeovery" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\PBDADisc.exeoveryW1" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\PBDADisc.exeoveryW2" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\PvrRecoveryTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\Pvrsc.exeheduleTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\RegisterSearch" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\ReindexSearchRoot" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\SqlLiteRecoveryTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Media Center\UpdateRecordPath" /Disable
schtasks /Change /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "\Microsoft\Windows\NlaSvc\WiFiTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /Disable
schtasks /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" /Disable
schtasks /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" /Disable
schtasks /Change /TN "\Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\sc.exehedule sc.exean" /Disable
schtasks /Change /TN "\Microsoft\Windows\WCM\WiFiTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks /Change /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable
schtasks /Change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
schtasks /Change /TN "\Microsoft\Windows\WindowsUpdate\sih" /Disable
schtasks /Change /TN "\Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "\Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "\Microsoft\Windows\WS\WSTask" /Disable
schtasks /Change /TN "\Microsoft\XblGameSave\XblGameSaveTask" /Disable
schtasks /Change /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable
schtasks /Change /TN "\NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable
schtasks /Change /TN "\NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable
schtasks /Change /TN "\NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disabled
schtasks /Change /TN "\NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable
schtasks /change /tn "Adobe Acrobat Update Task" /disable
schtasks /change /tn "Adobe Flash Player Updater" /disable
schtasks /Change /TN "GoogleUpdateTaskMachineCore" /Disable
schtasks /Change /TN "GoogleUpdateTaskMachineUA" /Disable
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SlideshowEnabled" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0
Set-Itemproperty -path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:24048576
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:24048576
wevtutil sl "Microsoft-Windows-Tasksc.exeheduler/Operational" /e:true
wevtutil sl "Windows Powershell" /ms:24048576
wevtutil sl Application /ms:48048576
wevtutil sl Security /ms:48048576
wevtutil sl Setup /ms:48048576
wevtutil sl System /ms:48048576

# Start Menu: Disale Cortana 
If (-not(Test-Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings' -Name 'AcceptedPrivacyPolicy' -Type DWord -Value 0
If (-not(Test-Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitTextCollection' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Type DWord -Value 1
If (-not(Test-Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' -Name 'HarvestContacts' -Type DWord -Value 0
If (-not(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type DWord -Value 0

# Script courtesy of https://github.com/Sycnex/Windows10Debloater
Write-Output "Uninstalling OneDrive. Please wait."
    
New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
$ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
$ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Stop-Process -Name "OneDrive*"
Start-Sleep 2
If (!(Test-Path $onedrive)) 
{
    $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}
Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
Start-Sleep 2
Write-Output "Stopping explorer"
Start-Sleep 1
taskkill.exe /F /IM explorer.exe
Start-Sleep 3
Write-Output "Removing leftover files"
Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") 
{
    Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse
}
Write-Output "Removing OneDrive from windows explorer"
If (!(Test-Path $ExplorerReg1)) 
{
    New-Item $ExplorerReg1
}

# Activity Tracking: Disable
@('EnableActivityFeed','PublishUserActivities','UploadUserActivities') |% { Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name $_ -Type DWord -Value 0 }


Get-Service DiagTrack, Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled

# Uninstalls cortana on Windows 10 build 2004+
# Yes, you can fully remove her now!
Get-AppxPackage -AllUsers *Microsoft.549981C3F5F10* | Remove-AppxPackage



# WiFi Sense: HotSpot Sharing: Disable
If (Test-Path 'HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting') {
    Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0
}

# WiFi Sense: Shared HotSpot Auto-Connect: Disable
If (Test-Path 'HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots') {
    Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0
}


# Start Menu: Disable Bing Search Results
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0


# Disable Telemetry (requires a reboot to take effect)
If (Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -ErrorAction SilentlyContinue) {
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
}

# It is now possible to remove 3D Paint and 3D Print, but they forgot to remove the option in the context menu when you remove them. To remove it
cmd.exe /c "cmd.exe /c "for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%I" /f )"
cmd.exe /c "cmd.exe /c "for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%I" /f )"
cmd.exe /c "for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)"
cmd.exe /c "for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)"
cmd.exe /c "for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)"
cmd.exe /c "for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)"
cmd.exe /c "for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)"
cmd.exe /c "for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)"
cmd.exe /c "for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)"
cmd.exe /c "for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)"
cmd.exe /c sc.exe stop AdobeARMservice
cmd.exe /c sc.exe config AdobeARMservice start=disabled
cmd.exe /c sc.exe stop adobeflashplayerupdatesvc
cmd.exe /c sc.exe config adobeflashplayerupdatesvc start=disabled
cmd.exe /c sc.exe stop adobeupdateservice
cmd.exe /c sc.exe config adobeupdateservice start=disabled
cmd.exe /c sc config wlidsvc start=demand
cmd.exe /c sc delete diagnosticshub.standardcollector.service
cmd.exe /c sc delete diagsvc
cmd.exe /c sc delete DiagTrack
cmd.exe /c sc delete dmwappushservice
cmd.exe /c sc delete MessagingService
cmd.exe /c sc delete OneSyncSvc
cmd.exe /c sc delete PcaSvc
cmd.exe /c sc delete RetailDemo
cmd.exe /c sc delete SessionEnv
cmd.exe /c sc delete shpamsvc 
cmd.exe /c sc delete TermService
cmd.exe /c sc delete TroubleshootingSvc
cmd.exe /c sc delete UmRdpService
cmd.exe /c sc delete wercplsupport
cmd.exe /c sc delete WerSvc
cmd.exe /c sc delete wisvc

$PathToLMServicesXbgm = "HKLM:\SYSTEM\CurrentControlSet\Services\xbgm"
$TweakType = "Xbox"

$XboxServices = @(
    "XblAuthManager"                    # Xbox Live Auth Manager
    "XblGameSave"                       # Xbox Live Game Save
    "XboxGipSvc"                        # Xbox Accessory Management Service
    "XboxNetApiSvc"
)

$XboxApps = @(
    "Microsoft.GamingServices"          # Gaming Services
    "Microsoft.XboxApp"                 # Xbox Console Companion (Replaced by new App)
    "Microsoft.XboxGameCallableUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.XboxGamingOverlay"       # Xbox Game Bar
    "Microsoft.XboxIdentityProvider"    # Xbox Identity Provider (Xbox Dependency)
    "Microsoft.Xbox.TCUI"               # Xbox Live API communication (Xbox Dependency)
)

Write-Output -Types "-", $TweakType -Status "Disabling ALL Xbox Services..."
Set-ServiceStartup -Disabled -Services $XboxServices

Write-Output -Types "-", $TweakType -Status "Wiping Xbox Apps completely from Windows..."
Remove-UWPAppx -AppxPackages $XboxApps

Write-Output -Types "-", $TweakType -Status "Disabling Xbox Game Monitoring..."
If (!(Test-Path "$PathToLMServicesXbgm")) {
    New-Item -Path "$PathToLMServicesXbgm" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMServicesXbgm" -Name "Start" -Type DWord -Value 4


# Initialize all Path variables used to Registry Tweaks
$PathToLMMultimediaSystemProfile = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
$PathToLMMultimediaSystemProfileOnGameTasks = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
$PathToLMPoliciesPsched = "HKLM:\SOFTWARE\Policies\Microsoft\Psched"
$PathToLMPoliciesWindowsStore = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$PathToUsersControlPanelDesktop = "Registry::HKEY_USERS\.DEFAULT\Control Panel\Desktop"
$PathToCUControlPanelDesktop = "HKCU:\Control Panel\Desktop"
$PathToCUGameBar = "HKCU:\SOFTWARE\Microsoft\GameBar"

Write-Output-Text "Performance Tweaks"

Write-Output -Text "System"
Write-Caption -Text "Display"
Write-Output -Types "+", $TweakType -Status "Enable Hardware Accelerated GPU Scheduling... (Windows 10 20H1+ - Needs Restart)"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Remote Assistance..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value $Zero

Write-Output -Types "-", $TweakType -Status "Disabling Ndu High RAM Usage..."
# [@] (2 = Enable Ndu, 4 = Disable Ndu)
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Type DWord -Value 4

# Details: https://www.tenforums.com/tutorials/94628-change-split-threshold-svchost-exe-windows-10-a.html
# Will reduce Processes number considerably on > 4GB of RAM systems
Write-Output -Types "+", $TweakType -Status "Setting SVCHost to match installed RAM size..."
$RamInKB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $RamInKB

Write-Output -Types "+", $TweakType -Status "Unlimiting your network bandwidth for all your system..." # Based on this Chris Titus video: https://youtu.be/7u1miYJmJ_4
If (!(Test-Path "$PathToLMPoliciesPsched")) {
    New-Item -Path "$PathToLMPoliciesPsched" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMPoliciesPsched" -Name "NonBestEffortLimit" -Type DWord -Value 0
Set-ItemProperty -Path "$PathToLMMultimediaSystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff

Write-Output -Types "*", $TweakType -Status "Enabling Windows Store apps Automatic Updates..."
If (!(Test-Path "$PathToLMPoliciesWindowsStore")) {
    New-Item -Path "$PathToLMPoliciesWindowsStore" -Force | Out-Null
}
If ((Get-Item "$PathToLMPoliciesWindowsStore").GetValueNames() -like "AutoDownload") {
    Remove-ItemProperty -Path "$PathToLMPoliciesWindowsStore" -Name "AutoDownload" # [@] (2 = Disable, 4 = Enable)
}

Write-Output -Text "Power Plan Tweaks"

Write-Output -Types "+", $TweakType -Status "Setting Power Plan to High Performance..."
powercfg -SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

Write-Output -Types "+", $TweakType -Status "Creating the Ultimate Performance hidden Power Plan..."
powercfg -DuplicateScheme e9a42b02-d5df-448d-aa00-03f14749eb61

Unregister-DuplicatedPowerPlan

Write-Output -Types "+", $TweakType -Status "Setting Hibernate size to reduced..."
powercfg -Hibernate -type Reduced

Write-Output -Types "+", $TweakType -Status "Enabling Hibernate (Boots faster on Laptops/PCs with HDD and generate '$env:SystemDrive\hiberfil.sys' file)..."
powercfg -Hibernate on

Write-Output -Text "Network & Internet"
Write-Caption -Text "Proxy"
Write-Output -Types "-", $TweakType -Status "Fixing Edge slowdown by NOT Automatically Detecting Settings..."
# Code from: https://www.reddit.com/r/PowerShell/comments/5iarip/set_proxy_settings_to_automatically_detect/?utm_source=share&utm_medium=web2x&context=3
$Key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
$Data = (Get-ItemProperty -Path $Key -Name DefaultConnectionSettings).DefaultConnectionSettings
$Data[8] = 3
Set-ItemProperty -Path $Key -Name DefaultConnectionSettings -Value $Data

Write-Output -Text "System & Apps Timeout behaviors"
Write-Output -Types "+", $TweakType -Status "Reducing Time to services app timeout to 2s to ALL users..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type DWord -Value 2000 # Default: 20000 / 5000
Write-Output -Types "*", $TweakType -Status "Don't clear page file at shutdown (takes more time) to ALL users..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Type DWord -Value 0 # Default: 0

Write-Output -Types "+", $TweakType -Status "Reducing mouse hover time events to 10ms..."
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type DWord -Value 10 # Default: 400

# Details: https://windowsreport.com/how-to-speed-up-windows-11-animations/ and https://www.tenforums.com/tutorials/97842-change-hungapptimeout-value-windows-10-a.html
ForEach ($DesktopRegistryPath in @($PathToUsersControlPanelDesktop, $PathToCUControlPanelDesktop)) {
    <# $DesktopRegistryPath is the path related to all users and current user configuration #>
    If ($DesktopRegistryPath -eq $PathToUsersControlPanelDesktop) {
        Write-Caption -Text "TO ALL USERS"
    } ElseIf ($DesktopRegistryPath -eq $PathToCUControlPanelDesktop) {
        Write-Caption -Text "TO CURRENT USER"
    }

    Write-Output -Types "+", $TweakType -Status "Don't prompt user to end tasks on shutdown..."
    Set-ItemProperty -Path "$DesktopRegistryPath" -Name "AutoEndTasks" -Type DWord -Value 1 # Default: Removed or 0

    Write-Output -Types "*", $TweakType -Status "Returning 'Hung App Timeout' to default..."
    If ((Get-Item "$DesktopRegistryPath").Property -contains "HungAppTimeout") {
        Remove-ItemProperty -Path "$DesktopRegistryPath" -Name "HungAppTimeout"
    }

    Write-Output -Types "+", $TweakType -Status "Reducing mouse and keyboard hooks timeout to 1s..."
    Set-ItemProperty -Path "$DesktopRegistryPath" -Name "LowLevelHooksTimeout" -Type DWord -Value 1000 # Default: Removed or 5000
    Write-Output -Types "+", $TweakType -Status "Reducing animation speed delay to 1ms on Windows 11..."
    Set-ItemProperty -Path "$DesktopRegistryPath" -Name "MenuShowDelay" -Type DWord -Value 1 # Default: 400
    Write-Output -Types "+", $TweakType -Status "Reducing Time to kill apps timeout to 5s..."
    Set-ItemProperty -Path "$DesktopRegistryPath" -Name "WaitToKillAppTimeout" -Type DWord -Value 5000 # Default: 20000
}

Write-Output -Text "Gaming Responsiveness Tweaks"

If (!$Revert) {
    Disable-XboxGameBarDVRandMode
} Else {
    Enable-XboxGameBarDVRandMode
}

Write-Output -Types "*", $TweakType -Status "Enabling game mode..."
Set-ItemProperty -Path "$PathToCUGameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
Set-ItemProperty -Path "$PathToCUGameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1

# Details: https://www.reddit.com/r/killerinstinct/comments/4fcdhy/an_excellent_guide_to_optimizing_your_windows_10/
Write-Output -Types "+", $TweakType -Status "Reserving 100% of CPU to Multimedia/Gaming tasks..."
Set-ItemProperty -Path "$PathToLMMultimediaSystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0 # Default: 20
Write-Output -Types "+", $TweakType -Status "Dedicate more CPU/GPU usage to Gaming tasks..."
Set-ItemProperty -Path "$PathToLMMultimediaSystemProfileOnGameTasks" -Name "GPU Priority" -Type DWord -Value 8 # Default: 8
Set-ItemProperty -Path "$PathToLMMultimediaSystemProfileOnGameTasks" -Name "Priority" -Type DWord -Value 6 # Default: 2
Set-ItemProperty -Path "$PathToLMMultimediaSystemProfileOnGameTasks" -Name "Scheduling Category" -Type String -Value "High" # Default: "Medium"


# Initialize all Path variables used to Registry Tweaks
$PathToLMAutoLogger = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger"
$PathToLMDeliveryOptimizationCfg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
$PathToLMPoliciesAdvertisingInfo = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
$PathToLMPoliciesSQMClient = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
$PathToLMPoliciesToWifi = "HKLM:\Software\Microsoft\PolicyManager\default\WiFi"
$PathToLMPoliciesWindowsUpdate = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$PathToLMWindowsTroubleshoot = "HKLM:\SOFTWARE\Microsoft\WindowsMitigation"
$PathToCUContentDeliveryManager = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
$PathToCUDeviceAccessGlobal = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global"
$PathToCUExplorerAdvanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$PathToCUInputPersonalization = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
$PathToCUInputTIPC = "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
$PathToCUPoliciesCloudContent = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$PathToCUSiufRules = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"

Write-Output-Text "Privacy Tweaks"
If (!$Revert) {
    Disable-ClipboardHistory
    Disable-ClipboardSyncAcrossDevice
    Disable-Cortana
} Else {
    Enable-ClipboardHistory
    Enable-ClipboardSyncAcrossDevice
    Enable-Cortana
}

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) File Explorer Ads (OneDrive, New Features etc.)..."
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value $Zero

Write-Output -Text "Personalization"
Write-Caption -Text "Start & Lockscreen"
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Show me the windows welcome experience after updates..."
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Get fun facts and tips, etc. on lock screen'..."

$ContentDeliveryManagerDisableOnZero = @(
    "SubscribedContent-310093Enabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-314563Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContent-353698Enabled"
    "RotatingLockScreenOverlayEnabled"
    "RotatingLockScreenEnabled"
    # Prevents Apps from re-installing
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "RemediationRequired"
    "SilentInstalledAppsEnabled"
    "SoftLandingEnabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)

Write-Output -Types "?", $TweakType -Status "From Path: $PathToCUContentDeliveryManager" -Warning
ForEach ($Name in $ContentDeliveryManagerDisableOnZero) {
    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) $($Name): $Zero"
    Set-ItemProperty -Path "$PathToCUContentDeliveryManager" -Name "$Name" -Type DWord -Value $Zero
}

Write-Output -Types "-", $TweakType -Status "Disabling 'Suggested Content in the Settings App'..."
If (Test-Path "$PathToCUContentDeliveryManager\Subscriptions") {
    Remove-Item -Path "$PathToCUContentDeliveryManager\Subscriptions" -Recurse
}

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Show Suggestions' in Start..."
If (Test-Path "$PathToCUContentDeliveryManager\SuggestedApps") {
    Remove-Item -Path "$PathToCUContentDeliveryManager\SuggestedApps" -Recurse
}

Write-Output -Text "Privacy -> Windows Permissions"
Write-Caption -Text "General"
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Let apps use my advertising ID..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value $Zero
If (!(Test-Path "$PathToLMPoliciesAdvertisingInfo")) {
    New-Item -Path "$PathToLMPoliciesAdvertisingInfo" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMPoliciesAdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value $One

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Let websites provide locally relevant content by accessing my language list'..."
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value $One

Write-Caption -Text "Speech"
If (!$Revert) {
    Disable-OnlineSpeechRecognition
} Else {
    Enable-OnlineSpeechRecognition
}

Write-Caption -Text "Inking & Typing Personalization"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value $Zero
Set-ItemProperty -Path "$PathToCUInputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value $Zero
Set-ItemProperty -Path "$PathToCUInputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value $One
Set-ItemProperty -Path "$PathToCUInputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value $One

Write-Caption -Text "Diagnostics & Feedback"
If (!$Revert) {
    Disable-Telemetry
} Else {
    Enable-Telemetry
}

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) send inking and typing data to Microsoft..."
If (!(Test-Path "$PathToCUInputTIPC")) {
    New-Item -Path "$PathToCUInputTIPC" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToCUInputTIPC" -Name "Enabled" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Improve Inking & Typing Recognition..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) View diagnostic data..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" -Name "EnableEventTranscript" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) feedback frequency..."
If (!(Test-Path "$PathToCUSiufRules")) {
    New-Item -Path "$PathToCUSiufRules" -Force | Out-Null
}
If ((Test-Path "$PathToCUSiufRules\PeriodInNanoSeconds")) {
    Remove-ItemProperty -Path "$PathToCUSiufRules" -Name "PeriodInNanoSeconds"
}
Set-ItemProperty -Path "$PathToCUSiufRules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value $Zero

Write-Caption -Text "Activity History"
If ($Revert) {
    Enable-ActivityHistory
} Else {
    Disable-ActivityHistory
}

Write-Output -Text "Privacy -> Apps Permissions"
Write-Caption -Text "Location"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value $Zero
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "EnableStatus" -Type DWord -Value $Zero

Write-Caption -Text "Notifications"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Value "Deny"

Write-Caption -Text "App Diagnostics"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny"

Write-Caption -Text "Account Info Access"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny"

Write-Caption -Text "Other Devices"
Write-Output -Types "-", $TweakType -Status "Denying device access..."
If (!(Test-Path "$PathToCUDeviceAccessGlobal\LooselyCoupled")) {
    New-Item -Path "$PathToCUDeviceAccessGlobal\LooselyCoupled" -Force | Out-Null
}
# Disable sharing information with unpaired devices
Set-ItemProperty -Path "$PathToCUDeviceAccessGlobal\LooselyCoupled" -Name "Value" -Value "Deny"
ForEach ($key in (Get-ChildItem "$PathToCUDeviceAccessGlobal")) {
    If ($key.PSChildName -EQ "LooselyCoupled") {
        Continue
    }
    Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Setting $($key.PSChildName) value to 'Deny' ..."
    Set-ItemProperty -Path ("$PathToCUDeviceAccessGlobal\" + $key.PSChildName) -Name "Value" -Value "Deny"
}

Write-Caption -Text "Background Apps"
Enable-BackgroundAppsToogle

Write-Output -Text "Update & Security"
Write-Caption -Text "Windows Update"
Write-Output -Types "-", $TweakType -Status "Disabling Automatic Download and Installation of Windows Updates..."
If (!(Test-Path "$PathToLMPoliciesWindowsUpdate")) {
    New-Item -Path "$PathToLMPoliciesWindowsUpdate" -Force | Out-Null
}
# [@] (2 = Notify before download, 3 = Automatically download and notify of installation)
# [@] (4 = Automatically download and schedule installation, 5 = Automatic Updates is required and users can configure it)
Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "AUOptions" -Type DWord -Value 2

Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Automatic Updates..."
# [@] (0 = Enable Automatic Updates, 1 = Disable Automatic Updates)
Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "NoAutoUpdate" -Type DWord -Value $Zero

Write-Output -Types "+", $TweakType -Status "Setting Scheduled Day to Every day..."
# [@] (0 = Every day, 1~7 = The days of the week from Sunday (1) to Saturday (7) (Only valid if AUOptions = 4))
Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "ScheduledInstallDay" -Type DWord -Value 0

Write-Output -Types "-", $TweakType -Status "Setting Scheduled time to 03h00m..."
# [@] (0-23 = The time of day in 24-hour format)
Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "ScheduledInstallTime" -Type DWord -Value 3

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Automatic Reboot after update..."
# [@] (0 = Enable Automatic Reboot after update, 1 = Disable Automatic Reboot after update)
Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value $One

Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Change Windows Updates to 'Notify to schedule restart'..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value $One

Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Restricting Windows Update P2P downloads for Local Network only..."
If (!(Test-Path "$PathToLMDeliveryOptimizationCfg")) {
    New-Item -Path "$PathToLMDeliveryOptimizationCfg" -Force | Out-Null
}
# [@] (0 = Off, 1 = Local Network only, 2 = Local Network private peering only)
# [@] (3 = Local Network and Internet,  99 = Simply Download mode, 100 = Bypass mode)
Set-ItemProperty -Path "$PathToLMDeliveryOptimizationCfg" -Name "DODownloadMode" -Type DWord -Value $One

Write-Caption -Text "Troubleshooting"
Write-Output -Types "+", $TweakType -Status "Enabling Automatic Recommended Troubleshooting, then notify me..."
If (!(Test-Path "$PathToLMWindowsTroubleshoot")) {
    New-Item -Path "$PathToLMWindowsTroubleshoot" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMWindowsTroubleshoot" -Name "UserPreference" -Type DWord -Value 3

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Windows Spotlight Features..."
If (!(Test-Path "$PathToCUPoliciesCloudContent")) {
    New-Item -Path "$PathToCUPoliciesCloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "ConfigureWindowsSpotlight" -Type DWord -Value 2
Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "IncludeEnterpriseSpotlight" -Type DWord -Value $Zero
Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value $One
Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Type DWord -Value $One
Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightOnSettings" -Type DWord -Value $One
Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Type DWord -Value $One

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Tailored Experiences..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value $Zero
Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value $One

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Third Party Suggestions..."
Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableThirdPartySuggestions" -Type DWord -Value $One
Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value $One

# Reference (the path may differ, but the description matches): https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.DeviceSoftwareSetup::DriverSearchPlaces_SearchOrderConfiguration
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Windows Update from downloading broken drivers..."
# [@] (0 = Do not search Windows Update, 1 = Always search Windows Update, 2 = Search Windows Update only if needed)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value $Zero
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) enhanced icons..."
# [@] (0 = Enhanced icons enabled, 1 = Enhanced icons disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value $One

If (!(Test-Path "$PathToLMPoliciesSQMClient")) {
    New-Item -Path "$PathToLMPoliciesSQMClient" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMPoliciesSQMClient" -Name "CEIPEnable" -Type DWord -Value $Zero
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value $Zero
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type DWord -Value $One

# Details: https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004#windows-system-startup-event-traces-autologgers
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) some startup event traces (AutoLoggers)..."
If (!(Test-Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener")) {
    New-Item -Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type DWord -Value $Zero
Set-ItemProperty -Path "$PathToLMAutoLogger\SQMLogger" -Name "Start" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'WiFi Sense: HotSpot Sharing'..."
If (!(Test-Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting")) {
    New-Item -Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting" -Name "value" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'WiFi Sense: Shared HotSpot Auto-Connect'..."
If (!(Test-Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots")) {
    New-Item -Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type DWord -Value $Zero

Write-Caption "Deleting useless registry keys..."
$KeysToDelete = @(
# Remove Background Tasks
"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
# Windows File
"HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
# Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
# Scheduled Tasks to delete
"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
# Windows Protocol Keys
"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
# Windows Share Target
"HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
)

ForEach ($Key in $KeysToDelete) {
If ((Test-Path $Key)) {
    Write-Output -Types "-", $TweakType -Status "Removing Key: [$Key]"
    Remove-Item $Key -Recurse
} Else {
    Write-Output -Types "?", $TweakType -Status "The registry key $Key does not exist" -Warning
}

 # Initialize all Path variables used to Registry Tweaks
 $PathToLMPoliciesEdge = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge"
 $PathToLMPoliciesMRT = "HKLM:\SOFTWARE\Policies\Microsoft\MRT"
 $PathToCUExplorer = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
 $PathToCUExplorerAdvanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

 Write-Output-Text "Security Tweaks"

 Write-Output -Text "Windows Firewall"
 Write-Output -Types "+", $TweakType -Status "Enabling default firewall profiles..."
 Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

 Write-Output -Text "Windows Defender"
 Write-Output -Types "?", $TweakType -Status "If you already use another antivirus, nothing will happen." -Warning
 Write-Output -Types "+", $TweakType -Status "Ensuring your Windows Defender is ENABLED..."
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWORD -Value 0 -Force
 Set-MpPreference -DisableRealtimeMonitoring $false -Force

 Write-Output -Types "+", $TweakType -Status "Enabling Microsoft Defender Exploit Guard network protection..."
 Set-MpPreference -EnableNetworkProtection Enabled -Force

 Write-Output -Types "+", $TweakType -Status "Enabling detection for potentially unwanted applications and block them..."
 Set-MpPreference -PUAProtection Enabled -Force

 Write-Output -Text "SmartScreen"
 Write-Output -Types "+", $TweakType -Status "Enabling 'SmartScreen' for Microsoft Edge..."
 If (!(Test-Path "$PathToLMPoliciesEdge\PhishingFilter")) {
     New-Item -Path "$PathToLMPoliciesEdge\PhishingFilter" -Force | Out-Null
 }
 Set-ItemProperty -Path "$PathToLMPoliciesEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1

 Write-Output -Types "+", $TweakType -Status "Enabling 'SmartScreen' for Store Apps..."
 Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 1

 Write-Output -Text "Old SMB Protocol"
 # Details: https://techcommunity.microsoft.com/t5/storage-at-microsoft/stop-using-smb1/ba-p/425858
 Write-Output -Types "+", $TweakType -Status "Disabling SMB 1.0 protocol..."
 Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

 Write-Output -Text "Old .NET cryptography"
 # Enable strong cryptography for .NET Framework (version 4 and above) - https://stackoverflow.com/a/47682111
 Write-Output -Types "+", $TweakType -Status "Enabling .NET strong cryptography..."
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1

 Write-Output -Text "Autoplay and Autorun (Removable Devices)"
 Write-Output -Types "-", $TweakType -Status "Disabling Autoplay..."
 Set-ItemProperty -Path "$PathToCUExplorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

 Write-Output -Types "-", $TweakType -Status "Disabling Autorun for all Drives..."
 If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
     New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
 }
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

 Write-Output -Text "Microsoft Store"
 Disable-SearchAppForUnknownExt

 Write-Output -Text "Windows Explorer"
 Write-Output -Types "+", $TweakType -Status "Enabling Show file extensions in Explorer..."
 Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "HideFileExt" -Type DWord -Value 0

 Write-Output -Text "User Account Control (UAC)"
 # Details: https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings
 Write-Output -Types "+", $TweakType -Status "Raising UAC level..."
 If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
     New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
 }
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

 Write-Output -Text "Windows Update"
 # Details: https://forums.malwarebytes.com/topic/246740-new-potentially-unwanted-modification-disablemrt/
 Write-Output -Types "+", $TweakType -Status "Enabling offer Malicious Software Removal Tool via Windows Update..."
 If (!(Test-Path "$PathToLMPoliciesMRT")) {
     New-Item -Path "$PathToLMPoliciesMRT" -Force | Out-Null
 }
 Set-ItemProperty -Path "$PathToLMPoliciesMRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 0

 Write-Output -Types "?", $TweakType -Status "For more tweaks, edit the '$PSCommandPath' file, then uncomment '#SomethingHere' code lines" -Warning
 # Consumes more RAM - Make Windows Defender run in Sandbox Mode (MsMpEngCP.exe and MsMpEng.exe will run on background)
 # Details: https://www.microsoft.com/security/blog/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/
 #Write-Output -Types "+", $TweakType -Status "Enabling Windows Defender Sandbox mode..."
 #setx /M MP_FORCE_USE_SANDBOX 1  # Restart the PC to apply the changes, 0 to Revert

 # Disable Windows Script Host. CAREFUL, this may break stuff, including software uninstall.
 #Write-Output -Types "+", $TweakType -Status "Disabling Windows Script Host (execution of *.vbs scripts and alike)..."
 #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0

$IsSystemDriveSSD = $(Get-OSDriveType) -eq "SSD"
$EnableServicesOnSSD = @("SysMain", "WSearch")

# Services which will be totally disabled
$ServicesToDisabled = @(
    "DiagTrack"                                 # DEFAULT: Automatic | Connected User Experiences and Telemetry
    "diagnosticshub.standardcollector.service"  # DEFAULT: Manual    | Microsoft (R) Diagnostics Hub Standard Collector Service
    "dmwappushservice"                          # DEFAULT: Manual    | Device Management Wireless Application Protocol (WAP)
    "Fax"                                       # DEFAULT: Manual    | Fax Service
    "fhsvc"                                     # DEFAULT: Manual    | File History Service
    "GraphicsPerfSvc"                           # DEFAULT: Manual    | Graphics performance monitor service
    "HomeGroupListener"                         # NOT FOUND (Win 10+)| HomeGroup Listener
    "HomeGroupProvider"                         # NOT FOUND (Win 10+)| HomeGroup Provider
    "lfsvc"                                     # DEFAULT: Manual    | Geolocation Service
    "MapsBroker"                                # DEFAULT: Automatic | Downloaded Maps Manager
    "PcaSvc"                                    # DEFAULT: Automatic | Program Compatibility Assistant (PCA)
    "RemoteAccess"                              # DEFAULT: Disabled  | Routing and Remote Access
    "RemoteRegistry"                            # DEFAULT: Disabled  | Remote Registry
    "RetailDemo"                                # DEFAULT: Manual    | The Retail Demo Service controls device activity while the device is in retail demo mode.
    "SysMain"                                   # DEFAULT: Automatic | SysMain / Superfetch (100% Disk usage on HDDs)
    "TrkWks"                                    # DEFAULT: Automatic | Distributed Link Tracking Client
    "WSearch"                                   # DEFAULT: Automatic | Windows Search (100% Disk usage on HDDs)
    # - Services which cannot be disabled (and shouldn't)
    #"wscsvc"                                   # DEFAULT: Automatic | Windows Security Center Service
    #"WdNisSvc"                                 # DEFAULT: Manual    | Windows Defender Network Inspection Service
)

# Making the services to run only when needed as 'Manual' | Remove the # to set to Manual
$ServicesToManual = @(
    "BITS"                           # DEFAULT: Manual    | Background Intelligent Transfer Service
    "edgeupdate"                     # DEFAULT: Automatic | Microsoft Edge Update Service
    "edgeupdatem"                    # DEFAULT: Manual    | Microsoft Edge Update Service²
    "FontCache"                      # DEFAULT: Automatic | Windows Font Cache
    "PhoneSvc"                       # DEFAULT: Manual    | Phone Service (Manages the telephony state on the device)
    "SCardSvr"                       # DEFAULT: Manual    | Smart Card Service
    "stisvc"                         # DEFAULT: Automatic | Windows Image Acquisition (WIA) Service
    "WbioSrvc"                       # DEFAULT: Manual    | Windows Biometric Service (required for Fingerprint reader / Facial detection)
    "wisvc"                          # DEFAULT: Manual    | Windows Insider Program Service
    "WMPNetworkSvc"                  # DEFAULT: Manual    | Windows Media Player Network Sharing Service
    "WpnService"                     # DEFAULT: Automatic | Windows Push Notification Services (WNS)
    <# Bluetooth services #>
    "BTAGService"                    # DEFAULT: Manual    | Bluetooth Audio Gateway Service
    "BthAvctpSvc"                    # DEFAULT: Manual    | AVCTP Service
    "bthserv"                        # DEFAULT: Manual    | Bluetooth Support Service
    "RtkBtManServ"                   # DEFAULT: Automatic | Realtek Bluetooth Device Manager Service
    <# Diagnostic Services #>
    "DPS"                            # DEFAULT: Automatic | Diagnostic Policy Service
    "WdiServiceHost"                 # DEFAULT: Manual    | Diagnostic Service Host
    "WdiSystemHost"                  # DEFAULT: Manual    | Diagnostic System Host
    <# Network Services #>
    "iphlpsvc"                       # DEFAULT: Automatic | IP Helper Service (IPv6 (6to4, ISATAP, Port Proxy and Teredo) and IP-HTTPS)
    "lmhosts"                        # DEFAULT: Manual    | TCP/IP NetBIOS Helper
    "ndu"                            # DEFAULT: Automatic | Windows Network Data Usage Monitoring Driver (Shows network usage per-process on Task Manager)
    #"NetTcpPortSharing"             # DEFAULT: Disabled  | Net.Tcp Port Sharing Service
    "SharedAccess"                   # DEFAULT: Manual    | Internet Connection Sharing (ICS)
    <# Telemetry Services #>
    "Wecsvc"                         # DEFAULT: Manual    | Windows Event Collector Service
    "WerSvc"                         # DEFAULT: Manual    | Windows Error Reporting Service
    <# Xbox services #>
    "XblAuthManager"                 # DEFAULT: Manual    | Xbox Live Auth Manager
    "XblGameSave"                    # DEFAULT: Manual    | Xbox Live Game Save
    "XboxGipSvc"                     # DEFAULT: Manual    | Xbox Accessory Management Service
    "XboxNetApiSvc"                  # DEFAULT: Manual    | Xbox Live Networking Service
    <# NVIDIA services #>
    "NVDisplay.ContainerLocalSystem" # DEFAULT: Automatic | NVIDIA Display Container LS (NVIDIA Control Panel)
    "NvContainerLocalSystem"         # DEFAULT: Automatic | NVIDIA LocalSystem Container (GeForce Experience / NVIDIA Telemetry)
    <# Printer services #>
    #"PrintNotify"                   # DEFAULT: Manual    | WARNING! REMOVING WILL TURN PRINTING LESS MANAGEABLE | Printer Extensions and Notifications
    #"Spooler"                       # DEFAULT: Automatic | WARNING! REMOVING WILL DISABLE PRINTING              | Print Spooler
    <# Wi-Fi services #>
    #"WlanSvc"                       # DEFAULT: Manual (No Wi-Fi devices) / Automatic (Wi-Fi devices) | WARNING! REMOVING WILL DISABLE WI-FI | WLAN AutoConfig
    <# 3rd Party Services #>
    "gupdate"                        # DEFAULT: Automatic | Google Update Service
    "gupdatem"                       # DEFAULT: Manual    | Google Update Service²
)

Write-Output-Text "Services tweaks"
Write-Output -Text "Disabling services from Windows"

If ($Revert) {
    Write-Output -Types "*", "Service" -Status "Reverting the tweaks is set to '$Revert'." -Warning
    $CustomMessage = { "Resetting $Service ($((Get-Service $Service).DisplayName)) as 'Manual' on Startup..." }
    Set-ServiceStartup -Manual -Services $ServicesToDisabled -Filter $EnableServicesOnSSD -CustomMessage $CustomMessage
} Else {
    Set-ServiceStartup -Disabled -Services $ServicesToDisabled -Filter $EnableServicesOnSSD
}

Write-Output -Text "Enabling services from Windows"

If ($IsSystemDriveSSD -or $Revert) {
    $CustomMessage = { "The $Service ($((Get-Service $Service).DisplayName)) service works better in 'Automatic' mode on SSDs..." }
    Set-ServiceStartup -Automatic -Services $EnableServicesOnSSD -CustomMessage $CustomMessage
}

Set-ServiceStartup -Manual -Services $ServicesToManual
}

powershell.exe Get-Service DiagTrack, Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled


# Adapted from: https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations#task-scheduler
$DisableScheduledTasks = @(
    "\Microsoft\Office\OfficeTelemetryAgentLogOn"
    "\Microsoft\Office\OfficeTelemetryAgentFallBack"
    "\Microsoft\Office\Office 15 Subscription Heartbeat"
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "\Microsoft\Windows\Application Experience\StartupAppTask"
    "\Microsoft\Windows\Autochk\Proxy"
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"         # Recommended state for VDI use
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"       # Recommended state for VDI use
    "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"              # Recommended state for VDI use
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    "\Microsoft\Windows\Location\Notifications"                                       # Recommended state for VDI use
    "\Microsoft\Windows\Location\WindowsActionDialog"                                 # Recommended state for VDI use
    "\Microsoft\Windows\Maps\MapsToastTask"                                           # Recommended state for VDI use
    "\Microsoft\Windows\Maps\MapsUpdateTask"                                          # Recommended state for VDI use
    "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"                # Recommended state for VDI use
    "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"                   # Recommended state for VDI use
    "\Microsoft\Windows\Retail Demo\CleanupOfflineContent"                            # Recommended state for VDI use
    "\Microsoft\Windows\Shell\FamilySafetyMonitor"                                    # Recommended state for VDI use
    "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"                                # Recommended state for VDI use
    "\Microsoft\Windows\Shell\FamilySafetyUpload"
    "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"                          # Recommended state for VDI use
)

$EnableScheduledTasks = @(
"\Microsoft\Windows\Defrag\ScheduledDefrag"                 # Defragments all internal storages connected to your computer
"\Microsoft\Windows\Maintenance\WinSAT"                     # WinSAT detects incorrect system configurations, that causes performance loss, then sends it via telemetry | Reference (PT-BR): https://youtu.be/wN1I0IPgp6U?t=16
"\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE"        # Verify the Recovery Environment integrity, it's the Diagnostic tools and Troubleshooting when your PC isn't healthy on BOOT, need this ON.
"\Microsoft\Windows\Windows Error Reporting\QueueReporting" # Windows Error Reporting event, needed to improve compatibility with your hardware
)

Write-Output-Text "Task Scheduler tweaks"
Write-Output -Text "Disabling Scheduled Tasks from Windows"

If ($Revert) {
Write-Output -Types "*", "TaskScheduler" -Status "Reverting the tweaks is set to '$Revert'." -Warning
$CustomMessage = { "Resetting the $ScheduledTask task as 'Ready'..." }
Set-ScheduledTaskState -Ready -ScheduledTask $DisableScheduledTasks -CustomMessage $CustomMessage
} Else {
Set-ScheduledTaskState -Disabled -ScheduledTask $DisableScheduledTasks
}

Write-Output -Text "Enabling Scheduled Tasks from Windows"
Set-ScheduledTaskState -Ready -ScheduledTask $EnableScheduledTasks


$DisableFeatures = @(
    "FaxServicesClientPackage"             # Windows Fax and Scan
    "IIS-*"                                # Internet Information Services
    "Internet-Explorer-Optional-*"         # Internet Explorer
    "LegacyComponents"                     # Legacy Components
    "MediaPlayback"                        # Media Features (Windows Media Player)
    "MicrosoftWindowsPowerShellV2"         # PowerShell 2.0
    "MicrosoftWindowsPowershellV2Root"     # PowerShell 2.0
    "Printing-PrintToPDFServices-Features" # Microsoft Print to PDF
    "Printing-XPSServices-Features"        # Microsoft XPS Document Writer
    "WorkFolders-Client"                   # Work Folders Client
)

$EnableFeatures = @(
    "NetFx3"                            # NET Framework 3.5
    "NetFx4-AdvSrvs"                    # NET Framework 4
    "NetFx4Extended-ASPNET45"           # NET Framework 4.x + ASPNET 4.x
)

Write-Output-Text "Optional Features Tweaks"
Write-Output -Text "Uninstall Optional Features from Windows"

If ($Revert) {
    Write-Output -Types "*", "OptionalFeature" -Status "Reverting the tweaks is set to '$Revert'." -Warning
    $CustomMessage = { "Re-Installing the $OptionalFeature optional feature..." }
    Set-OptionalFeatureState -Enabled -OptionalFeatures $DisableFeatures -CustomMessage $CustomMessage
} Else {
    Set-OptionalFeatureState -Disabled -OptionalFeatures $DisableFeatures
}

Write-Output -Text "Install Optional Features from Windows"
Set-OptionalFeatureState -Enabled -OptionalFeatures $EnableFeatures

# Initialize all Path variables used to Registry Tweaks
$PathToCUAccessibility = "HKCU:\Control Panel\Accessibility"
$PathToCUPoliciesEdge = "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
$PathToCUExplorer = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
$PathToCUExplorerAdvanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$PathToCUPoliciesExplorer = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$PathToCUPoliciesLiveTiles = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$PathToCUNewsAndInterest = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds"
$PathToCUWindowsSearch = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
$PathToLMPoliciesExplorer = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$PathToLMPoliciesNewsAndInterest = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
$PathToLMPoliciesWindowsSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"

Write-Output-Text "My Personal Tweaks"
If (!$Revert) {
    $Scripts = @("enable-photo-viewer.reg")
    Enable-DarkTheme
} Else {
    $Scripts = @("disable-photo-viewer.reg")
    Disable-DarkTheme
}
Open-RegFilesCollection -RelativeLocation "src\utils" -Scripts $Scripts -NoDialog

# Show Task Manager details - Applicable to 1607 and later - Although this functionality exist even in earlier versions, the Task Manager's behavior is different there and is not compatible with this tweak
If ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild).CurrentBuild -lt 22557) {
    Write-Output -Types "+", $TweakType -Status "Showing task manager details..."
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    Do {
        Start-Sleep -Milliseconds 100
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences)
    Stop-Process $taskmgr
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
} Else {
    Write-Output -Types "?", $TweakType -Status "Task Manager patch not run in builds 22557+ due to bug" -Warning
}

Write-Output -Text "Windows Explorer Tweaks"
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Quick Access from Windows Explorer..."
Set-ItemProperty -Path "$PathToCUExplorer" -Name "ShowFrequent" -Type DWord -Value $Zero
Set-ItemProperty -Path "$PathToCUExplorer" -Name "ShowRecent" -Type DWord -Value $Zero
Set-ItemProperty -Path "$PathToCUExplorer" -Name "HubMode" -Type DWord -Value $One

Write-Output -Types "-", $TweakType -Status "Removing 3D Objects from This PC..."
If (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}") {
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse
}
If (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}") {
    Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse
}

Write-Output -Types "-", $TweakType -Status "Removing 'Edit with Paint 3D' from the Context Menu..."
$Paint3DFileTypes = @(".3mf", ".bmp", ".fbx", ".gif", ".jfif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
ForEach ($FileType in $Paint3DFileTypes) {
    If (Test-Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$FileType\Shell\3D Edit") {
        Write-Output -Types "-", $TweakType -Status "Removing Paint 3D from file type: $FileType"
        Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$FileType\Shell\3D Edit" -Recurse
    }
}

Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Show Drives without Media..."
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "HideDrivesWithNoMedia" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) MRU lists (jump lists) of XAML apps in Start Menu..."
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "Start_TrackDocs" -Type DWord -Value $Zero
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "Start_TrackProgs" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Aero-Shake Minimize feature..."
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "DisallowShaking" -Type DWord -Value $One

Write-Output -Types "+", $TweakType -Status "Setting Windows Explorer to start on This PC instead of Quick Access..."
# [@] (1 = This PC, 2 = Quick access) # DO NOT REVERT, BREAKS EXPLORER.EXE
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "LaunchTo" -Type DWord -Value 1

Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Show hidden files in Explorer..."
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "Hidden" -Type DWord -Value $One

Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Showing file transfer details..."
If (!(Test-Path "$PathToCUExplorer\OperationStatusManager")) {
    New-Item -Path "$PathToCUExplorer\OperationStatusManager" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToCUExplorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value $One

Write-Output -Types "-", $TweakType -Status "Disabling '- Shortcut' name after creating a shortcut..."
Set-ItemProperty -Path "$PathToCUExplorer" -Name "link" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00))

Write-Output -Text "Task Bar Tweaks"
Write-Caption -Text "Task Bar - Windows 10 Compatible"
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) the 'Search Box' from taskbar..."
# [@] (0 = Hide completely, 1 = Show icon only, 2 = Show long Search Box)
Set-ItemProperty -Path "$PathToCUWindowsSearch" -Name "SearchboxTaskbarMode" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Windows search highlights from taskbar..."
If (!(Test-Path "$PathToLMPoliciesWindowsSearch")) {
    New-Item -Path "$PathToLMPoliciesWindowsSearch" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMPoliciesWindowsSearch" -Name "EnableDynamicContentInWSB" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) the 'Task View' icon from taskbar..."
# [@] (0 = Hide Task view, 1 = Show Task view)
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "ShowTaskViewButton" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Open on Hover from 'News and Interest' from taskbar..."
If (!(Test-Path "$PathToCUNewsAndInterest")) {
    New-Item -Path "$PathToCUNewsAndInterest" -Force | Out-Null
}
# [@] (0 = Disable, 1 = Enable)
Set-ItemProperty -Path "$PathToCUNewsAndInterest" -Name "ShellFeedsTaskbarOpenOnHover" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'News and Interest' from taskbar..."
If (!(Test-Path "$PathToLMPoliciesNewsAndInterest")) {
    New-Item -Path "$PathToLMPoliciesNewsAndInterest" -Force | Out-Null
}
# [@] (0 = Disable, 1 = Enable)
Set-ItemProperty -Path "$PathToLMPoliciesNewsAndInterest" -Name "EnableFeeds" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'People' icon from taskbar..."
If (!(Test-Path "$PathToCUExplorerAdvanced\People")) {
    New-Item -Path "$PathToCUExplorerAdvanced\People" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToCUExplorerAdvanced\People" -Name "PeopleBand" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Live Tiles..."
If (!(Test-Path "$PathToCUPoliciesLiveTiles")) {
    New-Item -Path "$PathToCUPoliciesLiveTiles" -Force | Out-Null
}
Set-ItemProperty -Path $PathToCUPoliciesLiveTiles -Name "NoTileApplicationNotification" -Type DWord -Value $One

Write-Output -Types "*", $TweakType -Status "Enabling Auto tray icons..."
Set-ItemProperty -Path "$PathToCUExplorer" -Name "EnableAutoTray" -Type DWord -Value 1

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Meet now' icon on taskbar..."
If (!(Test-Path "$PathToLMPoliciesExplorer")) {
    New-Item -Path "$PathToLMPoliciesExplorer" -Force | Out-Null
}
# [@] (0 = Show Meet Now, 1 = Hide Meet Now)
Set-ItemProperty -Path "$PathToLMPoliciesExplorer" -Name "HideSCAMeetNow" -Type DWord -Value $One

Write-Caption -Text "Task Bar - Windows 11 Compatible"
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Widgets' icon from taskbar..."
# [@] (0 = Hide Widgets, 1 = Show Widgets)
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "TaskbarDa" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Chat' icon from taskbar..."
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "TaskbarMn" -Type DWord -Value $Zero

Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) creation of Thumbs.db thumbnail cache files..."
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "DisableThumbnailCache" -Type DWord -Value $One
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value $One

Write-Caption -Text "Colors"
Write-Output -Types "*", $TweakType -Status "Re-Enabling taskbar transparency..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 1

Write-Output -Text "System"
Write-Caption -Text "Multitasking"
Write-Output -Types "-", $TweakType -Status "Disabling Edge multi tabs showing on Alt + Tab..."
Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "MultiTaskingAltTabFilter" -Type DWord -Value 3

Write-Output -Text "Devices"
Write-Caption -Text "Bluetooth & other devices"
Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) driver download over metered connections..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceSetup" -Name "CostedNetworkPolicy" -Type DWord -Value $One

Write-Output -Text "Cortana Tweaks"
Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Bing Search in Start Menu..."
Set-ItemProperty -Path "$PathToCUWindowsSearch" -Name "BingSearchEnabled" -Type DWord -Value $Zero
Set-ItemProperty -Path "$PathToCUWindowsSearch" -Name "CortanaConsent" -Type DWord -Value $Zero

If (!(Test-Path "$PathToCUPoliciesExplorer")) {
    New-Item -Path "$PathToCUPoliciesExplorer" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToCUPoliciesExplorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value $One

Write-Output -Text "Ease of Access"
Write-Caption -Text "Keyboard"
Write-Output -Types "-", $TweakType -Status "Disabling Sticky Keys..."
Set-ItemProperty -Path "$PathToCUAccessibility\StickyKeys" -Name "Flags" -Value "506"
Set-ItemProperty -Path "$PathToCUAccessibility\Keyboard Response" -Name "Flags" -Value "122"
Set-ItemProperty -Path "$PathToCUAccessibility\ToggleKeys" -Name "Flags" -Value "58"

Write-Output -Text "Microsoft Edge Policies"
Write-Caption -Text "Privacy, search and services / Address bar and search"
Write-Output -Types "*", $TweakType -Status "Show me search and site suggestions using my typed characters..."
Remove-ItemProperty -Path "$PathToCUPoliciesEdge" -Name "SearchSuggestEnabled" -Force -ErrorAction SilentlyContinue

Write-Output -Types "*", $TweakType -Status "Show me history and favorite suggestions and other data using my typed characters..."
Remove-ItemProperty -Path "$PathToCUPoliciesEdge" -Name "LocalProvidersEnabled" -Force -ErrorAction SilentlyContinue

Write-Output -Types "*", $TweakType -Status "Re-Enabling Error reporting..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0

Write-Output -Types "+", $TweakType -Status "Bringing back F8 alternative Boot Modes..."
bcdedit /set `{current`} bootmenupolicy Legacy

Write-Output -Text "Power Plan Tweaks"
$TimeoutScreenBattery = 5
$TimeoutScreenPluggedIn = 10

$TimeoutStandByBattery = 15
$TimeoutStandByPluggedIn = 180

$TimeoutDiskBattery = 20
$TimeoutDiskPluggedIn = 30

$TimeoutHibernateBattery = 15
$TimeoutHibernatePluggedIn = 15

Write-Output -Types "+", $TweakType -Status "Setting the Monitor Timeout to AC: $TimeoutScreenPluggedIn and DC: $TimeoutScreenBattery..."
powercfg -Change Monitor-Timeout-AC $TimeoutScreenPluggedIn
powercfg -Change Monitor-Timeout-DC $TimeoutScreenBattery

Write-Output -Types "+", $TweakType -Status "Setting the Standby Timeout to AC: $TimeoutStandByPluggedIn and DC: $TimeoutStandByBattery..."
powercfg -Change Standby-Timeout-AC $TimeoutStandByPluggedIn
powercfg -Change Standby-Timeout-DC $TimeoutStandByBattery

Write-Output -Types "+", $TweakType -Status "Setting the Disk Timeout to AC: $TimeoutDiskPluggedIn and DC: $TimeoutDiskBattery..."
powercfg -Change Disk-Timeout-AC $TimeoutDiskPluggedIn
powercfg -Change Disk-Timeout-DC $TimeoutDiskBattery

Write-Output -Types "+", $TweakType -Status "Setting the Hibernate Timeout to AC: $TimeoutHibernatePluggedIn and DC: $TimeoutHibernateBattery..."
powercfg -Change Hibernate-Timeout-AC $TimeoutHibernatePluggedIn
powercfg -Change Hibernate-Timeout-DC $TimeoutHibernateBattery


$Packages = (Get-Item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications') | Get-ChildItem
# Filter the list if provided a filter
$PackageFilter = $args[0]

If ([string]::IsNullOrEmpty($PackageFilter)) {
    Write-Warning "No filter specified, attempting to re-register all provisioned apps."
} Else {
    $Packages = $Packages | Where-Object { $_.Name -like $PackageFilter }

    If ($null -eq $Packages) {
        Write-Warning "No provisioned apps match the specified filter."
        exit
    } Else {
        Write-Host "Registering the provisioned apps that match $PackageFilter..."
    }
}

ForEach ($Package in $Packages) {
    # Get package name & path
    $PackageName = $Package | Get-ItemProperty | Select-Object -ExpandProperty PSChildName
    $PackagePath = [System.Environment]::ExpandEnvironmentVariables(($Package | Get-ItemProperty | Select-Object -ExpandProperty Path))
    # Register the package
    Write-Host "Attempting to register package: $PackageName..."
    Add-AppxPackage -register $PackagePath -DisableDevelopmentMode
}

$PathToLMEdgeUpdate = "HKLM:\SOFTWARE\Microsoft\EdgeUpdate"

If ((Test-Path -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application") -or (Test-Path -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeWebView\Application")) {
    ForEach ($FullName in (Get-ChildItem -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Edge*\Application\*\Installer\setup.exe").FullName) {
        Write-Output -Types "@" -Status "Uninstalling MS Edge from $FullName..."
        Start-Process -FilePath $FullName -ArgumentList "--uninstall", "--msedgewebview", "--system-level", "--verbose-logging", "--force-uninstall" -Wait
    }
} Else {
    Write-Output -Types "?" -Status "Edge/EdgeWebView folder does not exist anymore..." -Warning
}

If (Test-Path -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeCore") {
    ForEach ($FullName in (Get-ChildItem -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeCore\*\Installer\setup.exe").FullName) {
        Write-Output -Types "@" -Status "Uninstalling MS Edge from $FullName..."
        Start-Process -FilePath $FullName -ArgumentList "--uninstall", "--system-level", "--verbose-logging", "--force-uninstall" -Wait
    }
} Else {
    Write-Output -Types "?" -Status "EdgeCore folder does not exist anymore..." -Warning
}

Write-Output -Types "@" -Status "Preventing Edge from reinstalling..."
If (!(Test-Path "$PathToLMEdgeUpdate")) {
    New-Item -Path "$PathToLMEdgeUpdate" -Force | Out-Null
}
Set-ItemProperty -Path "$PathToLMEdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Type DWord -Value 1

Write-Output -Types "@" -Status "Deleting Edge appdata\local folders from current user..."
Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge*_*" -Recurse -Force | Out-Host

Write-Output -Types "@" -Status "Deleting Edge from Program Files (x86)..."
Remove-Item -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Edge*" -Recurse -Force | Out-Host
Remove-Item -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Temp" -Recurse -Force | Out-Host

# Description: This script will remove and disable OneDrive integration.
Write-Host "Kill OneDrive process..."
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Host "Remove OneDrive."
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Host "Removing OneDrive leftovers..."
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Host "Disable OneDrive via Group Policies."
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Host "Remove Onedrive from explorer sidebar."
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Host "Removing run hook for new users..."
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Host "Removing startmenu entry..."
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Host "Removing scheduled task..."
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Host "Restarting explorer..."
Start-Process "explorer.exe"

Write-Host "Waiting for explorer to complete loading..."
Start-Sleep 5

$ColorHistory = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\History\Colors"
$HexColor = "{0:X6}" -f (Get-Random -Maximum 0xFFFFFF)
$HexColorBGR = "$($HexColor[4..5] + $HexColor[2..3] + $HexColor[0..1])".Split(" ") -join ""

$PathToCUDesktop = "HKCU:\Control Panel\Desktop"
$PathToCUExplorerAccent = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent"
$PathToCUThemesColorHistory = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\History\Colors"
$PathToCUThemesHistory = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\History"
$PathToCUThemesPersonalize = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
$PathToCUWindowsDWM = "HKCU:\SOFTWARE\Microsoft\Windows\DWM"

$Max = 32
$RandomBytes = [System.Collections.ArrayList]@()
ForEach ($i in 1..$Max) {
    $Byte = "0x{0:X2}" -f (Get-Random -Maximum 0xFF)

    If ($i % 4 -eq 0) {
        $Byte = "0xFF"
    }

    If ($i -eq $Max) {
        $Byte = "0x00"
    }

    If ($i -in (1, 5, 9, 13, 17, 21, 25)) {
        $Byte = "0x$($HexColor[0..1])".Split(" ") -join ""
    }

    If ($i -in (2, 6, 10, 14, 18, 22, 26)) {
        $Byte = "0x$($HexColor[2..3])".Split(" ") -join ""
    }

    If ($i -in (3, 7, 11, 15, 19, 23, 27)) {
        $Byte = "0x$($HexColor[4..5])".Split(" ") -join ""
    }

    $RandomBytes.Add($Byte)
}

Write-Output -Types "@" -Status "HexColor: #$HexColor, BGR: #$HexColorBGR"
Write-Verbose "$RandomBytes"

# Taskbar and Settings color
Set-ItemProperty -Path "$PathToCUExplorerAccent" -Name "AccentPalette" -Type Binary -Value ([byte[]]($RandomBytes[0], $RandomBytes[1], $RandomBytes[2], $RandomBytes[3], $RandomBytes[4], $RandomBytes[5], $RandomBytes[6], $RandomBytes[7], $RandomBytes[8], $RandomBytes[9], $RandomBytes[10], $RandomBytes[11], $RandomBytes[12], $RandomBytes[13], $RandomBytes[14], $RandomBytes[15], $RandomBytes[16], $RandomBytes[17], $RandomBytes[18], $RandomBytes[19], $RandomBytes[20], $RandomBytes[21], $RandomBytes[22], $RandomBytes[23], $RandomBytes[24], $RandomBytes[25], $RandomBytes[26], $RandomBytes[27], $RandomBytes[28], $RandomBytes[29], $RandomBytes[30], $RandomBytes[31]))

# Window Top Color
Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "AccentColor" -Type DWord -Value 0xff$HexColor
Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "ColorizationAfterglow" -Type DWord -Value 0xc4$HexColor
Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "ColorizationColor" -Type DWord -Value 0xc4$HexColor

# Window Border Color
Set-ItemProperty -Path "$PathToCUExplorerAccent" -Name "AccentColorMenu" -Type DWord -Value 0xff$HexColorBGR
Set-ItemProperty -Path "$PathToCUExplorerAccent" -Name "StartColorMenu" -Type DWord -Value 0xff$HexColor

# Start, Taskbar and Action center
Set-ItemProperty -Path "$PathToCUThemesPersonalize" -Name "ColorPrevalence" -Type DWord -Value 0

# Title Bars and Windows Borders
Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "ColorPrevalence" -Type DWord -Value 1

# Window Color History
Set-ItemProperty -Path "$PathToCUThemesColorHistory" -Name "ColorHistory0" -Type DWord -Value 0xff$HexColorBGR
Set-ItemProperty -Path "$PathToCUThemesColorHistory" -Name "ColorHistory1" -Type DWord -Value $ColorHistory.ColorHistory0
Set-ItemProperty -Path "$PathToCUThemesColorHistory" -Name "ColorHistory2" -Type DWord -Value $ColorHistory.ColorHistory1
Set-ItemProperty -Path "$PathToCUThemesColorHistory" -Name "ColorHistory3" -Type DWord -Value $ColorHistory.ColorHistory2
Set-ItemProperty -Path "$PathToCUThemesColorHistory" -Name "ColorHistory4" -Type DWord -Value $ColorHistory.ColorHistory3
Set-ItemProperty -Path "$PathToCUThemesColorHistory" -Name "ColorHistory5" -Type DWord -Value $ColorHistory.ColorHistory4

# Miscellaneous stuff (didn't work)
Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "ColorizationAfterglowBalance" -Type DWord -Value 10
# Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "ColorizationBlurBalance" -Type DWord -Value 1
Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "ColorizationColorBalance" -Type DWord -Value 89
Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "ColorizationGlassAttribute" -Type DWord -Value 0
Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "ColorizationGlassAttribute" -Type DWord -Value 1
Set-ItemProperty -Path "$PathToCUWindowsDWM" -Name "EnableWindowColorization" -Type DWord -Value 1

Set-ItemProperty -Path "$PathToCUDesktop" -Name "AutoColorization" -Type DWord -Value 0
Set-ItemProperty -Path "$PathToCUThemesHistory" -Name "AutoColor" -Type DWord -Value 0


$FontsFolder = "fonts"

function Install-NerdFont() {
    Push-Location -Path "$PSScriptRoot\..\..\tmp"
    New-Item -Path "Fonts" -ItemType Directory | Out-Null

    Write-Output -Types "@" -Status "Downloading Fira Code..."
    Install-FiraCode
    Write-Output -Types "@" -Status "Downloading JetBrains Mono..."
    Install-JetBrainsMono
    Write-Output -Types "@" -Status "Downloading MesloLGS NF..."
    Install-MesloLGS

    Write-Output -Types "+" -Status "Installing downloaded fonts on $pwd\$FontsFolder..."
    Install-Font -FontSourceFolder "$FontsFolder"
    Write-Output -Types "@" -Status "Cleaning up..."
    Remove-Item -Path "$FontsFolder" -Recurse
    Pop-Location
}

function Install-FiraCode() {
    $FiraCodeOutput = Get-APIFile -URI "https://api.github.com/repos/tonsky/FiraCode/releases/latest" -ObjectProperty "assets" -FileNameLike "Fira*Code*.zip" -PropertyValue "browser_download_url" -OutputFolder "$FontsFolder" -OutputFile "FiraCode.zip"
    Expand-Archive -Path "$FiraCodeOutput" -DestinationPath "$FontsFolder\FiraCode"
    Move-Item -Path "$FontsFolder\FiraCode\ttf\*" -Include *.ttf -Destination "$FontsFolder"
    Move-Item -Path "$FontsFolder\FiraCode\variable*\*" -Include *.ttf -Destination "$FontsFolder"
}

function Install-JetBrainsMono() {
    $JetBrainsOutput = Get-APIFile -URI "https://api.github.com/repos/JetBrains/JetBrainsMono/releases/latest" -ObjectProperty "assets" -FileNameLike "JetBrainsMono-*.zip" -PropertyValue "browser_download_url" -OutputFolder "$FontsFolder" -OutputFile "JetBrainsMono.zip"
    Expand-Archive -Path "$JetBrainsOutput" -DestinationPath "$FontsFolder\JetBrainsMono" -Force
    Move-Item -Path "$FontsFolder\JetBrainsMono\fonts\ttf\*" -Include *.ttf -Destination "$FontsFolder"
    Move-Item -Path "$FontsFolder\JetBrainsMono\fonts\variable*\*" -Include *.ttf -Destination "$FontsFolder"
}

function Install-MesloLGS() {
    $MesloLgsURI = "https://github.com/romkatv/powerlevel10k-media/raw/master"
    $FontFiles = @("MesloLGS NF Regular.ttf", "MesloLGS NF Bold.ttf", "MesloLGS NF Italic.ttf", "MesloLGS NF Bold Italic.ttf")

    ForEach ($Font in $FontFiles) {
        Request-FileDownload -FileURI "$MesloLgsURI/$Font" -OutputFolder "$FontsFolder" -OutputFile "$Font"
    }
}

Install-NerdFont

fsutil behavior set DisableLastAccess 1
fsutil behavior set EncryptPagingFile 0

$Apps = @(
    # Default Windows 10+ apps
    "Microsoft.3DBuilder"                    # 3D Builder
    "Microsoft.549981C3F5F10"                # Cortana
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"                  # Finance
    "Microsoft.BingFoodAndDrink"             # Food And Drink
    "Microsoft.BingHealthAndFitness"         # Health And Fitness
    "Microsoft.BingNews"                     # News
    "Microsoft.BingSports"                   # Sports
    "Microsoft.BingTranslator"               # Translator
    "Microsoft.BingTravel"                   # Travel
    "Microsoft.BingWeather"                  # Weather
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.MicrosoftSolitaireCollection" # MS Solitaire
    "Microsoft.MixedReality.Portal"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.Office.OneNote"               # MS Office One Note
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.People"                       # People
    "Microsoft.MSPaint"                      # Paint 3D
    "Microsoft.Print3D"                      # Print 3D
    "Microsoft.SkypeApp"                     # Skype (Who still uses Skype? Use Discord)
    "Microsoft.Todos"                        # Microsoft To Do
    "Microsoft.Wallet"
    "Microsoft.Whiteboard"                   # Microsoft Whiteboard
    "Microsoft.WindowsAlarms"                # Alarms
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsMaps"                  # Maps
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsReadingList"
    "Microsoft.WindowsSoundRecorder"         # Windows Sound Recorder
    "Microsoft.XboxApp"                      # Xbox Console Companion (Replaced by new App)
    "Microsoft.YourPhone"                    # Your Phone
    "Microsoft.ZuneMusic"                    # Groove Music / (New) Windows Media Player
    "Microsoft.ZuneVideo"                    # Movies & TV

    # Default Windows 11 apps
    "Clipchamp.Clipchamp"				     # Clipchamp – Video Editor
    "MicrosoftWindows.Client.WebExperience"  # Taskbar Widgets
    "MicrosoftTeams"                         # Microsoft Teams / Preview

    # 3rd party Apps
    "*ACGMediaPlayer*"
    "*ActiproSoftwareLLC*"
    "*AdobePhotoshopExpress*"                # Adobe Photoshop Express
    "*Amazon.com.Amazon*"                    # Amazon Shop
    "*Asphalt8Airborne*"                     # Asphalt 8 Airbone
    "*AutodeskSketchBook*"
    "*BubbleWitch3Saga*"                     # Bubble Witch 3 Saga
    "*CaesarsSlotsFreeCasino*"
    "*CandyCrush*"                           # Candy Crush
    "*COOKINGFEVER*"
    "*CyberLinkMediaSuiteEssentials*"
    "*DisneyMagicKingdoms*"
    "*Dolby*"                                # Dolby Products (Like Atmos)
    "*DrawboardPDF*"
    "*Duolingo-LearnLanguagesforFree*"       # Duolingo
    "*EclipseManager*"
    "*Facebook*"                             # Facebook
    "*FarmVille2CountryEscape*"
    "*FitbitCoach*"
    "*Flipboard*"                            # Flipboard
    "*HiddenCity*"
    "*Hulu*"
    "*iHeartRadio*"
    "*Keeper*"
    "*LinkedInforWindows*"
    "*MarchofEmpires*"
    "*Netflix*"                              # Netflix
    "*NYTCrossword*"
    "*OneCalendar*"
    "*PandoraMediaInc*"
    "*PhototasticCollage*"
    "*PicsArt-PhotoStudio*"
    "*Plex*"                                 # Plex
    "*PolarrPhotoEditorAcademicEdition*"
    "*RoyalRevolt*"                          # Royal Revolt
    "*Shazam*"
    "*Sidia.LiveWallpaper*"                  # Live Wallpaper
    "*SlingTV*"
    "*Speed Test*"
    "*Sway*"
    "*TuneInRadio*"
    "*Twitter*"                              # Twitter
    "*Viber*"
    "*WinZipUniversal*"
    "*Wunderlist*"
    "*XING*"

    # Apps which other apps depend on
    "Microsoft.Advertising.Xaml"

    # SAMSUNG Bloat
    #"SAMSUNGELECTRONICSCO.LTD.SamsungSettings1.2"          # Allow user to Tweak some hardware settings
    "SAMSUNGELECTRONICSCO.LTD.1412377A9806A"
    "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote"
    "SAMSUNGELECTRONICSCoLtd.SamsungNotes"
    "SAMSUNGELECTRONICSCoLtd.SamsungFlux"
    "SAMSUNGELECTRONICSCO.LTD.StudioPlus"
    "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome"
    "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate"
    "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2"
    "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording"
    #"SAMSUNGELECTRONICSCO.LTD.SamsungRecovery"             # Used to Factory Reset
    "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch"
    "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner"
    "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync"
    "SAMSUNGELECTRONICSCO.LTD.PCGallery"
    "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService"
    "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION"

    # <==========[ DIY ]==========> (Remove the # to Uninstall)

    # [DIY] Default apps i'll keep

    #"Microsoft.FreshPaint"             # Paint
    #"Microsoft.MicrosoftEdge"          # Microsoft Edge
    #"Microsoft.MicrosoftStickyNotes"   # Sticky Notes
    #"Microsoft.WindowsCalculator"      # Calculator
    #"Microsoft.WindowsCamera"          # Camera
    #"Microsoft.ScreenSketch"           # Snip and Sketch (now called Snipping tool, replaces the Win32 version in clean installs)
    #"Microsoft.WindowsFeedbackHub"     # Feedback Hub
    #"Microsoft.Windows.Photos"         # Photos

    # [DIY] Common Streaming services

    #"*SpotifyMusic*"                   # Spotify

    # [DIY] Can't be reinstalled

    #"Microsoft.WindowsStore"           # Windows Store

    # Apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.WindowsFeedback"        # Feedback Module
    #"Windows.ContactSupport"
)

Write-Title -Text "Remove Bloatware Apps"
Write-Section -Text "Removing Windows unneeded Apps"
Remove-UWPAppx -AppxPackages $Apps

# Chocolatey Apps Install
powershell.exe Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
powershell.exe choco feature enable -n allowGlobalConfirmation
powershell.exe choco install sublimetext3.app vscode chromium firefox vivaldi element-desktop gpg4win git 7zip syinternals libreoffice-fresh openoffice rufus putty sandboxie hxd zim ericzimmermantools volatility  httrack burpsuite