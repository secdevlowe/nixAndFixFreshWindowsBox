#Requires -RunAsAdministrator
#Requires -Version 5.1

Clear-Host

Remove-Module -Name nixAndFixFreshWinBox -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\nixAndFixFreshWinBox.psd1 -PassThru -Force

Import-LocalizedData -BindingVariable Global:Localization  -FileName nixAndFixFreshWinBox

# Checking
Check

#region Start menu
# Unpin all the Start tiles
UnpinAllStartTiles

# Do not show recently added apps in the Start menu
HideRecentlyAddedApps

# Show recently added apps in the Start menu
# ShowRecentlyAddedApps

# Do not show app suggestions in the Start menu
HideAppSuggestions

# Show app suggestions in the Start menu
# ShowAppSuggestions

# Hide live tiles
HideLiveTiles
#endregion Start menu
#region UI & Personalization
# Do not use check boxes to select items (current user only)
DisableCheckBoxes

# Use check boxes to select items (current user only)
# EnableCheckBoxes

# Show hidden files, folders, and drives (current user only)
ShowHiddenItems

# Do not show hidden files, folders, and drives (current user only)
# HideHiddenItems

# Show file name extensions (current user only)
ShowFileExtensions

# Do not show file name extensions (current user only)
# HideFileExtensions

# Do not hide folder merge conflicts (current user only)
ShowMergeConflicts

# Hide folder merge conflicts (current user only)
# HideMergeConflicts

# Open File Explorer to: "This PC" (current user only)
OpenFileExplorerToThisPC

# Open File Explorer to: "Quick access" (current user only)
# OpenFileExplorerToQuickAccess

# Do not show Cortana button on the taskbar (current user only)
HideCortanaButton

# Show Cortana button on the taskbar (current user only)
# ShowCortanaButton

# Do not show Task View button on the taskbar (current user only)
HideTaskViewButton

# Show Task View button on the taskbar (current user only)
# ShowTaskViewButton

# Do not show People button on the taskbar (current user only)
HidePeopleTaskbar

# Show People button on the taskbar (current user only)
# ShowPeopleTaskbar

# Show seconds on the taskbar clock (current user only)
# ShowSecondsInSystemClock

# Do not show seconds on the taskbar clock (current user only)
HideSecondsInSystemClock

# Do not show when snapping a window, what can be attached next to it (current user only)
DisableSnapAssist

# Show when snapping a window, what can be attached next to it (current user only)
# EnableSnapAssist

# Always open the file transfer dialog box in the detailed mode (current user only)
FileTransferDialogDetailed

# Always open the file transfer dialog box in the compact mode (current user only)
# FileTransferDialogCompact

# Show the ribbon expanded in File Explorer (current user only)
FileExplorerRibbonExpanded

# Do not show the ribbon expanded in File Explorer (current user only)
# FileExplorerRibbonMinimized

# Display recycle bin files delete confirmation
EnableRecycleBinDeleteConfirmation

# Do not display recycle bin files delete confirmation
# DisableRecycleBinDeleteConfirmation

# Hide the "3D Objects" folder from "This PC" and "Quick access" (current user only)
Hide3DObjects

# Show the "3D Objects" folder from "This PC" and "Quick access" (current user only)
# Show3DObjects

# Do not show frequently used folders in "Quick access" (current user only)
HideQuickAccessFrequentFolders

# Show frequently used folders in "Quick access" (current user only)
# ShowQuickAccessFrequentFolders

# Do not show recently used files in Quick access (current user only)
HideQuickAccessRecentFiles

# Show recently used files in Quick access (current user only)
# ShowQuickAccessShowRecentFiles

# Hide the search box or the search icon from the taskbar (current user only)
HideTaskbarSearch

# Show the search box from the taskbar (current user only)
# ShowTaskbarSearch

# Do not show the "Windows Ink Workspace" button on the taskbar (current user only)
HideWindowsInkWorkspace

# Show the "Windows Ink Workspace" button in taskbar (current user only)
# ShowWindowsInkWorkspace

# Always show all icons in the notification area (current user only)
ShowTrayIcons

# Do not show all icons in the notification area (current user only)
# HideTrayIcons

# Unpin all taskbar icons
UnpinAllTaskbarIcons

# View the Control Panel icons by: large icons (current user only)
ControlPanelLargeIcons

# View the Control Panel icons by: category (current user only)
# ControlPanelCategoryIcons

# Set the Windows mode color scheme to the light (current user only)
# WindowsColorSchemeLight

# Set the Windows mode color scheme to the dark (current user only)
WindowsColorSchemeDark

# Set the default app mode color scheme to the light (current user only)
# AppModeLight

# Set the default app mode color scheme to the dark (current user only)
AppModeDark

# Do not show the "New App Installed" indicator
DisableNewAppInstalledNotification

# Show the "New App Installed" indicator
# EnableNewAppInstalledNotification

# Do not show user first sign-in animation after the upgrade
HideFirstSigninAnimation

# Show user first sign-in animation the upgrade
# ShowFirstSigninAnimation

# Set the quality factor of the JPEG desktop wallpapers to default (current user only)
JPEGWallpapersQualityDefault

# Start Task Manager in expanded mode (current user only)
# TaskManagerWindowExpanded

# Show a notification when your PC requires a restart to finish updating
ShowRestartNotification

# Do not show a notification when your PC requires a restart to finish updating
# HideRestartNotification

# Do not add the "- Shortcut" suffix to the file name of created shortcuts (current user only)
DisableShortcutsSuffix

# Add the "- Shortcut" suffix to the file name of created shortcuts (current user only)
# EnableShortcutsSuffix

# Use the PrtScn button to open screen snipping (current user only)
EnablePrtScnSnippingTool

# Do not use the PrtScn button to open screen snipping (current user only)
# DisablePrtScnSnippingTool

# Change desktop background
ChangeDesktopBackground

# Small taskbar icons
SmallTaskbarIcons

# Smaller min max close window button
MinMaxCloseWindowButton

# Turn off action center
TurnOffActionCenter
#endregion UI & Personalization
#region Context menu
# Add the "Extract all" item to Windows Installer (.msi) context menu
AddMSIExtractContext

# Remove the "Extract all" item from Windows Installer (.msi) context menu
# RemoveMSIExtractContext

# Add the "Install" item to the .cab archives context menu
AddCABInstallContext

# Remove the "Install" item from the .cab archives context menu
# RemoveCABInstallContext

# Add the "Run as different user" item to the .exe files types context menu
AddExeRunAsDifferentUserContext

# Remove the "Run as different user" item from the .exe files types context menu
# RemoveExeRunAsDifferentUserContext

# Hide the "Cast to Device" item from the context menu
HideCastToDeviceContext

# Show the "Cast to Device" item in the context menu
# ShowCastToDeviceContext

# Hide the "Share" item from the context menu
HideShareContext

# Show the "Share" item in the context menu
# ShowShareContext

# Hide the "Edit with Paint 3D" item from the context menu
HideEditWithPaint3DContext

# Show the "Edit with Paint 3D" item in the context menu
# ShowEditWithPaint3DContext

# Hide the "Edit with Photos" item from the context menu
HideEditWithPhotosContext

# Show the "Edit with Photos" item in the context menu
# ShowEditWithPhotosContext

# Hide the "Create a new video" item from the context menu
HideCreateANewVideoContext

# Show the "Create a new video" item in the context menu
# ShowCreateANewVideoContext

# Hide the "Edit" item from the images context menu
HideImagesEditContext

# Show the "Edit" item from in images context menu
# ShowImagesEditContext

# Hide the "Print" item from the .bat and .cmd context menu
HidePrintCMDContext

# Show the "Print" item in the .bat and .cmd context menu
# ShowPrintCMDContext

# Hide the "Include in Library" item from the context menu
HideIncludeInLibraryContext

# Show the "Include in Library" item in the context menu
# ShowIncludeInLibraryContext

# Hide the "Send to" item from the folders context menu
HideSendToContext

# Show the "Send to" item in the folders context menu
# ShowSendToContext

# Hide the "Turn on BitLocker" item from the context menu
HideBitLockerContext

# Show the "Turn on BitLocker" item in the context menu
# ShowBitLockerContext

# Remove the "Bitmap image" item from the "New" context menu
RemoveBitmapImageNewContext

# Restore the "Bitmap image" item in the "New" context menu
# RestoreBitmapImageNewContext

# Remove the "Rich Text Document" item from the "New" context menu
RemoveRichTextDocumentNewContext

# Restore the "Rich Text Document" item in the "New" context menu
# RestoreRichTextDocumentNewContext

# Remove the "Compressed (zipped) Folder" item from the "New" context menu
RemoveCompressedFolderNewContext

# Restore the "Compressed (zipped) Folder" item from the "New" context menu
# RestoreCompressedFolderNewContext

# Make the "Open", "Print", and "Edit" context menu items available, when more than 15 items selected
EnableMultipleInvokeContext

# Disable the "Open", "Print", and "Edit" context menu items for more than 15 items selected
# DisableMultipleInvokeContext

# Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog
DisableUseStoreOpenWith

# Show the "Look for an app in the Microsoft Store" item in the "Open with" dialog
# EnableUseStoreOpenWith

# Hide the "Previous Versions" tab from files and folders context menu and also the "Restore previous versions" context menu item
DisablePreviousVersionsPage

# Show the "Previous Versions" tab from files and folders context menu and also the "Restore previous versions" context menu item
# EnablePreviousVersionsPage
#endregion Context menu
#region Chocolatey
# Install Chocolatey package manager and pre-installs as well
ChocolateyPackageManager
#endregion Chocolatey
#region Microsoft Defender & Security
# Turn on Microsoft Defender Exploit Guard network protection
# EnableNetworkProtection

# Turn off Microsoft Defender Exploit Guard network protection
DisableNetworkProtection

# Turn on detection for potentially unwanted applications and block them
# EnablePUAppsDetection

# Turn off detection for potentially unwanted applications and block them
DisabledPUAppsDetection

# Run Microsoft Defender within a sandbox
EnableDefenderSandbox

# Do not run Microsoft Defender within a sandbox
# DisableDefenderSandbox

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
DismissMSAccount

# Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge
DismissSmartScreenFilter

<#
	Include command line in process creation events
	In order this feature to work events auditing must be enabled ("EnableAuditProcess" function)

#>
# EnableAuditProcess

# Turn off events auditing generated when a process is created or starts
DisableAuditProcess

# Turn on events auditing generated when a process is created or starts
# EnableAuditCommandLineProcess

# Do not include command line in process creation events
DisableAuditCommandLineProcess

# Do not check apps and files within Microsofot Defender SmartScreen
DisableAppsSmartScreen

# Check apps and files within Microsofot Defender SmartScreen
# EnableAppsSmartScreen

# Prevent SmartScreen from marking files that have been downloaded from the Internet as unsafe (current user only)
DisableSaveZoneInformation

# Mark files that have been downloaded from the Internet as unsafe within SmartScreen (current user only)
# EnableSaveZoneInformation

# Disable activity history
DisableActivityHistory

# Disable automatic map updates
DisableMapUpdates

# Disable wap push service
DisableWAPPush

# Enable strong cryptography for .NET Framework(version 4 and above)
EnableDotNetStrongCrypto

<#
Enable Meltdown (CVE-2017-5754) compatibility flag(required for january 2018 and all subsequent windows updates)
This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all
#>
EnableMeltdownCompatFlag

# Disable password complexity and maximum age requirements
DisablePasswordPolicy

# Schedule automatic maintenance hours
AutomaticMaintenanceHours

# Turn off memory integry(virtualization based security)
TurnOffMemoryIntegry

# Disable implicit administrative shares
DisableAdminShares

# Disable obsolete SMB protocol(disabled by default since 1709)
DisableSMB

# Disable link-local multicast name resolution(LLMNR) protocol
DisableLLMNR

# Set unknown networks profile to public(deny file sharing, device discovery, etc.)
SetUnknownNetworksPublic

# Disable automatic installation of network devices
DisableNetDevicesAutoInst

# Hide tray icon
HideTrayIcon

# Disable defender cloud
DisableDefenderCloud

# Disable ntfs refs mitigations
DisableNTFSREFSMitigations

# Disable weak TLS
DisableWeakTLS
#endregion Microsoft Defender & Security
#region O&OShutup
OOShutup
#endregion O&OShutup
#region Privacy & Telemetry
# Disable the "Connected User Experiences and Telemetry" service (DiagTrack)
DisableTelemetryServices

# Set the OS level of diagnostic data gathering to minimum
SetMinimalDiagnosticDataLevel

# Set the default OS level of diagnostic data gathering
# SetDefaultDiagnosticDataLevel

# Turn off Windows Error Reporting for the current user
DisableWindowsErrorReporting

# Turn on Windows Error Reporting for the current user
# EnableWindowsErrorReporting

# Change Windows feedback frequency to "Never" for the current user
DisableWindowsFeedback

# Change Windows Feedback frequency to "Automatically" for the current user
# EnableWindowsFeedback

# Turn off tracking apps launch event
TurnOffAppLaunchTracking

# Turn off diagnostics tracking scheduled tasks
DisableScheduledTasks

# Turn on diagnostics tracking scheduled tasks
# EnableScheduledTasks

# Do not use sign-in info to automatically finish setting up device and reopen apps after an update or restart (current user only)
DisableSigninInfo

# Use sign-in info to automatically finish setting up device and reopen apps after an update or restart (current user only)
# EnableSigninInfo

# Do not let websites provide locally relevant content by accessing language list (current user only)
DisableLanguageListAccess

# Let websites provide locally relevant content by accessing language list (current user only)
# EnableLanguageListAccess

# Do not allow apps to use advertising ID (current user only)
DisableAdvertisingID

# Allow apps to use advertising ID (current user only)
# EnableAdvertisingID

# Do not let apps on other devices open and message apps on this device, and vice versa (current user only)
DisableShareAcrossDevices

# Let apps on other devices open and message apps on this device, and vice versa (current user only)
# EnableShareAcrossDevices

# Do not show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested (current user only)
DisableWindowsWelcomeExperience

# Show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested (current user only)
# EnableWindowsWelcomeExperience

# Get tip, trick, and suggestions as you use Windows (current user only)
#EnableWindowsTips

# Do not get tip, trick, and suggestions as you use Windows (current user only)
DisableWindowsTips

# Do not show suggested content in the Settings app (current user only)
DisableSuggestedContent

# Show suggested content in the Settings app (current user only)
# EnableSuggestedContent

# Turn off automatic installing suggested apps (current user only)
DisableAppsSilentInstalling

# Turn on automatic installing suggested apps (current user only)
# EnableAppsSilentInstalling

# Do not suggest ways I can finish setting up my device to get the most out of Windows (current user only)
DisableWhatsNewInWindows

# Suggest ways I can finish setting up my device to get the most out of Windows
# EnableWhatsNewInWindows

# Do not offer tailored experiences based on the diagnostic data setting (current user only)
DisableTailoredExperiences

# Offer tailored experiences based on the diagnostic data setting
# EnableTailoredExperiences

# Disable Bing search in the Start Menu
DisableBingSearch

# Enable Bing search in the Start Menu
# EnableBingSearch

# Disable find my device
DisableFindMyDevice

# Disable apps suggestions, tips, welcome experience
DisableAppsSuggestionsTipsWelcomeExperience

# Disable news feeds
DisableNewsFeeds

# Disable edge update
DisableEdgeUpdate
#endregion Privacy & Telemetry
#region Gaming
# Turn off Xbox Game Bar tips
DisableXboxGameTips

# Turn on Xbox Game Bar tips
# EnableXboxGameTips

# Adjust best performance for all programs and also foreground services
BestPriorityForeground

# Disable mouse feedback
DisableMouseFeedback

# Enable full-screen optimization
EnableFullScreenOptimization
#endregion Gaming
#region UWP apps
<#
	Uninstall UWP apps
	A dialog box that enables the user to select packages to remove
	App packages will not be installed for new users if "Uninstall for All Users" is checked

#>
UninstallUWPApps

# Do not let UWP apps run in the background, except the followings... (current user only)
DisableBackgroundUWPApps

# Disable the following Windows features
DisableWindowsFeatures

# Disable certain Feature On Demand v2 (FODv2) capabilities
DisableWindowsCapabilities

# Turn off Cortana autostarting
DisableCortanaAutostart
#endregion UWP apps
#region System
# Uninstall OneDrive
UninstallOneDrive

# Do not show sync provider notification within File Explorer (current user only)
HideOneDriveFileExplorerAd

# Uninstall MSTeams
UninstallMSTeams

# Turn on Storage Sense (current user only)
EnableStorageSense

# Disable hibernation if the device is not a laptop
DisableHibernate

# Turn on hibernate
# EnableHibernate

# Change the %TEMP% environment variable path to the %SystemDrive%\Temp (both machine-wide, and for the current user)
SetTempPath

# Enable Windows 260 character path limit
EnableWin32LongPaths

# Disable Windows 260 character path limit
# DisableWin32LongPaths

# Display the Stop error information on the BSoD
EnableBSoDStopError

# Do not display the Stop error information on the BSoD
# DisableBSoDStopError

# Change "Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Elevate without prompting"
DisableAdminApprovalMode

# Change "Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent for non-Windows binaries" (default value)
# EnableAdminApprovalMode

# Turn on access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
EnableMappedDrivesAppElevatedAccess

# Turn off access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
# DisableMappedDrivesAppElevatedAccess

# Opt out of the Delivery Optimization-assisted updates downloading
DisableDeliveryOptimization

# Opt-in to the Delivery Optimization-assisted updates downloading
# EnableDeliveryOptimization

# Always wait for the network at computer startup and logon for workgroup networks
# AlwaysWaitNetworkStartup

# Never wait for the network at computer startup and logon for workgroup networks
NeverWaitNetworkStartup

# Use latest installed .NET runtime for all apps
EnableLatestInstalled.NET

# Do not use latest installed .NET runtime for all apps
# DisableLatestInstalled.NET

# Save screenshots by pressing Win+PrtScr to the Desktop folder (current user only)
# WinPrtScrDesktopFolder

# Hide annoying Troubleshooting
HideTroubleshooting

# Launch folder windows in a separate process (current user only)
# EnableFoldersLaunchSeparateProcess

# Do not folder windows in a separate process (current user only)
DisableFoldersLaunchSeparateProcess

# Turn on Num Lock at startup
# EnableNumLock

# Turn off Num Lock at startup
DisableNumLock

# Do not activate StickyKey after tapping the Shift key 5 times (current user only)
DisableStickyShift

# Activate StickyKey after tapping the Shift key 5 times (current user only)
# EnableStickyShift

# Do not use AutoPlay for all media and devices (current user only)
DisableAutoplay

# Use AutoPlay for all media and devices (current user only)
# EnableAutoplay

# Disable thumbnail cache removal
DisableThumbnailCacheRemoval

# Enable thumbnail cache removal
# EnableThumbnailCacheRemoval

# Automatically save my restartable apps when signing out and restart them after signing in (current user only)
EnableSaveRestartableApps

# Do not automatically save my restartable apps when signing out and restart them after signing in
# DisableSaveRestartableApps

# Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks
# EnableNetworkDiscovery

# Disable "Network Discovery" and "File and Printers Sharing" for workgroup networks
DisableNetworkDiscovery

# This option must be Enabled by default, otherwise set it so.
OnlySecurityUpdates

# Do not automatically adjust active hours for me based on daily usage
DisableSmartActiveHours

# Automatically adjust active hours for me based on daily usage
SetActiveHours

# Do not restart this device as soon as possible when a restart is required to install an update
DisableDeviceRestartAfterUpdate

# Set data execution prevention (DEP) policy to optout
SetDEPOptOut

# Disable remote assistance
DisableRemoteAssistance

# Stop and disable superfetch service
DisableSuperfetch

<#
Disable offering of drivers through Windows Update
Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
#>
DisableAutoUpdateDriver

# SvcHost split threshold in KB
SvcHostSplitThresholdInKB

# Function discovery resource publication
FDResPub

# Disable microsoft edge services
DisableMSEdgeServices

# Turn off lock screen background
TurnOffLockScreenBackground

# Disable license manager
DisableLicenseManager

# Disable network connection status indicator
NetworkConnectionStatusIndicator

# Fix timers
FixTimers

# Don't use firmware pci settings
DontUseFirmwarePciSettings

# Disable hyper virtualization
DisableHyperVirtualization

# Enable pae
EnablePae

# Disable au power management
DisableAUPowerManagement

# Prioritize csrss.exe service
PrioritizeCSRSSService

# Disable lock screen
DisableLockScreen

# Auto enhance during playback
AutoEnhanceDuringPlayback

# Disable windows auto upgrade
DisableWindowsAutoUpgrade

# Fix windows DPI
FixWindowsDPI

# Disable automatic maintenance
DisableAutomaticMaintenance

# Disable sleep study
DisableSleepStudy

# Disable system energy saving
DisableSystemEnergySaving

# Disable hiberboot
DisableHiberboot

# Disable warning sounds
DisableWarningSounds
#endregion System
#region Performance
# Adjust best performance(that would able to increase the overall performance)
AdjustBestPerformance

# Prevent battery saver
PreventBatterySaver

# Disable default disk defragmenter
DisableDefaultDiskDefragmenter

# Let personalize power plan, neither switch it off so
LetPersonalizePowerPlan

# Prevent require sign-in when after sleep
PreventRequireSignInWhenAfterSleep

# Disable indexing
DisableIndexing

# Set current boot timeout value to 1
SetBootTimeoutValue

# Ntfs allow extended character 8dot3 rename
NtfsAllowExtendedCharacter8dot3Rename

# Ntfs disable 8dot3 name creation
NtfsDisable8dot3NameCreation

# Auto end tasks
AutoEndTasks

# Hung app timeout
HungAppTimeout

# Wait to kill app timeout
WaitToKillAppTimeout

# Low-level hooks timeout
LowLevelHooksTimeout

# Foreground lock timeout
ForegroundLockTimeout

# No low disk space checks
NoLowDiskSpaceChecks

# Link resolve ignore link info
LinkResolveIgnoreLinkInfo

# No resolve search
NoResolveSearch

# No resolve track
NoResolveTrack

# No internet open with
NoInternetOpenWith

# Wait to kill service timeout
WaitToKillServiceTimeout

# Disable paging executive
DisablePagingExecutive

# Large system cache
LargeSystemCache

# IO page lock limit
IoPageLockLimit

# Paging files
PagingFiles

# Second-level data cache
SecondLevelDataCache

# Existing page files
ExistingPageFiles

# Enable prefetcher
EnablePrefetcher

# Wait to kill service timeout
WaitToKillServiceTimeout1

# Disable paging executive
DisablePagingExecutive1

# Enable boot optimization function
EnableBootOptimizationFunction

# Ntfs disable last access update
NtfsDisableLastAccessUpdate

# Max connections per 0 server
MaxConnectionsPer_0Server

# Max connections per server
MaxConnectionsPerServer

# Non best effort limit
NonBestEffortLimit

# Double click height width
DoubleClickHeightWidth

# Value max
ValueMax

# Disable boot splash animations
DisableBootSplashAnimations

# Disable trusted platform module
DisableTrustedPlatformModule

# Disable integrity checks
DisableIntegrityChecks

# Disable last access
DisableLastAccess

# Set memory usage
SetMemoryUsage

# Disable boot logging
DisableBootLogging

# Increase default size buffer
IncreaseDefaultSizeBuffer

# IRP stack size
IRPStackSize

# Size
Size

# Max work items
MaxWorkItems

# Maxmpxct
MaxMpxCt

# Max cmds
MaxCmds

# Disable strict name checking
DisableStrictNameChecking

# Enable dynamic backlog
EnableDynamicBacklog

# Minimum dynamic backlog
MinimumDynamicBacklog

# Maximum dynamic backlog
MaximumDynamicBacklog

# Dynamic backlog growth delta
DynamicBacklogGrowthDelta

# Increase mft zone
IncreaseMFTZone

# Enable memory allocation in graphics driver
EnableMemoryAllocationInGraphicsDriver

# Disable realtime monitoring
DisableRealtimeMonitoring

# Enable hardware accelerated GPU scheduling
EnableHardwareAcceleratedGPUScheduling

# Indexer respect power modes
IndexerRespectPowerModes

# Enable TRIM
EnableTRIM

# Disable power throttling
DisablePowerThrottling

# Disable wpp software tracing logs
DisableWPPSoftwareTracingLogs

# Cpu rate limit
CpuRateLimit

# Disable search history
DisableSearchHistory

# Thread priority
ThreadPriority

# Debloat microsoft services
DebloatMicrosoftServices
#endregion Performance
Errors
