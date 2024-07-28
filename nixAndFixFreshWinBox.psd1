@{
	RootModule            = 'nixAndFixFreshWinBox.psm1'
	ModuleVersion         = '0.1'
	Author                = 'secdevlowe'
	Description           = 'Nixing and fixing fresh installs of Windows 10 and/or 11.'
	PowerShellVersion     = '5.1'
	ProcessorArchitecture = 'AMD64'
	FunctionsToExport     = '*'

	PrivateData           = @{
		PSData = @{
			LicenseUri = 'https://github.com/secdevlowe/nixAndFixFreshWindowsBox/blob/main/LICENSE'
			ProjectUri = 'https://github.com/secdevlowe/nixAndFixFreshWindowsBox/tree/main'
		}
	}
}
