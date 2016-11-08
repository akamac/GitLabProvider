@{
	RootModule = 'GitLabProvider.psm1'
	ModuleVersion = '1.3.4'
	GUID = '603623a2-2dc6-47d2-bb7f-a6096cb12b4a'
	Author = 'Alexey Miasoedov'
	CompanyName = 'Intermedia'
	Copyright = '(c) 2016 Alexey Miasoedov. All rights reserved.'
	Description = 'GitLab PackageManagement provider'
	PowerShellVersion = '4.0'
	# RequiredModules = @('PackageManagement')
	# RequiredAssemblies = @()
	ScriptsToProcess = @('PackageProviderFunctions.ps1')
	# NestedModules = @()
	FunctionsToExport = @()
	# CmdletsToExport = @()
	# VariablesToExport = @()
	# AliasesToExport = @()
	# ModuleList = @()
	FileList = 'PackageProviderFunctions.ps1','HelperFunctions.ps1','GitLabProvider.psm1'
	PrivateData = @{
		'PackageManagementProviders' = 'GitLabProvider.psm1'
		PSData = @{
			Tags = @('PackageManagement','Provider','GitLab')
			#LicenseUri = 'https://github.com/akamac/GitLabProvider/blob/master/LICENSE'
			ProjectUri = 'https://github.com/akamac/GitLabProvider'
			ReleaseNotes = 'PackageProvider for GitLab. Allows you to install PowerShell modules right from a GitLab server.'
		}
	}
	# HelpInfoURI = ''
	# DefaultCommandPrefix = ''
}