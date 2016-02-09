@{
	RootModule = 'GitLabProvider.psm1'
	ModuleVersion = '1.0.1'
	GUID = '603623a2-2dc6-47d2-bb7f-a6096cb12b4a'
	Author = 'Alexey Miasoedov'
	CompanyName = 'Intermedia'
	Copyright = '(c) 2016 Alexey Miasoedov. All rights reserved.'
	Description = 'GitLab PackageManagement provider'
	PowerShellVersion = '5.0'
	# PowerShellHostName = ''
	# PowerShellHostVersion = ''
	# DotNetFrameworkVersion = ''
	# CLRVersion = ''
	# ProcessorArchitecture = ''
	RequiredModules = @('PackageManagement')
	# RequiredAssemblies = @()
	ScriptsToProcess = @('PackageProviderFunctions.ps1')
	# TypesToProcess = @('.ps1xml')
	# FormatsToProcess = @('.ps1xml')
	# NestedModules = @()
	# FunctionsToExport = @()
	# CmdletsToExport = @()
	# VariablesToExport = @()
	# AliasesToExport = @()
	# ModuleList = @()
	FileList = 'PackageProviderFunctions.ps1','HelperFunctions.ps1','GitLabProvider.psm1'
	PrivateData = @{'PackageManagementProviders' = 'GitLabProvider.psm1'}
	# HelpInfoURI = ''
	# DefaultCommandPrefix = ''
}