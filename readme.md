# PowerShell PackageManagement provider for GitLab
Implements [PackageProvider interface](https://github.com/OneGet/oneget/wiki/PackageProvider-Interface) (aka OneGet) for [GitLab](http://doc.gitlab.com/ee/api/). It allows you to install PowerShell modules right from a GitLab server.

Sample usage:  
```
Import-PackageProvider GitLab
# add GitLab Source (once)
Register-PackageSource -ProviderName GitLab -Name <Company> -Location 'https://gitlab.domain.local/api/v3' -Trusted  
$Package = Find-Package -ProviderName GitLab -Source <Company> -Name <PackageName> -Credential $Credential  
Save-Package $Package -Path D:\  
# install package into the user PSModule directory (default is system-wide); custom -Location is also available
Install-Package -Name <PackageName> -ProviderName GitLab -User $true  
Get-Package -Name <PackageName> -ProviderName GitLab | Uninstall-Package  
```

- **Module versions are equal to Git tags, thus you need to push tags to the repository first. Use 1.0.0 version notation**  
- **Requires 7z to be in the PATH**  
- You need to specify credentials to access GitLab server only once. All subsequent requests will use cached credentials.  

Dependencies are extracted from the module manifest RequiredModules property.
External dependencies are supported through specifying package CanonicalId in PrivateData section.
Other fields of RequiredPackage enable automatic package installation and assembly loading (nuget).
See excerpt from .psd1 file:
```
@{
	RequiredModules =
		@{ModuleName = 'DatabaseManagement'; ModuleVersion = '1.2.0'},
		@{ModuleName = 'CredentialManagement'; ModuleVersion = '2.0.1'}
	#RequiredAssemblies = 'C:\ProgramData\NuGet\Packages\Microsoft.Exchange.WebServices.2.2\lib\40\Microsoft.Exchange.WebServices.dll'
	PrivateData = @{
		'RequiredPackages' = @(
			@{
				CanonicalId = 'nuget:Microsoft.Exchange.WebServices/2.2#nuget.org'
				Destination = 'C:\ProgramData\NuGet\Packages'
				RequiredAssemblies = @('\lib\40\Microsoft.Exchange.WebServices.dll')
				EnvPath = $false
			},
			@{CanonicalId = 'powershellget:PSScriptAnalyzer/1.5.0#PSGallery'}
		)
	}
}
```