# PowerShell PackageManagement provider for GitLab
Implements [PackageProvider interface](https://github.com/OneGet/oneget/wiki/PackageProvider-Interface) (aka OneGet) for [GitLab](http://doc.gitlab.com/ee/api/). It allows you to install PowerShell modules right from a GitLab server **(api v4 only)**.

Sample usage:  
```
Import-PackageProvider GitLab
# add GitLab Source (once)
Register-PackageSource -ProviderName GitLab -Name <Company> -Location 'https://gitlab.domain.local/api/v4' -Trusted  
# search for package  
$Package = Find-Package -ProviderName GitLab -Source <Company> -Name <PackageName> -Credential $Credential  
# save package to disk  
$Package | Save-Package -Path D:\  
# install package into the user PSModule directory (default is system-wide); custom -Location is also available
Install-Package -Name <PackageName> -ProviderName GitLab -User $true  
# uninstall package  
Get-Package -Name <PackageName> -ProviderName GitLab | Uninstall-Package  
```

- **Module versions are equal to Git tags, thus you need to push tags to the repository first. Use 1.0.0 version notation**  
- You need to specify credentials to access GitLab server only once. All subsequent requests will use cached credentials.  

Dependencies CanonicalId should be specified in module manifest PrivateData.RequiredPackages section.  
See excerpt from .psd1 file:
```
@{
    PrivateData = @{
        RequiredPackages = @(
            @{CanonicalId = 'gitlab:CredentialManagement/1.2.1#CompanySource'},
            @{CanonicalId = 'powershellget:PSScriptAnalyzer/1.5.0#PSGallery'},
            @{
                CanonicalId = 'nuget:Microsoft.Exchange.WebServices/2.2#nuget.org'
                Destination = 'C:\ProgramData\NuGet\Packages'
                RequiredAssemblies = @('\lib\40\Microsoft.Exchange.WebServices.dll')
                EnvPath = $false # Machine
            },
            @{
                CanonicalId = 'chocolatey:OpenSSL.Light/1.1.0.20160926#'
                # only default install path is supported for chocolatey packages
                Destination = 'C:\Program Files\OpenSSL\bin'
                EnvPath = $true # Machine
            }
        )
    }
}
```
Other fields of RequiredPackages enable automatic package installation, assembly loading (nuget) and path update by a [separate project](https://github.com/akamac/load-dependencies).
