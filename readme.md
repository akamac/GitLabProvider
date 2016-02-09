# PowerShell PackageManagement provider for GitLab
Implements [PackageProvider interface](https://github.com/OneGet/oneget/wiki/PackageProvider-Interface) (aka OneGet) for GitLab. It allows you to install PowerShell modules right from GitLab server.

Sample usage:  
```
Import-PackageProvider GitLab
Register-PackageSource -ProviderName GitLab -Name <Company> -Location 'https://gitlab.domain.local/api/v3' -Trusted  

Find-Package -ProviderName GitLab -Source <Company> -Name <PackageName> -Credential $Credential -IncludeDependencies | Install-Package  

Get-Package -Name <PackageName> -ProviderName GitLab |  
Save-Package -Path D:\ -ProviderName GitLab  

Uninstall-Package -Name <PackageName> -ProviderName GitLab  
```

- **Module versions are equal to Git tags, thus you need to push tags to the repository first. Use 1.0.0 version notation**  
- At the moment registered package sources are not persistent across session, thus you have to add them every time a new PS session starts.
- You need to specify credentials to access GitLab server only once. All subsequent requests will use cached credentials.
- By default modules are installed to user PSModule directory.  
