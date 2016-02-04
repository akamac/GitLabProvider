<#
+public string GetProviderName(Func<string, IEnumerable<object>, object> c)
+public bool FindPackage(string name, string requiredVersion, string minimumVersion, string maximumVersion, Func<string, IEnumerable<object>, object> c)
+public void AddPackageSource(string name, string location, bool trusted, Func<string, IEnumerable<object>, object> c)
+public void RemovePackageSource(string name, Func<string, IEnumerable<object>, object> c)
+public bool GetPackageSources(Func<string, IEnumerable<object>, object> c)
+public bool InstallPackageByFastpath(string fastPath, Func<string, IEnumerable<object>, object> c)
public bool GetInstalledPackages(string name, Func<string, IEnumerable<object>, object> c)
public bool UninstallPackage(string fastPath, Func<string, IEnumerable<object>, object> c)
-public bool InstallPackageByFile(string filePath, Func<string, IEnumerable<object>, object> c)
-public bool FindPackageByFile(string filePath, Func<string, IEnumerable<object>, object> c)
-public void GetMetadataDefinitions(Func<string, IEnumerable<object>, object> c)
-public void GetInstallationOptionDefinitions(Func<string, IEnumerable<object>, object> c)
-public bool IsValidPackageSource(string packageSource, Func<string, IEnumerable<object>, object> c);
-public bool IsTrustedPackageSource(string packageSource, Func<string, IEnumerable<object>, object> c);
#>

<#
Find-Package
Find-PackageProvider
Get-Package
Get-PackageProvider
Get-PackageSource
Import-PackageProvider
Install-Package
Install-PackageProvider
Register-PackageSource
Save-Package
Set-PackageSource
Uninstall-Package
Unregister-PackageSource

Get-PSRepository
Register-PSRepository
Unregister-PSRepository
Set-PSRepository

Find-Module
Install-Module
Uninstall-Module
Save-Module
Update-Module
Get-InstalledModule
#>

#. $PSScriptRoot\PackageProviderFunctions.psm1

$ProviderName = 'GitLab'
$PrivateToken = Get-Content "$PSScriptRoot\PrivateToken" | ConvertFrom-SecureString # SourceName:UserName:Token
$PackageSourcesPath = "$PSScriptRoot\PackageSources.xml"
$RegisteredPackageSources = @()
Load-RegisteredPackageSources

$InstalledPackagesPath = "$PSScriptRoot\InstalledPackages.xml"
$InstalledPackages = if (Test-Path $InstalledPackagesPath) { Import-Clixml $InstalledPackagesPath } else { @() }

function Dump-RegisteredPackageSources {
	$RegisteredPackageSources = $script:RegisteredPackageSources
	$RegisteredPackageSources | % {
		$_.Headers.'PRIVATE-TOKEN' = $_.Headers.'PRIVATE-TOKEN' | ConvertTo-SecureString -AsPlainText -Force
	}
	$RegisteredPackageSources | Export-Clixml -Path $script:PackageSourcesPath -Force
}

function Load-RegisteredPackageSources {
	if (Test-Path $script:PackageSourcesPath) {
		$RegisteredPackageSources = Import-Clixml -Path $script:PackageSourcesPath
		$RegisteredPackageSources | % {
			$_.Headers.'PRIVATE-TOKEN' = ConvertFrom-SecureString $_.Headers.'PRIVATE-TOKEN'
		}
		$script:RegisteredPackageSources = $RegisteredPackageSources
	}
}

function Get-PackageProviderName { 
    return $ProviderName
}

function Initialize-Provider { 
    Write-Verbose "Initializing provider $ProviderName"
}

function Get-Feature {
    New-Feature -name 'supports-powershell-modules'
    #New-Feature -name 'supports-regex-search'
    New-Feature -name 'supports-wildcard-search'
}

function Get-DynamicOptions {
    param(
		[Parameter(Mandatory)]
        [Microsoft.PackageManagement.MetaProvider.PowerShell.OptionCategory] $Category
    )
    switch ($Category) {
        # for searching for packages
		Package {
			#New-DynamicOption -Category $category -Name Filter -ExpectedType String -IsRequired $false
        }
		# for package sources
		Source {}
		Provider {}
		# for Install/Uninstall/Get-InstalledPackage
        Install {
			#New-DynamicOption -Category $category -Name Destination -ExpectedType String -IsRequired $true
		}
    }
}

function Add-PackageSource {
    [CmdletBinding()]
    param(
		[Parameter(Mandatory)]
        [string] $Name,
		[Parameter(Mandatory)]
        [string] $Location,
		[Parameter(Mandatory)]
        [bool] $Trusted
    )
	<#
	$Credential = $request.Options.Credential
	if (-not $Credential) {
		$msg = 'Credentials are required'
        Write-Error -Message $msg -ErrorId CredentialsNotSpecified -Category InvalidOperation -TargetObject $Name
		#throw $msg
	} else {
		$Auth = @{
			login = $Credential.UserName
			password = $Credential.GetNetworkCredential().Password
		}
		$Location = $Location.TrimEnd('/')
		$PrivateToken = (Invoke-RestMethod -Uri ($Location + '/session') -Method Post -Body $Auth).'private_token'
	#>
	$Headers = @{
		'PRIVATE-TOKEN' = $scipt:PrivateToken
		'SUDO' = 'root'
	}
	# set superuser access
	#if ($Auth.login -eq 'root') { $Headers.'SUDO' = 'root' }
	$script:RegisteredPackageSources += $PSBoundParameters |
	Add-Member -MemberType NoteProperty -Name Headers -Value $Headers -TypeName hashtable -PassThru
	New-PackageSource @PSBoundParameters -Registered $true
	Dump-RegisteredPackageSources
}

function Remove-PackageSource {
    param(
		[Parameter(Mandatory)]
        [string] $Name
    )
	$PackageSource = $script:RegisteredPackageSources | ? Name -like $Name
	if (-not $PackageSource) {
		$msg = 'Package source matching the specified name is not registered'
        Write-Error -Message $msg -ErrorId PackageSourceNotFound -Category InvalidOperation -TargetObject $Name
		#throw $msg
	} else {
		$script:RegisteredPackageSources = @($script:RegisteredPackageSources) -ne $PackageSource
		Dump-RegisteredPackageSources
	}
}

function Resolve-PackageSource { # GetPackageSources ?
    $SourceName = $request.PackageSources
    if (-not $SourceName) { $SourceName = '*' }

    $SourceName | % {
        if ($request.IsCanceled) { return }
		$PackageSource = $script:RegisteredPackageSources | ? Name -like $_
        if (-not $PackageSource) {
			$msg = "Package source matching the name $_ not registered"
			Write-Error -Message $msg -ErrorId PackageSourceNotFound -Category InvalidOperation -TargetObject $_
        } else {
			$PackageSource
		}
    }
}

function Find-Package { 
    param(
		[Parameter(Mandatory)]
        [string[]] $Name,
        [string] $RequiredVersion,
        [string] $MinimumVersion = '0.0',
        [string] $MaximumVersion = "$([int]::MaxValue).0"
    )
    <#
        $request.Options
			AllVersions
			Command
			ConfigFile
			Contains
			Filter
			ForceBootstrap
			IncludeDependencies
			Includes
			PublishLocation
			ScriptPublishLocation
			ScriptSourceLocation
			SkipValidate
			Source
			Tag
			Type
    #>
	$Options = $request.Options

	$Sources = @()
	$request.PackageSources | % {
		$Sources += $script:RegisteredPackageSources | ? Name -eq $_
	}
	if (-not $Sources) { $Sources = $script:RegisteredPackageSources }
	
	foreach ($Source in $Sources) {
		if ($request.IsCanceled) { return }
		$Name | % {
			Invoke-RestMethod -Headers $Source.Headers -Uri ($Source.Location + "/projects/search/${_}?per_page=-1") -pv Project | % {
				$Id = $Project.id
				$Tags = Invoke-RestMethod -Headers $Source.Headers -Uri ($Source.Location + "/projects/$Id/repository/tags?per_page=-1")
				
				$Tags.name | ? { [System.Version]$_ -ge $MinimumVersion -and
								 [System.Version]$_ -le $MaximumVersion -and
								 (-not $RequiredVersion -or [System.Version]$_ -eq $RequiredVersion)
				} -pv Tag | % {
					$Swid = @{
						#FastPackageReference = 
						Name = $Project.name
						Version = [System.Version]$Tag
						VersionScheme = 'MultiPartNumeric'
						Summary = $Project.description
						Source = $Source.Location
						#SearchKey <string>
						#FullPath <string>
						#Filename <string>
						#Details <hashtable>
						#Entities <ArrayList>
						Links = @($Source.Location + "/projects/$Id/repository/archive?sha=$Tag") # zip download link
						#FromTrustedSource <bool>
						#Dependencies <ArrayList> ??
						#TagId <string> ??
					}
					$Swid.FastPackageReference = $Swid | ConvertTo-Json
					New-SoftwareIdentity @Swid
				}
			}
		}

	}
}

function Download-Package {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $FastPackageReference,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Location
    )
	if (Test-Path $Location) {
		if (-not $request.Options.Force) {
			throw 'Target location already exists. Specify -Force to overwrite'
		}
	} else { mkdir $Location }
	Push-Location $Location

	$PackageInfo = $FastPackageReference | ConvertFrom-Json
	$Source = $script:RegisteredPackageSources | ? Location -eq $PackageInfo.Source

	$OutFile = "$Location\package.tar.gz"
	Invoke-WebRequest -Uri $FastPackageReference -Headers $Source.Headers -OutFile $OutFile
	& cmd "/C 7z e $OutFile -so | 7z x -si -ttar"
	mkdir $PackageInfo.Name
	Join-Path $Location "$($PackageInfo.Name)-$($PackageInfo.Version)*" -Resolve |
	Rename-Item -NewName $PackageInfo.Version | Move-Item -Destination $PackageInfo.Name
	rm $OutFile
	Pop-Location
}

function Install-Package {
    param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )   	
	Download-Package @PSBoundParameters -Location ($env:USERPROFILE + '\Documents\WindowsPowerShell\Modules')
	# 'C:\Program Files\WindowsPowerShell\Modules'
	$Swid = $FastPackageReference | ConvertFrom-Json
	$Swid.FastPackageReference = $FastPackageReference
	New-SoftwareIdentity @Swid
	$script:InstalledPackages += $FastPackageReference
	$script:InstalledPackages | Export-Clixml -Path $script:InstalledPackagesPath
}

function Uninstall-Package {
    param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )   	
	$Swid = $FastPackageReference | ConvertFrom-Json
	$Location = -join $env:USERPROFILE,'\Documents\WindowsPowerShell\Modules\',$Swid.Name,'\',$Swid.Version
	Remove-Item $Location -Recurse
	$script:InstalledPackages = @($script:InstalledPackages) -ne $FastPackageReference
	$script:InstalledPackages | Export-Clixml -Path $script:InstalledPackagesPath
}

function Get-InstalledPackage {
	$script:InstalledPackages | % {
		$Swid = ConvertFrom-Json $_
		$Swid.FastPackageReference = $_
		New-SoftwareIdentity @Swid
	}
}
