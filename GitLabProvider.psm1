<#
+public string GetProviderName(Func<string, IEnumerable<object>, object> c)
+public bool FindPackage(string name, string requiredVersion, string minimumVersion, string maximumVersion, Func<string, IEnumerable<object>, object> c)
+public void AddPackageSource(string name, string location, bool trusted, Func<string, IEnumerable<object>, object> c)
+public void RemovePackageSource(string name, Func<string, IEnumerable<object>, object> c)
+public bool GetPackageSources(Func<string, IEnumerable<object>, object> c)
+public bool InstallPackageByFastpath(string fastPath, Func<string, IEnumerable<object>, object> c)
+public bool GetInstalledPackages(string name, Func<string, IEnumerable<object>, object> c)
+public bool UninstallPackage(string fastPath, Func<string, IEnumerable<object>, object> c)
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
#$PrivateToken = Get-Content "$PSScriptRoot\PrivateToken" | ConvertFrom-SecureString # SourceName:UserName:Token
$PackageSourcesPath = "$PSScriptRoot\PackageSources.json"
$RegisteredPackageSources = @()
Load-RegisteredPackageSources

$InstalledPackagesPath = "$PSScriptRoot\InstalledPackages.json"
[array]$InstalledPackages = if (Test-Path $InstalledPackagesPath) {
	Get-Content $InstalledPackagesPath | ConvertFrom-Json
} else { @() }

# helper functions
function Get-PackageSources {
	param(
		[Parameter(Mandatory)]
		$request
	)
	$Sources = if ($request.PackageSources) {
		$script:RegisteredPackageSources | ? Name -in $request.PackageSources
	} else { $script:RegisteredPackageSources }
	
	$Sources | ? {-not $_.Headers} | % {
		if ($request.Credential) {
			Set-PackageSourcePrivateToken -Source $_.Name -Credential $request.Credential
		} else {
			$msg = "Credentials are required for source $($_.Name)"
			Write-Error -Message $msg -ErrorId CredentialsNotSpecified -Category InvalidOperation -TargetObject $_.Name
		}
	}
	$Sources
}

function ConvertTo-Hashtable {
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
        $Object
    )
    Process {
        $ht = @{}
        $Object | Get-Member -MemberType Properties | % {
            $ht[$_.Name] = $Object.($_.Name)
        }
        $ht
    }
}

function ConvertTo-PlainText {
	param(
		[Parameter(Mandatory,ValueFromPipeline)]
		[System.Security.SecureString] $SecureString
	)
	$marshal = [System.Runtime.InteropServices.Marshal]
	$BSTR = $marshal::SecureStringToBSTR($SecureString)
	$marshal::PtrToStringAuto($BSTR)
	$marshal::ZeroFreeBSTR($BSTR)
}

function Dump-InstalledPackages {
	$script:InstalledPackages | ConvertTo-Json |
	Out-File $script:InstalledPackagesPath -Force
}

function Dump-RegisteredPackageSources {
	#$RegisteredPackageSources = $script:RegisteredPackageSources.PSObject.Copy()
	$script:RegisteredPackageSources | ? Headers | % {
		$_.Headers.'PRIVATE-TOKEN' = $_.Headers.'PRIVATE-TOKEN' |
		ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
	}
	$script:RegisteredPackageSources | ConvertTo-Json |
	Out-File $script:PackageSourcesPath -Force
	Load-RegisteredPackageSources
	#Export-Clixml -Path $script:PackageSourcesPath -Force
}

function Load-RegisteredPackageSources {
	if (Test-Path $script:PackageSourcesPath) {
		$RegisteredPackageSources = Get-Content $script:PackageSourcesPath |
		ConvertFrom-Json | % {
			$ht = ConvertTo-Hashtable $_
			if ($ht.Headers) {
				$Headers = @{'PRIVATE-TOKEN' = ConvertTo-SecureString $ht.Headers.'PRIVATE-TOKEN' | ConvertTo-PlainText}
				$ht.Remove('Headers')
			}
			New-PackageSource @ht |
			Add-Member -MemberType NoteProperty -Name Headers -Value $Headers -TypeName hashtable -PassThru
			$ht, $headers | export-clixml d:\hh.xml
		}
		$RegisteredPackageSources | export-clixml d:\rps1.xml
		$script:RegisteredPackageSources = $RegisteredPackageSources
	}
}

function Set-PackageSourcePrivateToken {
	param(
		[Parameter(Mandatory)]
		[string[]] $Source,
		[Parameter(Mandatory)]
		[pscredential] $Credential
	)
	$Source | % {
		$PackageSource = $script:RegisteredPackageSources | ? Name -eq $_
		if (-not $PackageSource.Headers) {
			$Auth = @{
				login = $Credential.UserName
				password = $Credential.GetNetworkCredential().Password
			}
			$Location = $PackageSource.Location.TrimEnd('/')
			$PrivateToken = (Invoke-RestMethod -Uri ($Location + '/session') -Method Post -Body $Auth).'private_token'
			$Headers = @{
				'PRIVATE-TOKEN' = $PrivateToken
				#'SUDO' = 'root'
			}
			$PackageSource | Add-Member -MemberType NoteProperty -Name Headers -Value $Headers -TypeName hashtable
			#$PackageSource.Headers = $Headers
			#Dump-RegisteredPackageSources
		}
		#$PackageSource
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
	$PSBoundParameters.Registered = $true
	$PackageSource = New-PackageSource @PSBoundParameters
	$script:RegisteredPackageSources += $PackageSource
	#Dump-RegisteredPackageSources
	$script:RegisteredPackageSources | export-clixml d:\rps.xml
	$PackageSource
}

function Remove-PackageSource {
    param(
		[Parameter(Mandatory)]
        [string] $Name
    )
	$PackageSource = $script:RegisteredPackageSources | ? Name -eq $Name
	if (-not $PackageSource) {
		$msg = 'Package source matching the specified name is not registered'
        Write-Error -Message $msg -ErrorId PackageSourceNotFound -Category InvalidOperation -TargetObject $Name
		#throw $msg
	} else {
		$script:RegisteredPackageSources = @($script:RegisteredPackageSources) -ne $PackageSource
		#Dump-RegisteredPackageSources
	}
}

function Resolve-PackageSources {
    $SourceName = $request.PackageSources
    if (-not $SourceName) { $SourceName = '*' }
	$script:RegisteredPackageSources | export-clixml d:\rps3.xml
	
    $SourceName | % {
        if ($request.IsCanceled) { return }
		$PackageSource = $script:RegisteredPackageSources | ? Name -like $_
        if (-not $PackageSource) {
			$msg = "Package source matching the name $_ not registered"
			Write-Error -Message $msg -ErrorId PackageSourceNotFound -Category InvalidOperation -TargetObject $_
        } else { $PackageSource }
    }
}

function Find-Package { 
    param(
		[Parameter(Mandatory)]
        [string[]] $Name,
        [string] $RequiredVersion,
        [string] $MinimumVersion,
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
	if (-not $MinimumVersion) {
		$MinimumVersion = '0.0'
	}
    if (-not $MaximumVersion) {
		$MaximumVersion = "$([int]::MaxValue).0"
	}
	$Options = $request.Options
	$Sources = Get-PackageSources $request
	$sources | Export-Clixml d:\sources.xml
	foreach ($Source in $Sources) {
		if ($request.IsCanceled) { return }
		$Name | % {
			$Projects = Invoke-RestMethod -Headers $Source.Headers -Uri ($Source.Location + "/projects/search/${_}?per_page=-1")
			foreach ($Project in $Projects) {
				$Id = $Project.id
				$Tags = Invoke-RestMethod -Headers $Source.Headers -Uri ($Source.Location + "/projects/$Id/repository/tags?per_page=-1")
				
				$Tags.name | ? { [System.Version]$_ -ge $MinimumVersion -and
								 [System.Version]$_ -le $MaximumVersion -and
								 (-not $RequiredVersion -or $_ -eq $RequiredVersion)
				} -pv Tag | % {
					$Swid = @{
						#FastPackageReference = 
						Name = $Project.name
						Version = $Tag #[System.Version]$Tag
						VersionScheme = 'MultiPartNumeric'
						Source = $Source.Name
						Summary = $Project.description
						FullPath = $Source.Location + "/projects/$Id/repository/archive?sha=$Tag" # zip download link
						FromTrustedSource = $true
						#Filename <string>
						#SearchKey <string>
						#Details <hashtable>
						##Entities <ArrayList> private
						##Links <ArrayList> private
						##Dependencies <ArrayList> private
						##TagId <string> private
					}
					$Swid.FastPackageReference = $Swid | ConvertTo-Json
					#New-SoftwareIdentity @Swid
					[Microsoft.PackageManagement.MetaProvider.PowerShell.SoftwareIdentity]$Swid
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
	$Options = $request.Options
	$Sources = Get-PackageSources $request

	if (-not (Test-Path $Location)) { mkdir $Location }
	Push-Location $Location

	$PackageInfo = $FastPackageReference | ConvertFrom-Json
	$Source = $Sources | ? Name -eq $PackageInfo.Source
	$OutFile = Join-Path $Location 'package.tar.gz'
	Invoke-WebRequest -Uri $PackageInfo.FullPath -Headers $Source.Headers -OutFile $OutFile
	& cmd "/C 7z e $OutFile -so | 7z x -si -ttar"
	mkdir $PackageInfo.Name
	Join-Path $Location "$($PackageInfo.Name)-$($PackageInfo.Version)*" -Resolve |
	Rename-Item -NewName $PackageInfo.Version -PassThru | Move-Item -Destination $PackageInfo.Name
	rm $OutFile
	Pop-Location
	
	$Swid = $PackageInfo | ConvertTo-Hashtable
	$Swid.FastPackageReference = $FastPackageReference
	[Microsoft.PackageManagement.MetaProvider.PowerShell.SoftwareIdentity]$Swid
}

function Install-Package {
    param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )	
	Download-Package @PSBoundParameters -Location ($env:USERPROFILE + '\Documents\WindowsPowerShell\Modules')
	# 'C:\Program Files\WindowsPowerShell\Modules'
	$script:InstalledPackages += $FastPackageReference | ConvertFrom-Json
	Dump-InstalledPackages
}

function Uninstall-Package {
    param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )   	
	$Swid = $FastPackageReference | ConvertFrom-Json
	$Location = -join $env:USERPROFILE,'\Documents\WindowsPowerShell\Modules\',$Swid.Name,'\',$Swid.Version
	Remove-Item $Location -Recurse
	$script:InstalledPackages = $script:InstalledPackages -ne ($FastPackageReference | ConvertFrom-Json)
	Dump-InstalledPackages
}

function Get-InstalledPackage {
	$script:InstalledPackages | % {
		$Swid = ConvertTo-Hashtable $_
		$Swid.FastPackageReference = $_ | ConvertTo-Json
		[Microsoft.PackageManagement.MetaProvider.PowerShell.SoftwareIdentity]$Swid
	}
}