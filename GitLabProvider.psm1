. $PSScriptRoot\HelperFunctions.ps1

$RegisteredPackageSources = @()

$InstalledPackagesPath = "$PSScriptRoot\InstalledPackages.json"
[array]$InstalledPackages = if (Test-Path $InstalledPackagesPath) {
	Get-Content $InstalledPackagesPath | ConvertFrom-Json
} else { @() }

function Get-PackageProviderName { 
    return 'GitLab'
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
	} else {
		$script:RegisteredPackageSources = @($script:RegisteredPackageSources) -ne $PackageSource
		#Dump-RegisteredPackageSources
	}
}

function Resolve-PackageSources {
    $SourceName = $request.PackageSources
    if (-not $SourceName) { $SourceName = '*' }
	
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
        $request.Options; implement:
			Filter
			IncludeDependencies
    #>
	if (-not $MinimumVersion) {
		$MinimumVersion = '0.0'
	}
    if (-not $MaximumVersion) {
		$MaximumVersion = "$([int]::MaxValue).0"
	}
	$Options = $request.Options
	$Sources = Get-PackageSources $request
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
	mkdir $PackageInfo.Name -ea SilentlyContinue
	Join-Path $Location "$($PackageInfo.Name)-$($PackageInfo.Version)*" -Resolve |
	Rename-Item -NewName $PackageInfo.Version -PassThru | Move-Item -Destination $PackageInfo.Name
	rm $OutFile
	rm pax_global_header
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
	$Location = $env:USERPROFILE,'\Documents\WindowsPowerShell\Modules\',$Swid.Name,'\',$Swid.Version -join ''
	Remove-Item $Location -Recurse
	$script:InstalledPackages = $script:InstalledPackages | ? { $_.Name -ne $Swid.Name -and $_.Version -ne $Swid.Version }
	Dump-InstalledPackages
}

function Get-InstalledPackage {
	$script:InstalledPackages | % {
		$Swid = ConvertTo-Hashtable $_
		$Swid.FastPackageReference = $_ | ConvertTo-Json
		[Microsoft.PackageManagement.MetaProvider.PowerShell.SoftwareIdentity]$Swid
	}
}