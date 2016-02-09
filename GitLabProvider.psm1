. $PSScriptRoot\HelperFunctions.ps1

try {
	Get-Command 7z
} catch {
	throw '7zip should be in the PATH'
}

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
$i = 0
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
		$h = @{Headers = $Source.Headers}
		$Name | % {
			$Projects = Invoke-RestMethod @h ($Source.Location + "/projects/search/${_}?per_page=-1")
			foreach ($Project in $Projects) {
				$ProjectId = $Project.id
				$Tags = Invoke-RestMethod @h ($Source.Location + "/projects/$ProjectId/repository/tags?per_page=-1")

				$Tags | ? { [System.Version]($_.name) -ge $MinimumVersion -and
							[System.Version]($_.name) -le $MaximumVersion -and
							(-not $RequiredVersion -or $_.name -eq $RequiredVersion)
				} -pv Tag | % {
					$TagName = $Tag.name
					$CommitId = $Tag.commit.id

					# retrieve dependencies
					$ProjectTree = Invoke-RestMethod @h ($Source.Location + "/projects/$ProjectId/repository/tree?per_page=-1")
					$ManifestFileName = ($ProjectTree | ? Name -like *.psd1).name
					$ManifestFilePath = [System.IO.Path]::GetTempFileName()
					Invoke-WebRequest @h ($Source.Location + "/projects/$ProjectId/repository/blobs/${CommitId}?filepath=$ManifestFileName") -OutFile $ManifestFilePath
					$ModuleManifest = Invoke-Expression (Get-Content $ManifestFilePath -Raw)
					$Dependencies = New-Object System.Collections.ArrayList
					@($ModuleManifest.RequiredModules) -ne $null | % {
						#$DependantProject = Invoke-RestMethod @h ($Source.Location + "/projects/search/$($_.ModuleName)?per_page=-1")
						#$DependantSwid = @{
						<#
						@{
							#FastPackageReference = 
							Name = $_.ModuleName
							Version = $_.ModuleVersion
							VersionScheme = 'MultiPartNumeric'
							Source = $Source.Name
							Summary = $DependantProject.description
							FullPath = $Source.Location + "/projects/$($DependantProject.id)/repository/archive?sha=$($_.ModuleVersion)" # zip download link
							FromTrustedSource = $true
							Filename = ''
							SearchKey = ''
							Details = @{}
							Entities = @()
							Links = @()
							Dependencies = @()
							#TagId <string>
						} | ConvertTo-Json
						#>
						#$DependantSwid.FastPackageReference = $DependantSwid | ConvertTo-Json
						#New-SoftwareIdentity @DependantSwid
						$Dependency = @{
							ProviderName = Get-PackageProviderName
							PackageName = $_.ModuleName
							Version = $_.ModuleVersion
							Source = $Source.Name
							AppliesTo = $null
						}
						[void]$Dependencies.Add((New-Dependency @Dependency))
					}
					$Swid = @{
						#FastPackageReference = 
						Name = $Project.name
						Version = $TagName #[System.Version]$Tag
						VersionScheme = 'MultiPartNumeric'
						Source = $Source.Name
						Summary = $Project.description
						FullPath = $Source.Location + "/projects/$ProjectId/repository/archive?sha=$TagName" # zip download link
						FromTrustedSource = $true
						Filename = ''
						SearchKey = ''
						Details = @{}
						Entities = @()
						Links = @()
						Dependencies = $Dependencies # array of json
						#TagId <string>
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
	#[Microsoft.PackageManagement.MetaProvider.PowerShell.SoftwareIdentity]$Swid
	New-SoftwareIdentity @Swid
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
		New-SoftwareIdentity @Swid
	}
}

function Get-PackageDependencies {
	param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )
	$Swid = $FastPackageReference | ConvertFrom-Json
	$Swid.Dependencies | % {
		Find-Package -Name $_.PackageName -RequiredVersion $_.Version
		#ProviderName,Source
	}
}