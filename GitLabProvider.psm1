. $PSScriptRoot\HelperFunctions.ps1

function Initialize-Provider {
    Write-Verbose "Initializing provider $ProviderName"
	# does not execute!
}

function Get-PackageProviderName {
	# actual initialization
	if (-not $Initialized) {
		$ConfigFolder = 'C:\ProgramData\GitLabProvider'
		if (-not (Test-Path $ConfigFolder)) { mkdir $ConfigFolder }
		$script:RegisteredPackageSourcesPath = "$ConfigFolder\PackageSources.json"
		[array]$script:RegisteredPackageSources = if (Test-Path $RegisteredPackageSourcesPath) {
			Get-Content $RegisteredPackageSourcesPath | ConvertFrom-Json | % {
				Add-PackageSource -Name $_.Name -Location $_.Location -Trusted $_.IsTrusted
			}
		} else { @() }
	
		$script:InstalledPackagesPath = "$ConfigFolder\InstalledPackages.json"
		
		$script:Initialized = $true
	}

    return 'GitLab'
}

function Get-Feature {
    New-Feature -Name 'supports-powershell-modules'
}

function Get-DynamicOptions {
    param(
		[Parameter(Mandatory)]
        [Microsoft.PackageManagement.MetaProvider.PowerShell.OptionCategory] $Category
    )
    switch ($Category) {
		Package {} # for Find-Package
		Source {} # for Add/Remove-PackageSource
		Provider {} # not used
		# for Install/Uninstall/Get-InstalledPackage
        Install {
			New-DynamicOption -Category $Category -Name Location -ExpectedType String -IsRequired $false
			New-DynamicOption -Category $Category -Name User -ExpectedType String -IsRequired $false
			#New-DynamicOption -Category $Category -Name System -ExpectedType String -IsRequired $false
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
	Dump-RegisteredPackageSources
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
		Dump-RegisteredPackageSources
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

				$Tags | Sort name -Descending | ? { [System.Version]($_.name) -ge $MinimumVersion -and
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
					<#
					@($ModuleManifest.RequiredModules) -ne $null | % {
						$Dependency = @{
							ProviderName = Get-PackageProviderName
							PackageName = $_.ModuleName
							Version = $_.ModuleVersion
							Source = $Source.Name
							AppliesTo = $null
						}
						[void]$Dependencies.Add((New-Dependency @Dependency))
					}
					#>
					# GitLab / PSGallery / chocolatey / nuget
					@($ModuleManifest.PrivateData.RequiredPackages) -ne $null | % {
						$Dependency = $_.CanonicalId.Split(':/#') # 'nuget:Microsoft.Exchange.WebServices/2.2#nuget.org'
						[void]$Dependencies.Add((New-Dependency @Dependency))
					}
					$Swid = @{
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
					if (-not $Options.AllVersions) { break }
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
	Push-Location $PSScriptRoot
	& cmd "/C .\7z.exe e `"$OutFile`" -so | 7z x -si -ttar"
	Pop-Location
	mkdir $PackageInfo.Name -ea SilentlyContinue
	Join-Path $Location "$($PackageInfo.Name)-$($PackageInfo.Version)*" -Resolve |
	Rename-Item -NewName $PackageInfo.Version -PassThru | Move-Item -Destination $PackageInfo.Name
	rm $OutFile
	rm pax_global_header
	Pop-Location
	
	$Swid = $PackageInfo | ConvertTo-Hashtable
	$Swid.FastPackageReference = $FastPackageReference
	New-SoftwareIdentity @Swid
}

function Install-Package {
    param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )
	$Location = if ($request.Options.Location) {
		$request.Options.Location
	} elseif ($request.Options.User) {
		"$env:USERPROFILE\Documents\WindowsPowerShell\Modules\"
	} else {
		'C:\Program Files\WindowsPowerShell\Modules'
	}
	Download-Package @PSBoundParameters -Location $Location
	$Swid = $FastPackageReference | ConvertFrom-Json
	$Param = @{
		MemberType = 'NoteProperty'
		Name = 'Location'
		Value = $Location
		TypeName = 'string'
	}
	[array]$InstalledPackages = if (Test-Path $InstalledPackagesPath) {
		Get-Content $InstalledPackagesPath | ConvertFrom-Json
	} else { @() }
	$InstalledPackages += $Swid | Add-Member @Param -PassThru
	Dump-InstalledPackages $InstalledPackages
}

function Uninstall-Package {
    param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )
	$Swid = $FastPackageReference | ConvertFrom-Json
	#[array]$InstalledPackages = Get-Content $InstalledPackagesPath | ConvertFrom-Json
	$Package = $script:InstalledPackages | ? { $_.Name -eq $Swid.Name -and $_.Version -eq $Swid.Version }
	$Location = Join-Path $Package.Location $Swid.Name
	Remove-Item "$Location\$($Swid.Version)" -Recurse
	if (-not (Test-Path "$Location\*")) {
		Remove-Item $Location
	}
	$InstalledPackages = $InstalledPackages -ne $Package
	Dump-InstalledPackages $InstalledPackages
}

function Get-InstalledPackage {
	param(
        [string] $Name,
        [string] $RequiredVersion,
        [string] $MinimumVersion,
        [string] $MaximumVersion = "$([int]::MaxValue).0"
    )
	if (-not $MinimumVersion) {
		$MinimumVersion = '0.0'
	}
    if (-not $MaximumVersion) {
		$MaximumVersion = "$([int]::MaxValue).0"
	}

	[array]$script:InstalledPackages = if (Test-Path $InstalledPackagesPath) {
		Get-Content $InstalledPackagesPath | ConvertFrom-Json
	} else { @() }
	$InstalledPackages | ? Name -match $Name | Sort Version -Descending | ? {
		[System.Version]($_.Version) -ge $MinimumVersion -and
		[System.Version]($_.Version) -le $MaximumVersion -and
		(-not $RequiredVersion -or $_.Version -eq $RequiredVersion)
	} | ? Location -match ([regex]::Escape($request.Options.Location)) |
	Select * -ExcludeProperty Location | % {
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