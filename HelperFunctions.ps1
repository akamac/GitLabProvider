function Dump-InstalledPackages {
	$script:InstalledPackages | ConvertTo-Json |
	Out-File $script:InstalledPackagesPath -Force
}

function Dump-RegisteredPackageSources {
	$script:RegisteredPackageSources | Select * -ExcludeProperty Headers | ConvertTo-Json |
	Out-File $script:RegisteredPackageSourcesPath -Force
}

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
		}
	}
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