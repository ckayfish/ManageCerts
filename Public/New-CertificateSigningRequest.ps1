using namespace System.Management.Automation

<#
.SYNOPSIS
Creates a CSR and Private Key for for an SSL/TLS Server Certificate.

.DESCRIPTION
This command will create a CSR and private key for the CommonName (cn) provided. It will use
the default Country, State/Province, Locality/City, and organization if not specified. The
Subject Alternate Names (-SubjectAlternateName) can be passed as a comma-separated string

```powershell
-SubjectAlternateName "name1.alt.net, name2.alt.net"
```

or as an array of strings

```powershell
-SubjectAlternateName name1.alt.net, name2.alt.net
```

.EXAMPLE
Create a new CSR and key file for "mynewwebsite.com" in the default directory "CSRsInProgress" at the root of the module.
PS C:\> New-CertificateSigningRequest -CommonName mynewwebsite.com
#>
function New-CertificateSigningRequest {
    [CmdletBinding()]
    param (
        # The CN (Common Name) of the certificte being generated. Added to Subject.
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][Alias('CN')][string]$CommonName,
        # The 2 letter country code. Added to Subject.
        [Parameter(ValueFromPipelineByPropertyName)][ValidatePattern('^[A-Za-z]{0,2}$')][Alias('C')][string]$Country,
        # State/Province.
        [Parameter(ValueFromPipelineByPropertyName)][string]$State,
        # The city or other location.
        [Parameter(ValueFromPipelineByPropertyName)][string]$Locality,
        # Organisation, company, affiliation.
        [Parameter(ValueFromPipelineByPropertyName)][string]$Organisation,
        # Array of Subject Alternate Names
        [Parameter(ValueFromPipelineByPropertyName)][Alias('SANs')][string[]]$SubjectAlternateName,
        # Output directory for key and cert files.
        [ValidateNotNullOrEmpty()][string]$CSRDirectory = "./CsrsInProgress",
        # Force generating new CSR files (deletes clobbered paths).
        [switch]$Force
    )

    begin {
        $OpenSSL = Get-Command -Name 'openssl.exe' -CommandType Application -ErrorAction Stop
        
        # Check OpenSSL version
        $RawVersion = & $OpenSSL version
        Write-Host "Found $($RawVersion.Trim())"
        [version]$Version = $RawVersion -replace '^OpenSSL (\d+\.\d+\.\d+).*', '$1'
        if($Version -lt '1.1.1'){
            throw "OpenSSL 1.1.1 or greater is not available. Found version: $Version"
        }

        # Generate CSR/Key output directory if it doesn't exist.
        if(!(Test-Path -LiteralPath $CSRDirectory -PathType Container)){
            Write-Verbose "Folder ""$CSRDirectory"" does not exist, creating now."
            $null = New-Item -ItemType Directory -Path $CSRDirectory
        }
    }

    process {
        if($SubjectAlternateName.Count -eq 1 -and $SubjectAlternateName[0] -like '*,*'){
            Write-Verbose "Splitting SubjectAlternateName (appears to be an array string)"
            $SubjectAlternateName = $SubjectAlternateName -split ',' | ForEach-Object Trim | Where-Object { $_ }
        }
        try {
            $CSRFilePath = Join-Path -Path $CSRDirectory -ChildPath "$CommonName.csr"
            $KeyFilePath = Join-Path -Path $CSRDirectory -ChildPath "$CommonName.key"
    
            #If CSR or key file already exists, do not overwrite unless -Force'd
            if($true -in @(Test-Path -LiteralPath $CSRFilePath, $KeyFilePath)){
                if($Force){
                    if(Test-Path -LiteralPath $CSRFilePath){
                        Remove-Item -LiteralPath $CSRFilePath -Force -ErrorAction Stop
                    }
                    if(Test-Path -LiteralPath $KeyFilePath){
                        Remove-Item -LiteralPath $KeyFilePath -Force -ErrorAction Stop
                    }
                    Write-Verbose "CSR and/or private key removed. Creating new CSR and private key..."
                } else {
                    Write-Warning "CSR and/or Key file(s) already exist. Please delete or move them before recreating, or use -Force to overwrite"
                    Write-Warning "CSR: File $CSRFilePath"
                    Write-Warning "Key: File $KeyFilePath"
                    return
                }
            } else {
                Write-Verbose "CSR and private key not found. Creating now..."
            }
    
            $OpenSSLArguments = @(
                "req -nodes -newkey rsa:2048 -keyout ""$KeyFilePath"" -out ""$CSRFilePath"""
                "-subj ""/CN=$CommonName/C=$Country/ST=$State/L=$Locality/O=$Organisation"""
                if($SubjectAlternateName){
                    "-addext ""subjectAltName = $($SubjectAlternateName -replace '^', 'DNS:' -join ',')"""
                }
            ) -join " "
            Start-Process -NoNewWindow -Wait -FilePath $OpenSSL.Path -ArgumentList $OpenSSLArguments | Out-Host
            Write-Verbose "Arguments sent to openssl.exe: $OpenSSLArguments"
            Write-Verbose "Done creating cert ""$CommonName"" using above arguments."
            return [pscustomobject]@{
                CSRPath = $CSRFilePath
                KeyPath = $KeyFilePath
            }
        } catch [CommandNotFoundException] {
            throw [CommandNotFoundException]::new("openssl.exe was not found in your path. Please make sure OpenSSL is installed and available.", $_)
        } catch {
            throw
        }
    }
}