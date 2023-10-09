using namespace System.Management.Automation

<#
.SYNOPSIS
Creates a CSR using OpenSSL.

.DESCRIPTION
Creates a Certificate Signing Request (CSR) using OpenSSL while absctracting how parameters are passed given various scenarios.
#>
function New-CertificateSigningRequest {
    param (
        # The CN (Common Name) of the certificte being generated. Added to Subject.
        [Parameter(Mandatory)][Alias('CN')][string]$CommonName,
        # The 2 letter country code. Added to Subject.
        [ValidatePattern('^[A-Za-z]{2}$')][Alias('C')][string]$Country,
        # State/Province.
        [string]$State,
        # The city or other location.
        [string]$Location,
        # Organisation, company, affiliation.
        [string]$Organisation,
        # Array of Subject Alternate Names
        [Alias('SANs')][string[]]$SubjectAlternateName,
        # Output directory for key and cert files.
        [ValidateNotNullOrEmpty()][string]$CSRDirectory = ".",
        # Force generating new CSR files (deletes clobbered paths).
        [switch]$Force
    )

    try {
        $OpenSSL = Get-Command -Name 'openssl.exe' -CommandType Application -ErrorAction Stop
        
        # Check OpenSSL version
        $RawVersion = & $OpenSSL version
        Write-Host "Found $($RawVersion.Trim())"
        [version]$Version = $RawVersion -replace '^OpenSSL (\d+\.\d+\.\d+).*', '$1'
        if($Version -lt '1.1.1'){
            throw "OpenSSL 1.1.1 or greater is not available. Found version: $Version"
        }

        # Generate CSR/Key files + output directory if it doesn't exist.
        if(!(Test-Path -LiteralPath $CSRDirectory -PathType Container)){
            Write-Verbose "Folder ""$CSRDirectory"" does not exist, creating now."
            $null = New-Item -ItemType Directory -LiteralPath $CSRDirectory
        }
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
                Write-Warning "CSR and/or Key file(s) already exist. Please delete or move them before recreating."
                Write-Warning "CSR: File $CSRFilePath"
                Write-Warning "Key: File $KeyFilePath"
                return
            }
        } else {
            Write-Verbose "CSR and private key not found. Creating now..."
        }

        $OpenSSLArguments = @(
            "req -nodes -newkey rsa:2048 -keyout ""$KeyFilePath"" -out ""$CSRFilePath"""
            "-subj ""/CN=$CommonName/C=$Country/ST=$State/L=$Location/O=$Organisation"""
            if($SubjectAlternateName){
                "-addext ""subjectAltName = $($SubjectAlternateName -replace '^', 'DNS:' -join ',')"""
            }
        ) -join " "
        Start-Process -NoNewWindow -Wait -FilePath $OpenSSL.Path -ArgumentList $OpenSSLArguments
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
