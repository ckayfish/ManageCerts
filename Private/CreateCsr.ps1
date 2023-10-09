<#
 .Synopsis
  Creates a CSR using OpenSSL. 
 .Description
  Creates a Certificate Signing Request (CSR) using OpenSSL while absctracting how parameters are passed given various scenarios.
 .Parameter cn
  Required. The CN (Common Name) of the certificte being generated. Added to Subject.
 .Parameter c
  Optional. The 2 letter country code. Added to Subject.
 .Parameter st
  Optional. State/Province.
 .Parameter loc
  Optional. The city or other location.
 .Parameter org
  Optional. Organisation, company, affiliation.
 .Parameter sans
  Optional. Array of strings for each SAN.
 .Example
  # Get the certificate hosted at the address github.com on port 443
  ProbeCert -hostname github.com
 .Example
   # Get the certificate hosted at mydomain.com on TCP 8443
   ProbeCert -hostname mydomain.com -port 8443
#>
function CreateCsr {
    param (
        [Parameter(Mandatory)]
        [string]$cn,
        [string]$c,
        [string]$st,
        [string]$loc,
        [string]$org,
        [string[]]$sans,
        [string]$csrDir
    )
    # Requires openssl to exist in the envornment path.
    # TODO Confirm version is >= v1.1.1 to support the -addext parameter required to include SANs
    $osscmd = "openssl.exe"
    if (!(Get-Command $osscmd -ErrorAction SilentlyContinue)) { 
        Write-Host "Unable to find $osscmd in your path."
        return 1
    } else {
        Write-Host "$osscmd found in your path. If there are problems generating CSR's, please ensure you are using v1.1.1 or greater."
        & $osscmd version
    }
    #Set csr and key file names, taking into consideration the defined path.
    $csrFile="$cn.csr"
    $keyFile="$cn.key"
    if ($csrDir) {
        $csrFile="$csrDir\$csrFile"
        $keyFile="$csrDir\$keyFile"
    }
    #Create folder if it doesnt exist
    if (!(Test-Path $csrDir -PathType Container)) {
        Write-Host "Folder '$csrDir' does not exist, creating now."
        $null = New-Item -ItemType Directory -Force -Path $csrDir
    }
    #If CSR or key file already exists, do not overwrite
    if (!((Test-Path -Path $csrFile -PathType Leaf) -or (Test-Path -Path $keyFile -PathType Leaf))) {
        Write-Host "CSR and private key not found. Creating now..."
        $osslArgs = "req -nodes -newkey rsa:2048 -keyout $keyFile -out $csrFile -subj `"/CN=$cn/C=$c/ST=$st/L=$loc/O=$org`""
        if ($sans.Count -gt 0) {
           [String]$altNames = $sans | ForEach-Object {"DNS:$($_),"}
           $altNames = $altNames.Substring(0,$altNames.Length-1)
           $osslArgs= "$osslArgs -addext `"subjectAltName = $altNames`""
        }
        Start-Process -NoNewWindow -Wait "openssl" -ArgumentList $osslArgs
        Write-Host "Arguments sent to openssl.exe: $osslArgs"
        Write-Host "Done creating cert '$cn' using above arguments. Keyfile: $keyFile, CsrFile: $csrFile"
    } else {
        Write-Host "CSR and/or Key file(s) already exist. Please delete or move them before recreating."
        Write-Host "CSR: File $csrFile"
        Write-Host "Key: File $keyFile"
    }
}
