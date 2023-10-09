<#
   .SYNOPSIS
   Create CSR & Private Key for net-new server certificate
   .EXAMPLE
   CreateCSR -cn mynewwebsite.com
   This command will create a CSR and private key for the hostname (-cn) provided. It will use
   the default Country, State/Province, Location/City, and organization if not specified. The
   Subject Alternate Names (-sans) can be passed as a CSV string. Eg: -san "name1.alt.net, name2.alt.net"
#>

param (
    [string]$cn = '',                               # Common name/hostname
    [string]$c = 'CA',                              # 2 letter country code
    [string]$st = 'British Columbia',               # State/Province 
    [string]$loc = 'Victoria',                      # Location (City)
    [string]$org= 'Province of British Columbia',   # Organisation
    [string]$sans = '',                             # CSV of Subject Alternate Names
    [string]$csrDir = '.\csrsInProgress'            # Directory where generated CSRs and keys are stored
)

#Import modules, set path, initiate important objects
Import-Module .\CertsModule\CertsModule.psm1 -Force
$MyInvocation.MyCommand.Path | Split-Path | Push-Location # Set path to script folder

if ($cn) {
    if ($sans) {
        $sansArray=$sans.Replace(' ','') -Split(",")
        Write-Host "Using SANs: $($sansArray -join ',')"
    } else {
        Write-Host "No SANs (alternate names) provided."
    }
    # Check function parameters in module file to ensure you are passing them the right order.
    # Should be: Common Name, Country (2 letter code), State, Location, Organisation, and array of SAN's
    CreateCsr $cn $c $st $loc $org $sansArray $csrDir
} else {
    Write-Host "-cn (Common Name) not defined. cn = '$cn'"
}
