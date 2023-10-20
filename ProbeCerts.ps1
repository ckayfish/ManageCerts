<#
Alternatives to this script calling the module functions directly, including:
 *Get-RemoteCertificate
 *New-CertificateSigningRequest:

Instead of ProbeCerts.ps1 -Host "google.com, reddit.com" -JsonOutFile $JsonPath:

    Get-RemoteCertificate google.com, reddit.com | ConvertTo-Json > $JsonPath

Instead of ProbeCerts.ps1 -HostFile "hosts.txt" -gencsr

    Get-Content hosts.txt |
        Get-RemoteCertificate |
        Where-Object ExpiresIn -lt '30.0:0' |
        New-CertificateSigningRequest

Instead of ProbeCerts.ps1 -Hosts google.com -JsonOutfile $JsonPath -gencsr

    $Certs = Get-RemoteCertificate google.com
    $Certs | ConvertTo-Json > $JsonPath
    $Certs | Where-Object ExpiresIn -lt '30.0:0' | New-CertificateSigningRequest
#>

<#
    .SYNOPSIS
        Collects SSL cert details from realtime probes, and optionally create CSRs if they expire within X days
    .EXAMPLE
        ProbeCerts -hosts "google.ca,reddit.com" -gencsr

        This command will do a TCP request to collect certificates from the mentioned URIs
        then generate a JSON output file of the desired information. Since -gencsr is selected,
        we will create a CSR if it expires in less than a default number of days. Use -daysleft to specify 
    #>
[CmdletBinding(DefaultParameterSetName='ByHosts')]
param (
    [Parameter(ParameterSetName='ByHosts')][string[]]$Hosts = "google.com",
    [Parameter(ParameterSetName='ByFile')][string]$HostFile,
    [string]$JsonOutFile = ".\logs\certDetails-$(Get-Date -format "yyyyMMddhhmmss").json",
    [switch]$gencsr,
    [int]$DaysLeft = 30,
    [string]$csrDir = ".\CsrsInProgress"
)

Import-Module '.\ManageCerts.psd1' -Force
Write-Host "Execution Path: $(Get-Location)"
Write-Host "Starting script: $($MyInvocation.MyCommand.Name)"

try {
    $csrDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("$PSScriptRoot/$csrDir")
    if($HostFile){
        Write-Verbose "Reading hosts from file: $HostFile"
        $Hosts = Get-Content -Path $HostFile -ErrorAction Stop |
            Where-Object { $_ -and $_ -notlike '#*' } |
            ForEach-Object Trim
    } elseif($Hosts.Count -eq 1 -and $Hosts[0] -like '*,*'){
        Write-Verbose "Hosts appears to be a comma-separated string, splitting."
        $Hosts = $Hosts[0] -split ',' | ForEach-Object Trim
    }

    Write-Host "Creating JSON of all certificates probed: '$jsonOutFile'"
    $AllCertificates = Get-RemoteCertificate -HostName $Hosts
    $AllCertificates | Format-Table
    $null = $AllCertificates |
        Sort-Object -Property ValidTo |
        ConvertTo-Json |
        New-Item -Path $JsonOutFile -Force

    #If selected, generate Certificate Signing Requests for certs expiring in X days
    if($gencsr){
        $TimeRemaining = New-TimeSpan -Days $DaysLeft
        $AllCertificates |
            Where-Object ExpiresIn -lt $TimeRemaining |
            ForEach-Object {
                Write-Host "The certificate for $($_.CommonName) expires in $($_.ExpiresIn.Days) days."
                $_
            } |
            New-CertificateSigningRequest -CSRDirectory $csrDir
    }
} catch {
    throw
} finally {
    Pop-Location
}
