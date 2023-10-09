function ProbeCerts {
    <#
       .SYNOPSIS
         Collects SSL cert details from realtime probes, and optionally creates CSRs if they expire within X days
       .EXAMPLE
         ProbeCerts -hosts "google.ca,reddit.com" -gencsr
         This command will do a web request to google.ca & reddit.com to collect their certificate
         details, then generate a JSON output file of desired information. Since -gencsr is selected, create
         a CSR if it expires is less than default number of days. Use -daysleft to specify 
     #>
    param (
        [string]$hosts,
        [string]$hostfile = ".\hostfile.txt",
        [string]$jsonOutFile = ".\logs\certDetails-$((Get-Date -format "yyyyMMddhhmmss")).json",
        [string]$csvOutFile = ".\logs\certDetails-$((Get-Date -format "yyyyMMddhhmmss")).csv",
        [switch]$gencsr,
        [int]$daysleft = 30,
        [string]$csrDir = ".\csrsInProgress"
    )
    
    #Import modules, set path, announce execution, initiate important objects
    Import-Module .\CertsModule\CertsModule.psm1 -Force
    $MyInvocation.MyCommand.Path | Split-Path | Push-Location # Set path to script folder
    Write-Host "Execution Path: $(Get-Location)"
    Write-Host "Starting script: $($MyInvocation.MyCommand.Name)"
    $allCerts = New-Object System.Collections.Generic.List[psobject]
    
    # First get the certificate details into a list of objects
    # Could be for single host or many listed in a file with each host on a seperarte line
    if ($hosts) {
        Write-Host "Using hosts defined in CLI"
        $hosts.Replace(" ","") -Split(",") | ForEach-Object {
            Write-Host "Probing Certificate: $_"
            $allCerts.Add((Get-RemoteCertificate -Hostname $_))
        }
    } else {
        Write-Host "No hostname declared, using hostfile '$hostfile'"
        if (Test-Path -Path $hostfile -PathType Leaf) {
            Get-Content -Path $hostfile | ForEach-Object {
                $thisHost = $_ -replace '\s',''
                Write-Host "Probing Certificate: $thisHost"
                $allCerts.Add((Get-RemoteCertificate -Hostname $thisHost))
            }
        } else {
            Write-Host "Error: `"$hostfile`" not found at $(Get-Location)"
            Write-Host
            exit 1
        }
    }
    $allCerts | Format-Table
    
    Write-Host "Creating JSON of all certificates probed: '$jsonOutFile'"
    $allCerts | Sort-Object -Property validTo | ConvertTo-Json  |  New-Item -Path $jsonOutFile -Force | Out-Null
    # $allCerts | Export-Csv -Path $csvOutFile -NoTypeInformation
    
    #If selected, generate Certificate Signing Requests for certs expiring in X days
    if ($gencsr){
        Write-Host "Looking for certs ready for renewal..."
        $allCerts | ForEach-Object {
            if (!($_.cn -eq $null)) {
                if ((Get-Date).AddDays($daysleft) -gt $_.validTo  ) {
                    Write-Host "The certificate for $($_.cn) expires in $(($_.validTo - (Get-Date)).Days) days."
                    $Parameters = @{
                        CommonName = $_.CommonName
                        Country = $_.Subject.C
                        State = $_.Subject.S
                        Location = $_.Subject.L
                        Organisation = $_.Subject.O
                        SubjectAlternateName = $_.SANs
                        CSRDirectory = $csrDir
                    }
                    New-CertificateSigninfRequest @Parameters
                }
            }
        }
    }
}
