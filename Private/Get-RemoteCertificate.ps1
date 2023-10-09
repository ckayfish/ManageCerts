using namespace System.Net
using namespace System.Net.Sockets
using namespace System.Net.Security
using namespace System.Security.Cryptography.X509Certificates

# This class is used to define what information we want to read from active certificates
class Cert {
    [String]$cn                 # Common name for certificate
    [String]$validToString      # Date that cert is valid to (String)
    [DateTime]$validTo          # Date that cert is valid to (DateTime)
    [DateTime]$validFrom        # Date that cert is valid from (DateTime)
    [int]$numCips               # Number of IPs CN/hostname resolves to
    [string[]]$cips             # Array of IPs thats the CN/hostname resolves to
    [int]$numSans               # Number os SANs, not including CN or www.CN
    [string[]]$sans             # Array of SANs, not including CN or www.CN
    [hashtable]$subject=@{}     # Hashtable of Subject keys & values
}

<#
.SYNOPSIS
Probe a certificate and return a object of class Cert.

.DESCRIPTION
Probe a certificate and return a object of class Cert. Takes a required hostname and optional Port,
completes a TCP level request to get the cert, adds the desired details to a cutom Class (systemObject),
and returns that object. 

.EXAMPLE
Get the certificate hosted at the address github.com on port 443
PS C:/> Get-RemoteCertifcate -Hostname github.com

.EXAMPLE
Get the certificate hosted at mydomain.com on TCP 8443
PS C:/> Get-RemoteCertificate -Hostname mydomain.com -Port 8443
#>
function Get-RemoteCertificate {
    param (
        # The hostname that the function should probe.
        [Parameter(Mandatory)][string]$Hostname,
        # TCP port the webserver responds on.
        [int]$Port = 443,
        [SecurityProtocolType]$SecurityProtocols = 'Tls, Tls12'
    )
    
    $Hostname = $Hostname.ToLower()
    try {
        $Addresses = [Dns]::GetHostAddresses($Hostname)
        $TcpClient = [TcpClient]::new()
        $TcpClient.Connect($Hostname, $Port)
        $SslStream = [SslStream]::new($TcpClient.GetStream(), $true, {
            param($send, $cert, $chain, $errs)
            return $true
        })
        $SslStream.AuthenticateAsClient($Hostname, $null, $SecurityProtocols, $false)
        [X509Certificate2]$Certificate = $SslStream.RemoteCertificate
        if(!$Certificate){
            return [pscustomobject]@{
                CommonName = $Hostname
                ResolvedAddresses = $Addresses
                ValidFrom = $null
                ValidTo = $null
                ValidToString = $null
                SANs = @()
                Subject = @{}
            }
        }

        return [pscustomobject]@{
            CommonName = $Hostname
            ResolvedAddresses = $Addresses
            ValidFrom = $Certificate.NotBefore
            ValidTo = $Certificate.NotAfter
            ValidToString = $Certificate.NotAfter.ToString('yyyy-MM-dd')
            SANs = $Certificate.DnsNameList | Where-Object { $_ -ne $Hostname -and $_ -ne "www.$Hostname" }
            Subject = Get-CertificateSubject -Subject $Certificate.Subject
        }
    } catch {
        throw
    } finally {
        if($SslStream){ $SslStream.Dispose() }
        if($TcpClient){ $TcpClient.Dispose() }
    }
}
