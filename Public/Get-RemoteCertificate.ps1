using namespace System.Net
using namespace System.Net.Sockets
using namespace System.Net.Security
using namespace System.Security.Cryptography.X509Certificates

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
        # The hostname(s) to probe.
        [Parameter(Mandatory,ValueFromPipeline)][string[]]$HostName,
        # TCP port the webserver(s) respond on.
        [int]$Port = 443,
        # The security protocols to use for retrieving the certificate.
        [SecurityProtocolType]$SecurityProtocols = 'Tls, Tls12'
    )

    process {
        foreach($Name in $HostName){
            $Name = $Name.ToLower()
            try {
                $Addresses = [Dns]::GetHostAddresses($Name)
                $TcpClient = [TcpClient]::new()
                $TcpClient.Connect($Name, $Port)
    
                $SslStream = [SslStream]::new($TcpClient.GetStream(), $true, {
                    param($send, $cert, $chain, $errs)
                    return $true
                })
                $SslStream.AuthenticateAsClient($Name, $null, $SecurityProtocols, $false)
    
                [X509Certificate2]$Certificate = $SslStream.RemoteCertificate
                if(!$Certificate){
                    return [pscustomobject]@{
                        CommonName = $Name
                        ResolvedAddresses = $Addresses
                        ValidFrom = $null
                        ValidTo = $null
                        ValidToString = $null
                        SANs = @()
                        Subject = @{}
                    }
                }
    
                $Subject = Get-CertificateSubject -Subject $Certificate.Subject
                [pscustomobject]@{
                    CommonName = $Name
                    Country = $Subject.C
                    State = $Subject.S
                    Location = $Subject.L
                    Organisation = $Subject.O
                    SANs = $Certificate.DnsNameList | Where-Object { $_ -ne $Name -and $_ -ne "www.$Name" }
    
                    ResolvedAddresses = $Addresses
                    ValidFrom = $Certificate.NotBefore
                    ValidTo = $Certificate.NotAfter
                    ValidToString = $Certificate.NotAfter.ToString('yyyy-MM-dd')
                    ExpiresIn = $Certificate.NotAfter - [datetime]::Now
                }
            } catch {
                throw
            } finally {
                if($SslStream){ $SslStream.Dispose() }
                if($TcpClient){ $TcpClient.Dispose() }
            }
        }
    }
}
