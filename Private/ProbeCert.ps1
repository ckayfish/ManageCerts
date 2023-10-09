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
 .Synopsis
  Probe a certificate and return a object of class Cert.
 .Description
  Probe a certificate and return a object of class Cert. Takes a required hostname and optional Port,
  completes a TCP level request to get the cert, adds the desired details to a cutom Class (systemObject),
  and returns that object. 
 .Parameter Hostname
  Required. The hostname that the function should probe.
 .Parameter Port
  Optional, defaults to 443. TCP port the webserver responds on.
 .Example
   # Get the certificate hosted at the address github.com on port 443
   ProbeCert -hostname github.com
 .Example
   # Get the certificate hosted at mydomain.com on TCP 8443
   ProbeCert -hostname mydomain.com -port 8443
#>
function ProbeCert{
    param (
        [Parameter(Mandatory)]
        [string]$Hostname,
        [int]$Port = 443
    )
    if ($HostName)  { $HostName = $HostName.ToLower() }
    $certInst=[Cert]::new()
    $certInst.cn = $HostName
    $error.Clear()
    # Confirm DNS Lookup
    try
        {$ips = [System.Net.Dns]::GetHostAddresses($HostName) }
    catch
        { return 2 }
    if (!$error) {
        $certInst.NumCips = $ips.Length
        $certInst.cips=$ips
        $Certificate = $null
        $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
        try {
            $TcpClient.Connect($HostName, $Port)
            $TcpStream = $TcpClient.GetStream()
            $Callback = { param($sender, $cert, $chain, $errors) return $true }
            $SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)
            try {
                $SslStream.AuthenticateAsClient($HostName, $null, [System.Net.SecurityProtocolType]'Tls, Tls12', $false )
                $Certificate = $SslStream.RemoteCertificate
            } finally {
                $SslStream.Dispose()
            }
        } finally {
            $TcpClient.Dispose()
        }
        if ($Certificate) {
            if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                $Certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Certificate
            }
            $certInst.validFrom = $Certificate.NotBefore
            $certInst.validTo = $Certificate.NotAfter
            $certInst.validToString = $Certificate.NotAfter.ToString("yyyy-MM-dd")
            [String[]]$altNames = $Certificate.DnsNameList
            $certInst.sans = $altNames | Where-Object { $_ -ne "www.$($Hostname)" -and $_ -ne $Hostname }
            $certInst.numSans = $certInst.sans.Count
            # Split subject into hashtable accounting for values with a comma. Eg: O=\"REDDIT, INC.\"
            $dn = [X500DistinguishedName]::new($Certificate.Subject.Replace('\"', '"'))
            $dn.Format($true).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object {
                $key, $value = $_.Split('=',2)
                $certInst.subject.Add("$key","$value")
            }
        }
    }
    return $certInst
}
