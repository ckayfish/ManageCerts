using namespace System.Security.Cryptography.X509Certificates

function Get-CertificateSubject {
    param([Parameter(Mandatory)][string]$Subject)

    $Result = @{}
    [X500DistinguishedName]$Name = $Subject -replace '\"', '"'
    foreach($Item in $Name.Format($true) -split '\r?\n'){
        if(!$Item){ continue }
        $Key, $Value = $Item -split '=', 2
        $Result.Add($Key, $Value)
    }
    return $Result
}