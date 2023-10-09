@{
    RootModule = 'ManageCerts.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'f8fc3f69-32a5-4275-a376-9af29bb46bd2'
    Author = 'ckayfish and cofl'
    Description = 'SSL/TSL CSR generation'

    FunctionsToExport = @(
        'CreateNewCsr'
        'Get-RemoteCertificate'
    )
}
