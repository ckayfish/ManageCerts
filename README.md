# ManageCerts
PowerShell module and scripts to help manage Server Certificates
# What's the Purpose?
The PowerShell module and scripts included here were created to reduce the effort required to create SSL/TLS Server Certificate Signing Requests (CSRs). Although each CSR doesn’t take much time to create manually, juggling dozens of them was becoming burdensome and I found it an opportunity to automate as much as I could.
# What are the Pre-Requisites?
This project depends on openssl v1.1.1q being available. We don’t distribute it, and we don’t support it. Legacy releases may not respect the cli option “-addext”, which is required to specify SANs
Please keep your runtime version of PowerShell current.
# What does it actually do?
**Get-RemoteCertificate** does a low level TCP request to a (required) domain name using a default port of 443, which can be optionally be specified on the cli. It gathers the certificate details and. returns a custom object.
**ProbeCerts** takes a single hostname, CSV of many names, or a file that includes a list Common Names (CN's), one per line. It will then iterate through each one, and capture the details to a JSON file for future reference, or to share with other systems. Parameters tell the script if it should generate CSRs, and how long before the cert expires that it should do so.

For example, the array of hostnames could include dozens or hundreds of hosts, the script will probe each one, log the details to a JSON file, and create the CSRs & Private Keys for any that expire within the next 30 (or x)  days.
**New-CertificateSigningRequest** uses OpenSSL to generate CSR and private KEY files for a given host (CommonName), Subject, and list of Subject Alternate Names. Basically a wrapper for "openssl req..."

