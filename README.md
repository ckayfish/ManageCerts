# ManageCerts
PowerShell module and scripts to help manage Server Certificates
# What's the Purpose?
The PowerShell module(s) and scripts included here were created to reduce the effort required to create SSL/TLS Server Certificate Signing Requests (CSRs),. Although each CSR doesn’t take much time to create manually, juggling dozens of them was becoming more burdensome and I found it an opportunity to automate as much as I could.
# What are the Pre-Requisites?
This project depends on openssl being available. We don’t distribute it, and we don’t support it. Legacy releases may not respect the cli option “-addext”, which is required to specify SANs
Please keep your runtime version of PowerShell current.
# What does it actually do?
**ProbeCerts** takes a single hostname, CSV of many names, or a file that includes a list Common Names (CN's), one per line. It will then iterate through each one, and capture the details to a JSON file for future reference, or to share with other systems. Parameters tell the script if it should generate CSRs, and how long before the cert expires that it should do so.

For example, the array of hostnames could include dozens or hundreds of hosts, the script will probe each one, log the details to a JSON file, and create the CSRs & Private Keys for any that expire within the next 30 (or x)  days.

**CreateNewCsr** generates a CSR for net-new certificates, that takes the CN, Subject details, and a CSV of SANs. If your Subject details are always consistent, you can set them as default parameters.

