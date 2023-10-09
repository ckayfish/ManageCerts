# ManageCerts
PowerShell module and scripts to help manage Server Certificates
# What's the Purpose?
The PowerShell module(s) and scripts included here were created to reduce the effort required to create SSL/TLS Server Certificate Signing Requests (CSRs), as well as net-net CSRs, using openssl. Althoug each CSR doesnt take much time to create manually, jugelling dones of them was becoming more burdensome and I found it an opportunity to automate as much as I could.
# What does it actually do?
My certificates expire annualy (by policy), and I had all the details documents (subject, alternate names, etc) to generate a CSR, but it included a lot of copy/pasta. Originally I was going to script generating them for a file I had, but I realized I could do one better. I have a simple text file that includes all on the Common Names (CN's), one per line, and a script that iterates through each one, and captures the details I want to a JSON file for future refference or to share with other systems. Parameters tell the script if it should generate CSRs, and how long before the cert expires (default of 30 days for me).

For example, the hostsfile could include dozens or hundreds of hosts/CN's, the script will probe each one, log the details to a JSON file, and create CSRs and private keys for any that expire within the next 30 days. The CSR's can then be emailed to the team who manages the relationship with a certificate authority who generates the certificate and sends it back to me.

There is also currently a function that can be used to generate CSRs for net-new certificates, that takes the CN, subject deatils, and a list of SANs. If your subject details are always consistant you can set them as default parameters to save time
