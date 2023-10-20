##################################################################################
#
# This module assists in managing SSL Certificates and their Signing Requests
# https://github.com/ckayfish/ManageCerts
#
##################################################################################
# Requires PoSH -Version 5.1+
# TODO Confirm which PoSH versions support or not

$Functions = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )
$Functions = $Functions + @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue )

# Dot Source the files
Foreach($Import in @($Functions)) {
    try {
        Write-Information "Importing $($Import.fullname)"
        . $Import.fullname
    }
    catch {
        Write-Error -Message "Failed to import function $($Import.fullname): $_"
    }
}