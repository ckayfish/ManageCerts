foreach($File in Get-ChildItem -File -Path "$PSScriptRoot/Private/*.ps1"){
    . $File.FullName
}
foreach($File in Get-ChildItem -File -Path "$PSScriptRoot/Public/*.ps1"){
    . $File.FullName
}
