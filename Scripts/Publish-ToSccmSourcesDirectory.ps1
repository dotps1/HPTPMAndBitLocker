#Set directories
$sourceDir="C:\users\tmalkewitz\Documents\GitHub\HpTpmAndBitLocker"
$destinationDir1="\\H101VSCCM001\sources$\Packages\Hope Network\Enforce-Bde"
$destinationDir2="\\h101vsccm001\sources$\PowershellScripts\CustomTasks\Enforce-Bde"

#Set Items to copy
Copy-Item $sourceDir"\Enforce-Bde.ps1" -Destination $destinationDir1
Copy-Item $sourceDir"\Modules\HpTpmAndBitLocker.psd1" -Destination $destinationDir1"\Modules"
Copy-Item $sourceDir"\Modules\HpTpmAndBitLocker.psm1" -Destination $destinationDir1"\Modules"
Copy-Item $sourceDir"\Scripts\New-RandomPassword.ps1" -Destination $destinationDir1"\Scripts"

Copy-Item $sourceDir"\Modules\HpTpmAndBitLocker.psd1" -Destination $destinationDir2"\Modules"
Copy-Item $sourceDir"\Modules\HpTpmAndBitLocker.psm1" -Destination $destinationDir2"\Modules"
Copy-Item $sourceDir"\Scripts\New-RandomPassword.ps1" -Destination $destinationDir2"\Scripts"

#Sign all items
Set-AuthenticodeSignature $destinationDir1"\Enforce-Bde.ps1" -Certificate (dir Cert:\CurrentUser\my\0FF4E6B85B633F2F0030290DB8AF29D978464B24) -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll
Set-AuthenticodeSignature $destinationDir1"\Modules\HpTpmAndBitLocker.psd1" -Certificate (dir Cert:\CurrentUser\my\0FF4E6B85B633F2F0030290DB8AF29D978464B24) -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll
Set-AuthenticodeSignature $destinationDir1"\Modules\HpTpmAndBitLocker.psm1" -Certificate (dir Cert:\CurrentUser\my\0FF4E6B85B633F2F0030290DB8AF29D978464B24) -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll
Set-AuthenticodeSignature $destinationDir1"\Scripts\New-RandomPassword.ps1" -Certificate (dir Cert:\CurrentUser\my\0FF4E6B85B633F2F0030290DB8AF29D978464B24) -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll

Set-AuthenticodeSignature $destinationDir2"\Modules\HpTpmAndBitLocker.psd1" -Certificate (dir Cert:\CurrentUser\my\0FF4E6B85B633F2F0030290DB8AF29D978464B24) -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll
Set-AuthenticodeSignature $destinationDir2"\Modules\HpTpmAndBitLocker.psm1" -Certificate (dir Cert:\CurrentUser\my\0FF4E6B85B633F2F0030290DB8AF29D978464B24) -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll
Set-AuthenticodeSignature $destinationDir2"\Scripts\New-RandomPassword.ps1" -Certificate (dir Cert:\CurrentUser\my\0FF4E6B85B633F2F0030290DB8AF29D978464B24) -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll