function Get-BitLockerStatus {
    <#
    .SYNOPSIS

    This function is to be used to easy determine the BitLocker status of a drive.

    Function: Get-BitLockerStatus
    Author: Thomas Malkewitz MCP, MCDST, CompTIA A+
    Required Dependencies: None
    Optional Dependencies: None
    Version: 0.9 

    .DESCRIPTION

    This function is for User Friendly STDOUT of the BitLocker Drive Encryption (BDE) of a drive.  No values are returned, only Write-Host values of the BDE Status.

    .PARAMETER ComputerName

    String.  This is the Computer Name where the Volume is located, default is the local computer running the function.

    .PARAMETER DriveLetter

    String.  This is the Drive Letter to evalute BDE on, default is the System Drive.  (Which is evalutated through, WMI, the $env:SYSTEMDRIVE varible is not used.)

    .EXAMPLE

    Get-BitLockerStatus -ComputerName $env:COMPUTERNAME

    .EXAMPLE

    Get-BitLockerStatus -ComputerName "MyComputer.MyDomain.org" -DriveLetter "C:"

    #>
    
    [CmdletBinding()]        
    param
        (
        [String] $ComputerName = $env:COMPUTERNAME,
        [String] $DriveLetter
        )

    if (!(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) {
        Throw 'Unable to connect to ' + $ComputerName + '.  Please ensure the system is available, and that you have sufficent rights to connect to the Remote Windows Management Interface.'
        }

    if ([String]::IsNullOrEmpty($DriveLetter)) {
        try {
            $drive = Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -ComputerName $ComputerName -Property SystemDrive -ErrorAction Stop
            $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$($drive.SystemDrive)'" -ComputerName $ComputerName -ErrorAction Stop
            }
        catch {
            Throw 'Unable to connect to the necassary WMI Namespaces, to get the system drive.  Verfy that you have sufficent rights to connect to the "OperationSystem" and "EncryptableVolume" Namespaces.'
            }
        }
    else {
        if (!($DriveLetter.Contains(":"))) {
            $DriveLetter = $DriveLetter + ":"
            }
        $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
        if ($volume -eq $null) {
            Throw 'Unable to enumarate the "EncryptableVolume" WMI Namespace for drive ' + $DriveLetter + '.  Please make sure the drive letter is correct and that the volume is accessable.'
            }
        }

    $status = $volume.GetConversionStatus()
    switch ($status.ConversionStatus) {
        0 { Write-Host "FullyDecrypted"; Write-Host "ProtectionOff" }
        1 { Write-Host "FullyEncrypted"; if ($volume.ProtectionStatus -eq 1) { Write-Host "ProtectionOn" }; else { Write-Host "ProtectionOff" } }
        2 { Write-Host "EncryptionInProgress" -NoNewline; Write-Host "  PercentageComplete: " $status.EncryptionPercentage; Write-Host "ProtectionOff" }
        3 { Write-Host "DecryptionInProgress" -NoNewline; Write-Host "  PercentageComplete: " $status.EncryptionPercentage; Write-Host "ProtectionOff" }
        4 { Write-Host "EncryptionPaused" -NoNewline; Write-Host "  PercentageComplete: " $status.EncryptionPercentage; Write-Host "ProtectionOff" }
        5 { Write-Host "DecryptionPaused" -NoNewline; Write-Host "  PercentageComplete: " $status.EncryptionPercentage; Write-Host "ProtectionOff" }
        }
    }

Export-ModuleMember -Function *