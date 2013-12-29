function Get-TpmStatus {
    <#
    .SYNOPSIS

    This function is to be used to easily determine the TPM (Trusted Platform Module) Status on a machine.

    Function: Get-TpmStatus
    Author: Thomas Malkewitz MCP, MCDST, CompTIA A+
    Required Dependencies: None
    Optional Dependencies: None
    Version: 0.3 

    .DESCRIPTION

    This function returns true if the TPM is On and Enabled, and false for all other seneros, the -Verbose parameter will provide user friendly STDOUT information.

    .PARAMETER ComputerName

    String.  This is the Computer Name where the Volume is located, default is the local computer running the function.

    .EXAMPLE
    
    Get-TpmStatus

    In this example, the TPM Status is returned of the system drive on the local machine.

    .EXAMPLE 

    Get-TpmStatus -ComputerName "MyComputer.MyDomain.org" -Verbose

    In this example, the TPM Status is returned from a remote computer with user friendly readable information.

    #>
    
    [CmdletBinding()]  
    param 
        (
        [String] $ComputerName = $env:COMPUTERNAME
        )

    if (!(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) {
        Throw 'Unable to connect to ' + $ComputerName + '.  Please ensure the system is available, and that you have sufficent rights to connect to the Remote Windows Management Interface.'
        return $false
        }

    try {
        $tpm = Get-WmiObject -Class Win32_Tpm -Namespace "root\CIMV2\Security\MicrosoftTpm" -ComputerName $ComputerName -ErrorAction Stop
        }
    catch {
        Throw 'Unable to connect to the "Win32_Tpm" Namespace, You may not have sufficent rights.'
        return $false
        }

    if (!($tpm.IsEnabled_InitialValue)) {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "TPM is not Enabled."
            }
        return $false
        }
    elseif (!($tpm.IsActivated_InitialValue)) {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "TPM is Enabled, but not Activated."
            }
        return $false
        }
    else {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "TPM is both Enabled and Activated."
            }
        return $true
        }
    }

function Get-BitLockerStatus {
    <#
    .SYNOPSIS

    This function is to be used to easily determine the BitLocker status of a drive.

    Function: Get-BitLockerStatus
    Author: Thomas Malkewitz MCP, MCDST, CompTIA A+
    Required Dependencies: None
    Optional Dependencies: None
    Version: 0.9 

    .DESCRIPTION

    This function returns true if the Protection Status is ON, and false for all other seneros, the -Verbose parameter will provide friendly STDOUT information.

    .PARAMETER ComputerName

    String.  This is the Computer Name where the Volume is located, default is the local computer running the function.

    .PARAMETER DriveLetter

    String.  This is the Drive Letter to evalute BDE on, default is the System Drive.  (Which is evalutated through, WMI, the $env:SYSTEMDRIVE varible is not used.)

    .EXAMPLE
    
    Get-BitLockerStatus

    In this example, the BDE Status is returned of the system drive on the local machine.

    .EXAMPLE 

    Get-BitLockerStatus -ComputerName "MyComputer.MyDomain.org" -DriveLetter "C:"

    In this example, the BDE Status is returned from the C: drive on remote computer.

    #>
    
    [CmdletBinding()]        
    param
        (
        [String] $ComputerName = $env:COMPUTERNAME,
        [String] $DriveLetter
        )

    if (!(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) {
        Throw 'Unable to connect to ' + $ComputerName + '.  Please ensure the system is available, and that you have sufficent rights to connect to the Remote Windows Management Interface.'
        return $false
        }

    if ([String]::IsNullOrEmpty($DriveLetter)) {
        try {
            $drive = Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -ComputerName $ComputerName -Property SystemDrive -ErrorAction Stop
            $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$($drive.SystemDrive)'" -ComputerName $ComputerName -ErrorAction Stop
            }
        catch {
            Throw 'Unable to connect to the necassary WMI Namespaces, to get the system drive.  Verfy that you have sufficent rights to connect to the "OperationSystem" and "EncryptableVolume" Namespaces.'
            return $false
            }
        }
    else {
        if (!($DriveLetter.Contains(":"))) {
            $DriveLetter = $DriveLetter + ":"
            }
        $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
        if ($volume -eq $null) {
            Throw 'Unable to enumarate the "EncryptableVolume" WMI Namespace for drive ' + $DriveLetter + '.  Please make sure the drive letter is correct and that the volume is accessable.'
            return $false
            }
        }

    $status = $volume.GetConversionStatus()

    if ($VerbosePreference -eq "Continue") {
        switch ($status.ConversionStatus) {
            0 { Write-Host "FullyDecrypted" }
            1 { Write-Host "FullyEncrypted" }
            2 { Write-Host "EncryptionInProgress" -NoNewline; Write-Host "  PercentageComplete: " $status.EncryptionPercentage }
            3 { Write-Host "DecryptionInProgress" -NoNewline; Write-Host "  PercentageComplete: " $status.EncryptionPercentage }
            4 { Write-Host "EncryptionPaused" -NoNewline; Write-Host "  PercentageComplete: " $status.EncryptionPercentage }
            5 { Write-Host "DecryptionPaused" -NoNewline; Write-Host "  PercentageComplete: " $status.EncryptionPercentage }
            }
        }
        
    if ($volume.GetProtectionStatus().ProtectionStatus -eq 0) {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "ProtectionOff"
            }
        return $false
        }
    else {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "ProtectionOn"
            }
        return $true
        }
    }

Export-ModuleMember -Function *