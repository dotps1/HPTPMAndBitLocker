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

    .LINKS

    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376484%28v=vs.85%29.aspx

    #>
    
    [CmdletBinding()]  
    param 
        (
        [String]$ComputerName = $env:COMPUTERNAME
        )

    if (!(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) {
        Write-Error 'Unable to connect to ' + $ComputerName + '.  Please ensure the system is available, and that you have sufficent rights to connect to the Remote Windows Management Interface.'
        return $false
        }

    try {
        $tpm = Get-WmiObject -Class Win32_Tpm -Namespace "root\CIMV2\Security\MicrosoftTpm" -ComputerName $ComputerName -ErrorAction Stop
        }
    catch {
        Write-Error 'Unable to connect to the "Win32_Tpm" Namespace, You may not have sufficent rights.'
        return $false
        }

    if (!($tpm.IsEnabled_InitialValue)) {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "TPM is not Enabled."
            return
            }
        return $false
        }
    elseif (!($tpm.IsActivated_InitialValue)) {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "TPM is Enabled, but not Activated."
            return
            }
        return $false
        }
    else {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "TPM is both Enabled and Activated."
            return
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

    .LINKS

    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376483%28v=vs.85%29.aspx

    #>
    
    [CmdletBinding()]        
    param
        (
        [String]$ComputerName = $env:COMPUTERNAME,
        [String]$DriveLetter
        )

    if (!(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) {
        Write-Error 'Unable to connect to ' + $ComputerName + '.  Please ensure the system is available, and that you have sufficent rights to connect to the Remote Windows Management Interface.'
        return $false
        }

    if ([String]::IsNullOrEmpty($DriveLetter)) {
        try {
            $drive = Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -ComputerName $ComputerName -Property SystemDrive -ErrorAction Stop
            $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$($drive.SystemDrive)'" -ComputerName $ComputerName -ErrorAction Stop
            }
        catch {
            Write-Error 'Unable to connect to the necassary WMI Namespaces, to get the system drive.  Verfy that you have sufficent rights to connect to the "OperatingSystem" and "EncryptableVolume" Namespaces.'
            return $false
            }
        }
    else {
        if (!($DriveLetter.EndsWith(":"))) {
            $DriveLetter = $DriveLetter + ":"
            }
        if ($DriveLetter.Length -gt 2) {
            Write-Error 'The DriveLetter Paramter must be formated with a single letter, followed by the ":" character.'
            return $false
            }

        $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
        if ($volume -eq $null) {
            Write-Error 'Unable to enumarate the "EncryptableVolume" WMI Namespace for drive ' + $DriveLetter + '.  Please make sure the drive letter is correct and that the volume is accessable.'
            return $false
            }
        }

    $status = $volume.GetConversionStatus()

    if ($VerbosePreference -eq "Continue") {
        switch ($status.ConversionStatus) {
            0 { Write-Host "FullyDecrypted" }
            1 { Write-Host "FullyEncrypted" }
            2 { Write-Host "EncryptionInProgress"; Write-Host "PercentageComplete: " $status.EncryptionPercentage }
            3 { Write-Host "DecryptionInProgress"; Write-Host "PercentageComplete: " $status.EncryptionPercentage }
            4 { Write-Host "EncryptionPaused"; Write-Host "PercentageComplete: " $status.EncryptionPercentage }
            5 { Write-Host "DecryptionPaused"; Write-Host "PercentageComplete: " $status.EncryptionPercentage }
            }
        }
        
    if ($volume.GetProtectionStatus().ProtectionStatus -eq 0) {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "ProtectionOff"
            return
            }
        return $false
        }
    else {
        if ($VerbosePreference -eq "Continue") {
            Write-Host "ProtectionOn"
            return
            }
        return $true
        }
    }

function Invoke-BitLockerWithTpmAndNumricalProtectors {
        <#
    .SYNOPSIS

    This function is to be used to Enable or Resume BitLocker with Key and TPM Key Protectors

    Function: Invoke-BitLockerWithTpmAndNumricalProtectors
    Author: Thomas Malkewitz MCP, MCDST, CompTIA A+
    Required Dependencies: None
    Optional Dependencies: None
    Version: 0.2 

    .DESCRIPTION

    This fuction will do up to five things: 
    1. If the TPM is not owned, it will take ownership and use a randomly generated 15 character password to do so.
    2. If the NumricalPasswordKeyProtector is empty, it will assign one.
    3. If the TPMKeyProtector is empty, it will assign one.
    4. The NumricalPasswordKeyProtector.ProtectorID can be backup up to the Active Directory Object.  GPOs need to be inplace for this to work.
    5. Will begin, or resume BitLocker Encryption.

    .PARAMETER ComputerName

    String.  This is the Computer Name where the Volume is located, default is the local computer running the function.

    .PARAMETER DriveLetter

    String.  This is the Drive Letter to evalute BDE on, default is the System Drive.  (Which is evalutated through, WMI, the $env:SYSTEMDRIVE varible is not used.)

    .PARAMETER ADKeyBackup

    Switch.  If set to true, it will attempt to back up the NumricalPasswordKeyProtector to the AD Object.  Default value is true.

    .EXAMPLE
    
    Invoke-BitLockerWithTpmAndNumricalProtectors

    In this example, BitLocker will be triggered on the local machine.

    .EXAMPLE 

    Invoke-BitLockerWithTpmAndNumricalProtectors -ComputerName "MyComputer.MyDomain.org" -DriveLetter "F:" -ADKeyBackup $false

    In this example, BitLocker will be triggered on the remote machine, for Drive "F:" and the key password will NOT be backup to AD.

    #>
    
    [CmdletBinding()]  
    param
        (
        [String]$ComputerName = $env:COMPUTERNAME,
        [String]$DriveLetter,
        [Switch]$ADKeyBackup = $true
        )

    if (!(Get-TpmStatus -ComputerName $ComputerName)) {
        throw 'TPM is currently not Enabled, Activated or Both.  Use the Get-TpmStatus -Verbose cmdlet to investigate the TPMs current Phyisical State.'
        }

    $tpm = Get-WmiObject -Class Win32_Tpm -Namespace "root\CIMV2\Security\MicrosoftTpm" -ComputerName $ComputerName -ErrorAction Stop
    if (!($tpm.IsOwned_InitialValue)) {
        $charArray = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray()
        $random = [String]::Empty()
        for ($x = 0; $x -lt 15; $x++) {
            $random += $charArray | Get-Random
            }
        
        $tpm.TakeOwnership($tpm.ConvertToOwnerAuth($random).OwnerAuth)
        }

    if ([String]::IsNullOrEmpty($DriveLetter)) {
        try {
            $drive = Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -ComputerName $ComputerName -Property SystemDrive -ErrorAction Stop
            $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$($drive.SystemDrive)'" -ComputerName $ComputerName -ErrorAction Stop
            }
        catch {
            throw 'Unable to connect to the necassary WMI Namespaces, to get the system drive.  Verfy that you have sufficent rights to connect to the "OperationSystem" and "EncryptableVolume" Namespaces.'
            }
        }
    else {
        if (!($DriveLetter.EndsWith(":"))) {
            $DriveLetter = $DriveLetter + ":"
            }
        if ($DriveLetter.Length -gt 2) {
            throw 'The DriveLetter Paramter must be formated with a single letter, followed by the ":" character.'
            }

        $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
        if ($volume -eq $null) {
            throw 'Unable to enumarate the "EncryptableVolume" WMI Namespace for drive ' + $DriveLetter + '.  Please make sure the drive letter is correct and that the volume is accessable.'
            }
        }

    if (!($volume.GetKeyProtectors(3).VolumeKeyProtectorID)) {
        $volume.ProtectKeyWithNumericalPassword()
        if ($ADKeyBackup) {
            try {
                $volume.BackupRecoveryInformationToActiveDirectory($volume.GetKeyProtectors(3).VolumeKeyProtectorID)
                }
            catch {
                throw 'There was an error backing up the information to AD DS, please use the Get-Help Invoke-BitLockerWithTpmAndNumricalProtectors cmdlet and verify all settings are correct to use this function.'
                }
            }
        }
    if (!($volume.GetKeyProtectors(1).VolumeKeyProtectorID)) {
        $volume.ProtectKeyWithTPM()
        }

    switch ($volume.GetConversionStatus().ConversionStatus) {
        0 { $volume.Encrypt() }
        1 { if ($volume.ProtectionStatus -eq 0) { $volume.EnableKeyProtectors() } }
        4 { $volume.ResumeConversion() }
        }
    }

Export-ModuleMember -Function *