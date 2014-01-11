<#
.Synopsis
   Get the current status of the TPM.
.DESCRIPTION
   Tests the status of the Trusted Platform Module, only returns true if both enabled and activated.
.EXAMPLE
   Get-TpmStatus
.EXAMPLE
   Get-TpmStatus -ComputerName "mycomputer.mydomain.org" -Verbose
.NOTES
    Usethe -Verbose switch for user friendly STDOUT.
.LINKS
    https://github.com/necromorph1024/BitLockerPowershellModule
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376484%28v=vs.85%29.aspx
#>
function Get-TpmStatus {
    
    [CmdletBinding()]
    [OutputType([bool])]
    Param 
    (
        # ComputerName, Type string, System to evaluate TPM against.
        [Parameter(Mandatory=$false,
                   Position=0)]
        [string]
        $ComputerName=$env:COMPUTERNAME
    )

    Begin
    {
        if (-not(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) 
        {
            Write-Error "Unable to connect to $ComputerName.  Please ensure the system is available."
            return $false
        }
    }
    Process
    {
        try 
        {
            $tpm=Get-WmiObject -Class Win32_Tpm -Namespace "root\CIMV2\Security\MicrosoftTpm" -ComputerName $ComputerName -ErrorAction Stop
        }
        catch 
        {
            Write-Error "Unable to connect to the Win32_Tpm Namespace, You may not have sufficent rights."
            return $false
        }
    }
    End
    {
        if (-not($tpm.IsEnabled_InitialValue)) 
        {
            if ($VerbosePreference -eq "Continue") 
            {
                Write-Host "TPM is not Enabled."
                return
            }
            return $false
        }
        elseif (-not($tpm.IsActivated_InitialValue)) 
        {
            if ($VerbosePreference -eq "Continue") 
            {
                Write-Host "TPM is Enabled, but not Activated."
                return
            }
            return $false
        }
        else 
        {
            if ($VerbosePreference -eq "Continue") 
            {
                Write-Host "TPM is both Enabled and Activated."
                return
            }
            return $true
        }
    }
}

<#
.Synopsis
    Gets the current status of BitLocker.
.DESCRIPTION
    Tests the current status of BitLocker Drive Encryption on an Encryptable Volume.  Only returns true if the volume is fully encrypted and the protection status is on.
.EXAMPLE
    Get-BitLockerStatus
.EXAMPLE
    Get-BitLockerStatus -ComputerName "mycomputer.mydomain.com" -DriveLetter C: -Verbose
.NOTES
    If no drive letter is specified, the default system drive will be used.
    The drive letter must be followed with a double colon ":".
    Use the -Verbose switch for user friendly STDOUT.
.LINKS
    https://github.com/necromorph1024/BitLockerPowershellModule
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376483%28v=vs.85%29.aspx
#>
function Get-BitLockerStatus {
    
    [CmdletBinding()]
    [OutputType([bool])]
    Param
    (
        # ComputerName, Type string, System to evaluate BitLocker against.
        [Parameter(Mandatory=$false,
                   Position=0)]
        [string]
        $ComputerName=$env:COMPUTERNAME,

        # DriveLetter, Type string, Drive letter to evaluate BitLocker against.  if NullOrEmpty the SystemDrive will be used.
        [Parameter(Mandatory=$false,
                   Position=1)]
        [ValidatePattern('[a-zA-Z]:')]
        [string]$DriveLetter
    )

    Begin
    {
        if (-not(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) 
        {
            Write-Error "Unable to connect to $ComputerName.  Please ensure the system is available."
            return $false
        }
    }
    Process
    {
        if (-not($DriveLetter)) 
        {
            try 
            {
                $drive=Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -ComputerName $ComputerName -Property SystemDrive -ErrorAction Stop
                $volume=Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$($drive.SystemDrive)'" -ComputerName $ComputerName -ErrorAction Stop
            }
            catch 
            {
                Write-Error "Unable to connect to the necassary WMI Namespaces, to get the system drive.  Verfy that you have sufficent rights to connect to the Win32_OperatingSystem and Win32_EncryptableVolume Namespaces."
                return $false
            }
        }
        else 
        {
            $volume=Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
            if ($volume -eq $null) 
            {
                Write-Error "Unable to enumarate the Win32_EncryptableVolume Namespace for $DriveLetter.  Please make sure the drive letter is correct and that the volume is accessable."
                return $false
            }
        }
    }
    End
    {
        if ($VerbosePreference -eq "Continue") 
        {
            switch ($volume.GetConversionStatus().ConversionStatus) 
            {
                0 { Write-Host "FullyDecrypted" }
                1 { Write-Host "FullyEncrypted" }
                2 { Write-Host "EncryptionInProgress"; Write-Host "PercentageComplete: " $status.EncryptionPercentage }
                3 { Write-Host "DecryptionInProgress"; Write-Host "PercentageComplete: " $status.EncryptionPercentage }
                4 { Write-Host "EncryptionPaused"; Write-Host "PercentageComplete: " $status.EncryptionPercentage }
                5 { Write-Host "DecryptionPaused"; Write-Host "PercentageComplete: " $status.EncryptionPercentage }
            }
        }
        
        if ($volume.GetProtectionStatus().ProtectionStatus -eq 0) 
        {
            if ($VerbosePreference -eq "Continue") 
            {
                Write-Host "ProtectionOff"
                return
            }
            return $false
        }
        else 
        {
            if ($VerbosePreference -eq "Continue") 
            {
                Write-Host "ProtectionOn"
                return
            }
            return $true
        }
    }
}

<#
.Synopsis
    Invokes BitLocker on a drive.
.DESCRIPTION
    Invokes BitLocker Drive Encryption on an Encryptable Volume with a TPM and Numrical Password Key Protectors.
    If the Trusted Platform Module is not currently owned, ownership will be taken with randomized 15 character password.
.EXAMPLE
    Invoke-BitLockerWithTpmAndNumricalKeyProtectors
.EXAMPLE
    Invoke-BitLockerWithTpmAndNumricalKeyProtectors -ComputerName "mycomputer.mydomain.org" -DriveLetter C: -ADKeyBackup $false
.NOTES
    ADKeyBackup switch requires proper TPM ACL Delegation in Active Directory to be used.
    This function will resume encryption if currently paused, or suspended.
    If used outside of the scope of this module, the Get-TpmStatus and Get-BitLockerStatus cmdlets are required.
.LINKS
    https://github.com/necromorph1024/BitLockerPowershellModule
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376483%28v=vs.85%29.aspx
    http://technet.microsoft.com/en-us/library/dd875529%28v=ws.10%29.aspx
#>
function Invoke-BitLockerWithTpmAndNumricalKeyProtectors {
    
    [CmdletBinding()]
    [OutputType([void])] 
    Param
    (
        # ComputerName, Type string, System to invoke BitLocker against.
        [Parameter(Mandatory=$false,
                   Position=0)]
        [string]
        $ComputerName=$env:COMPUTERNAME,

        # DriveLetter, Type string, Drive letter to invoke BitLocker against.  if NullOrEmpty the SystemDrive will be used.
        [Parameter(Mandatory=$false,
                   Position=1)]
        [ValidatePattern('[a-zA-Z]:')]
        [string]$DriveLetter,

        # ADKeyBackup, Type switch, Backups recovery information to the AD DS Object.
        [Parameter(Mandatory=$false,
                   position=2)]
        [switch]
        $ADKeyBackup=$false
    )

    Begin
    {
        if (-not(Get-TpmStatus -ComputerName $ComputerName)) 
        {
            throw (Get-TpmStatus -ComputerName $ComputerName -Verbose)
        }
    }
    Process
    {
        $tpm=Get-WmiObject -Class Win32_Tpm -Namespace "root\CIMV2\Security\MicrosoftTpm" -ComputerName $ComputerName -ErrorAction Stop
        if (-not($tpm.IsOwned_InitialValue)) 
        {
            $charArray="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray()
            $random=""
            for ($x=0; $x -lt 15; $x++) 
            {
                $random+=$charArray | Get-Random
            }
            $tpm.TakeOwnership($tpm.ConvertToOwnerAuth($random).OwnerAuth)
        }

        if (-not($DriveLetter)) 
        {
            try 
            {
                $drive=Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -ComputerName $ComputerName -Property SystemDrive -ErrorAction Stop
                $volume=Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$($drive.SystemDrive)'" -ComputerName $ComputerName -ErrorAction Stop
            }
            catch 
            {
                Write-Error "Unable to connect to the necassary WMI Namespaces, to get the system drive.  Verfy that you have sufficent rights to connect to the Win32_OperatingSystem and Win32_EncryptableVolume Namespaces."
                return $false
            }
        }
        else 
        {
            $volume=Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
            if ($volume -eq $null) 
            {
                Write-Error "Unable to enumarate the Win32_EncryptableVolume Namespace for $DriveLetter.  Please make sure the drive letter is correct and that the volume is accessable."
                return $false
            }
        }

        if (-not($volume.GetKeyProtectors(3).VolumeKeyProtectorID)) 
        {
            $volume.ProtectKeyWithNumericalPassword()
            if ($ADKeyBackup) 
            {
                try 
                {
                    $volume.BackupRecoveryInformationToActiveDirectory($volume.GetKeyProtectors(3).VolumeKeyProtectorID)
                }
                catch 
                {
                    throw "There was an error backing up the information to AD DS, ensure the proper infrustructer settings are inplace to use this option."
                }
            }
        }
        if (-not($volume.GetKeyProtectors(1).VolumeKeyProtectorID))
        {
            $volume.ProtectKeyWithTPM()
        }

        switch ($volume.GetConversionStatus().ConversionStatus) 
        {
            0 { $volume.Encrypt() }
            1 { if ($volume.ProtectionStatus -eq 0) { $volume.EnableKeyProtectors() } }
            4 { $volume.ResumeConversion() }
        }
    }
    End
    {
    Get-BitLockerStatus -ComputerName $ComputerName -DriveLetter $volume
    }
}

Export-ModuleMember -Function *