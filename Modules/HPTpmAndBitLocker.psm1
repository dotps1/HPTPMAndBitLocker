<#
.SYNOPSIS
    Converts the return values to user friendly text.
.DESCRIPTION
    Converts the return values from the .SetBIOSSetting() method to user firendly verbose output.
.EXAMPLE
    Out-HpVerboseReturnValues -WmiMethodReturnValue 0
.EXAMPLE
    Out-HpVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("Setup Password"," ",$SetupPassword))
.LINKS
    https://github.com/necromorph1024/HPTpmAndBitLocker
    http://h20331.www2.hp.com/Hpsub/downloads/cmi_whitepaper.pdf  Page: 14
#>
function Out-HpVerboseReturnValues
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # WmiMethodReturnValue, Type int, The Return Property Value to be converted to verbose output.
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true)]
        [Alias("RetVal")]
        [int]
        $WmiMethodReturnValue
    )

    switch ($WmiMethodReturnValue)
    {
        0 { Write-Output "Success" }
        1 { Write-Output "Not Supported" }
        2 { Write-Output "Unspecified Error" }
        3 { Write-Output "Timeout" }
        4 { Write-Output "Failed" }
        5 { Write-Output "Invalid Parameter" }
        6 { Write-Output "Access Denied " }
        defualt { "Return Value Unknown" }
    }
}

<#
.SYNOPSIS
    Converts string to KBD encoded string.
.DESCRIPTION
    Converts UTF16 string to Keyboard Scan Hex Value (KBD).  Older HP BIOS's only accept this encoding method for setup passwords, usful for WMI BIOS Administration.
.EXAMPLE
    Convert-ToKbdString -UnicodeString "MyStringToConvert"
.LINKS
    https://github.com/necromorph1024/HPTpmAndBitLocker
    http://www.codeproject.com/Articles/7305/Keyboard-Events-Simulation-using-keybd_event-funct
    http://msdn.microsoft.com/en-us/library/aa299374%28v=vs.60%29.aspx
    http://h20331.www2.hp.com/Hpsub/downloads/cmi_whitepaper.pdf  Page: 14
#>
function Convert-ToKbdString 
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Input, Type string, String to be encoded with EN Keyboard Scan Code Hex Values.
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true)]
        [Alias("UniStr")]
        [AllowEmptyString()]
        [string]
        $UnicodeString
    )

    $kbdHexVals=New-Object System.Collections.Hashtable

    $kbdHexVals."a"="1E"
    $kbdHexVals."b"="30"
    $kbdHexVals."c"="2E"
    $kbdHexVals."d"="20"
    $kbdHexVals."e"="12"
    $kbdHexVals."f"="21"
    $kbdHexVals."g"="22"
    $kbdHexVals."h"="23"
    $kbdHexVals."i"="17"
    $kbdHexVals."j"="24"
    $kbdHexVals."k"="25"
    $kbdHexVals."l"="26"
    $kbdHexVals."m"="32"
    $kbdHexVals."n"="31"
    $kbdHexVals."o"="18"
    $kbdHexVals."p"="19"
    $kbdHexVals."q"="10"
    $kbdHexVals."r"="13"
    $kbdHexVals."s"="1F"
    $kbdHexVals."t"="14"
    $kbdHexVals."u"="16"
    $kbdHexVals."v"="2F"
    $kbdHexVals."w"="11"
    $kbdHexVals."x"="2D"
    $kbdHexVals."y"="15"
    $kbdHexVals."z"="2C"
    $kbdHexVals."A"="9E"
    $kbdHexVals."B"="B0"
    $kbdHexVals."C"="AE"
    $kbdHexVals."D"="A0"
    $kbdHexVals."E"="92"
    $kbdHexVals."F"="A1"
    $kbdHexVals."G"="A2"
    $kbdHexVals."H"="A3"
    $kbdHexVals."I"="97"
    $kbdHexVals."J"="A4"
    $kbdHexVals."K"="A5"
    $kbdHexVals."L"="A6"
    $kbdHexVals."M"="B2"
    $kbdHexVals."N"="B1"
    $kbdHexVals."O"="98"
    $kbdHexVals."P"="99"
    $kbdHexVals."Q"="90"
    $kbdHexVals."R"="93"
    $kbdHexVals."S"="9F"
    $kbdHexVals."T"="94"
    $kbdHexVals."U"="96"
    $kbdHexVals."V"="AF"
    $kbdHexVals."W"="91"
    $kbdHexVals."X"="AD"
    $kbdHexVals."Y"="95"
    $kbdHexVals."Z"="AC"
    $kbdHexVals."1"="02"
    $kbdHexVals."2"="03"
    $kbdHexVals."3"="04"
    $kbdHexVals."4"="05"
    $kbdHexVals."5"="06"
    $kbdHexVals."6"="07"
    $kbdHexVals."7"="08"
    $kbdHexVals."8"="09"
    $kbdHexVals."9"="0A"
    $kbdHexVals."0"="0B"
    $kbdHexVals."!"="82"
    $kbdHexVals."@"="83"
    $kbdHexVals."#"="84"
    $kbdHexVals."$"="85"
    $kbdHexVals."%"="86"
    $kbdHexVals."^"="87"
    $kbdHexVals."&"="88"
    $kbdHexVals."*"="89"
    $kbdHexVals."("="8A"
    $kbdHexVals.")"="8B"
    $kbdHexVals."-"="0C"
    $kbdHexVals."_"="8C"
    $kbdHexVals."="="0D"
    $kbdHexVals."+"="8D"
    $kbdHexVals."["="1A"
    $kbdHexVals."{"="9A"
    $kbdHexVals."]"="1B"
    $kbdHexVals."}"="9B"
    $kbdHexVals.";"="27"
    $kbdHexVals.":"="A7"
    $kbdHexVals."'"="28"
    $kbdHexVals."`""="A8"
    $kbdHexVals."``"="29"
    $kbdHexVals."~"="A9"
    $kbdHexVals."\"="2B"
    $kbdHexVals."|"="AB"
    $kbdHexVals.","="33"
    $kbdHexVals."<"="B3"
    $kbdHexVals."."="34"
    $kbdHexVals.">"="B4"
    $kbdHexVals."/"="35"
    $kbdHexVals."?"="B5"

    $kbdEncodedString=""
    foreach ($char in $UnicodeString.ToCharArray())
    {
        $kbdEncodedString+=$kbdHexVals.Get_Item($char.ToString())
    }
    return $kbdEncodedString
}

<#
.SYNOPSIS
    Gets the current state of the setup password.  It is not possiable to return the current setup password value.
.DESCRIPTION
    This function will determine if the password is set on the system, automation of Bios Settings cannot be used until the password is set.
.EXAMPLE
    Get-HpSetupPasswordIsSet
.EXAMPLE
    Get-HpSetupPasswordIsSet -ComputerName "mycomputer.mydomain.org
.LINKS
    https://github.com/necromorph1024/HPTpmAndBitLocker
#>
function Get-HpSetupPasswordIsSet
{
    [CmdletBinding()]
    [OutputType([bool])]
    Param
    (
        # ComputerName, Type string, System to evaluate Setup Password state against.
        [Parameter(Position=0,
                   ValueFromPipeline=$true)]
        [string[]]
        $ComputerName=$env:COMPUTERNAME
    )

    if (-not(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) 
    {
        throw "Failed to connect to $ComputerName.  Please ensure the system is available."
    }

    try
    {
        $manufacturer=Get-WmiObject -Class Win32_ComputerSystem -Namespace "root\CIMV2" -Property "Manufacturer" -ComputerName $ComputerName -ErrorAction Stop
    }
    catch
    {
        throw "Failed to connect to the Win32_ComputerSystem WMI Namespace, verify the system is avaialbe and you have the permissions to access the namespace."
    }

    if (-not($manufacturer.Manufacturer -eq "Hewlett-Packard" -or $manufacturer.Manufacturer -eq "HP"))
    {
        throw "Computer Manufacturer is not of type Hewlett-Packard.  This cmdlet can only be used on Hewlett-Packard systems."
    }

    $hpBios=Get-WmiObject -Class HP_BiosSetting -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction Stop

    if (($hpBios | ?{ $_.Name -eq 'Setup Password' }).IsSet -eq 0)
    {
        return $false
    }
    else
    {
        return $true
    }
}

<#
.SYNOPSIS
    Sets the Setup Password on an HP Bios.
.DESCRIPTION
    This function can be used to set a password on the Bios, it can also be used to clear the password, the current password is needed to change the value.
    If a new value is being set, and not cleared, it must be between 8 and 30 characters.
.EXAMPLE
    Set-HpSetupPassword -NewSetupPassword "MyNewPassword"
.EXAMPLE
    Set-HpSetupPassword -ComputerName "mycomputer.mydomain.org" -NewSetupPassword " " -CurrentSetupPassword "MyCurrentPassword"
.EXAMPLE
    Set-HpSetupPassword -NewSetupPassword "MyNewSetupPassword" -CurrentSetupPassword "MyCurrentPassword"
.LINKS
    https://github.com/necromorph1024/HPTpmAndBitLocker
#>
function Set-HpSetupPassword
{
    [CmdletBinding()]
    [OutputType([void])]
    Param
    (
        # ComputerName, Type string, System to set Bios Setup Password.
        [Parameter(Position=0,
                   ValueFromPipeline=$true)]
        [string[]]
        $ComputerName=$env:COMPUTERNAME,

        # NewPassword, Type string, The value of the password to be set.  The password can be cleared by using a space surrounded by double quotes, IE: " ".
        [Parameter(Mandatory=$true,
                   Position=1)]
        [string]
        $NewPassword,

        # CurrentPassword, Type string, The value of the current setup password.
        [Parameter(Position=2)]
        [string]
        $CurrentPassword
    )

    if (-not(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) 
    {
        throw "Failed to connect to $ComputerName.  Please ensure the system is available."
    }

    try
    {
        $manufacturer=Get-WmiObject -Class Win32_ComputerSystem -Namespace "root\CIMV2" -Property "Manufacturer" -ComputerName $ComputerName -ErrorAction Stop
        if (-not($manufacturer.Manufacturer -eq "Hewlett-Packard" -or $manufacturer.Manufacturer -eq "HP"))
        {
            throw "Computer Manufacturer is not of type Hewlett-Packard.  This cmdlet can only be used on Hewlett-Packard systems."
        }
    }
    catch
    {
        throw "Failed to connect to the Win32_ComputerSystem WMI Namespace, verify the system is avaialbe and you have the permissions to access the namespace."
    }

    if (-not([String]::IsNullOrWhiteSpace($NewPassword)))
    {
        if (($NewPassword.Length -lt 8) -or ($NewPassword.Length -gt 30))
        {
            throw "The Password Values must be be between 8 and 30 characters if not clearing the password."
        }
    }

    $hpBios=Get-WmiObject -Class HP_BiosSetting -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction Stop
    $hpBiosSettings=Get-WmiObject -Class HPBIOS_BIOSSettingInterface -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction stop

    switch (($hpBios | ?{ $_.Name -eq "Setup Password" }).SupportedEncoding)
    {
        "kbd"
        { 
            $NewSetupPassword="<kbd/>"+(Convert-ToKbdString -UnicodeString $NewPassword) 
            $CurrentSetupPassword="<kbd/>"+(Convert-ToKbdString -UnicodeString $CurrentPassword) 
        }
        "utf-16"
        { 
            $NewSetupPassword="<utf-16/>"+$NewPassword 
            $CurrentSetupPassword="<utf-16/>"+$CurrentPassword 
        }
        defualt  { throw "Current setup password encoding unknown, exiting." }
    }

    Write-Output "Setting Password..."
    Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("Setup Password",$NewSetupPassword,$CurrentSetupPassword)).Return
}

<#
.SYNOPSIS
   Get the current status of the TPM.
.DESCRIPTION
   Tests the status of the Trusted Platform Module, only returns true if both enabled and activated.
.EXAMPLE
   Get-TpmStatus
.EXAMPLE
   Get-TpmStatus -ComputerName "mycomputer.mydomain.org" -Verbose
.NOTES
    Use the -Verbose switch for user friendly STDOUT.
.LINKS
    https://github.com/necromorph1024/HPTpmAndBitLocker
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376484%28v=vs.85%29.aspx
#>
function Get-TpmStatus 
{
    [CmdletBinding()]
    [OutputType([PSobject])]
    Param 
    (
        # ComputerName, Type string, System to evaluate TPM against.
        [Parameter(Position=0,
                   ValueFromPipeline=$true)]
        [string[]]
        $ComputerName=$env:COMPUTERNAME
    )

    if (-not(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) 
    {
        throw "Failed to connect to $ComputerName.  Please ensure the system is available."
    }

    try 
    {
        $tpm=Get-WmiObject -Class Win32_Tpm -Namespace "root\CIMV2\Security\MicrosoftTpm" -ComputerName $ComputerName -ErrorAction Stop
    }
    catch 
    {
        throw "Failed to connect to the Win32_Tpm Namespace, You may not have sufficent rights."
    }

    if (-not($tpm.IsEnabled_InitialValue)) 
    {
        $enabled="No"
    }
    else
    {
        $enabled="Yes"
    }
    
    if (-not($tpm.IsActivated_InitialValue))
    {
        $activated="No"
    }
    else 
    {
        $activated="Yes"
    }

    $tpmStatus=[PSCustomObject] @{
                                      'Enabled'  =$enabled
                                      'Activated'=$activated
                                 }
    return $tpmStatus
}

<#
.SYNOPSIS
    Enables the Trusted Platform Module.
.DESCRIPTION
    Enables and configures the required settings of the TPM in order to use the TPM Protector Type for BitLocker drive encryption.
    A system restart is required to complete this action, the default delay of this timer is 30 seconds if the restart switch is used.
.EXAMPLE
    Invoke-HpTpm -SetupPassword "MyPassword"
.EXAMPLE
    Invoke-HpTpm -ComputerName "mycomputer.mydomain.org" -SetupPassword "MyPassword"
.EXAMPLE
    Invoke-HpTpm -SetupPassword "ABCD1234" -RestartComputer -RestartDelay 30
.LINKS
    https://github.com/necromorph1024/HPTpmAndBitLocker
#>
function Invoke-HpTpm
{
    [CmdletBinding(DefaultParametersetName="None")]
    [OutputType([void])]
    Param
    (
        # ComputerName, Type string, The HP Computer to enable and configure TPM.
        [Parameter(Position=0,
                   ValueFromPipeline=$true)]
        [string[]]
        $ComputerName=$env:ComputerName,

        # Password, Type string, The current Setup Password of the system Bios.
        [Parameter(Mandatory=$true,
                   Position=1)]
        [string]
        $Password,

        # RestartComputer, Type switch, Boolean value that determines to reboot the pc.
        [Parameter(ParameterSetName="Overload")]
        [switch]
        $RestartComputer,

        # RestartDelay, Type int, The amount of time in seconds before the computer restarts, must be specified if the $RestartComputer switch is used.
        [Parameter(ParameterSetName="Overload",
                   Mandatory=$true)]
        [ValidateRange(0,86400)]
        [int]
        $RestartDelay
    )

    if (-not(Get-HPSetupPasswordIsSet -ComputerName $ComputerName))
    {
        throw "The Bios Setup Password must be set before this cmdlet can be used."
    }

    $hpBios=Get-WmiObject -Class HP_BiosSetting -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction Stop
    $hpBiosSettings=Get-WmiObject -Class HPBIOS_BIOSSettingInterface -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction stop
        
    switch (($hpBios | ?{ $_.Name -eq "Setup Password" }).SupportedEncoding)
    {
        "kbd"    { $SetupPassword="<kbd/>"+(Convert-ToKbdString -UnicodeString $Password) }
        "utf-16" { $SetupPassword="<utf-16/>"+$Password }
        defualt  { throw "Setup password encoding unknown, exiting." }
    }

    Write-Output "Enabling the Trusted Platform Module..."
    if (($hpBios | ?{ $_.Name -eq "Embedded Security Device" }) -ne $null)
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("Embedded Security Device","Device available",$SetupPassword)).Return
    }
    elseif (($hpBios | ?{ $_.Name -eq "Embedded Security Device Availability" }) -ne $null)
    {
        Out-HpVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("Embedded Security Device Availability","Available",$SetupPassword)).Return
    }
    elseif (($hpBios | ?{ $_.Name -eq "TPM Device" }) -ne $null)
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("TPM Device","Available",$SetupPassword)).Return
    }

    Write-Output "Activating the Trusted Platform Module..."
    if (($hpBios | ?{ $_.Name -eq "Activate Embedded Security On Next Boot" }) -ne $null)
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("Activate Embedded Security On Next Boot","Enable",$SetupPassword)).Return
    }
    elseif (($hpBios | ?{ $_.Name -eq "Activate TPM On Next Boot" }) -ne $null)
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("Activate TPM On Next Boot","Enable",$SetupPassword)).Return
    }

    Write-Output "Setting Trusted Platform Module Activation Policy..."
    if (($hpBios | ?{ $_.Name -eq "Embedded Security Activation Policy" }) -ne $null )
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("Embedded Security Activation Policy","No prompts",$SetupPassword)).Return
    } 
    elseif (($hpBios | ?{ $_.Name -eq "TPM Activation Policy" }) -ne $null)
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("TPM Activation Policy","No prompts",$SetupPassword)).Return
    }

    Write-Output "Setting Operating System Management of Trusted Platform Module..."
    if (($hpBios | ?{ $_.Name -eq "OS management of Embedded Security Device" }) -ne $null)
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("OS management of Embedded Security Device","Enable",$SetupPassword)).Return
    }
    elseif (($hpBios | ?{ $_.Name -eq "OS Management of TPM" }) -ne $null)
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("OS Management of TPM","Enable",$SetupPassword)).Return
    }

    Write-Output "Setting Reset Capabilites of Trusted Platform Module for Operating System..."
    if (($hpBios | ?{ $_.Name -eq "Reset of Embedded Security Device through OS" }) -ne $null)
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("Reset of Embedded Security Device through OS","Enable",$SetupPassword)).Return
    }
    elseif (($hpBios | ?{ $_.Name -eq "Reset of TPM from OS" }) -ne $null)
    {
        Out-HPVerboseReturnValues -WmiMethodReturnValue ($hpBiosSettings.SetBIOSSetting("Reset of TPM from OS","Enable",$SetupPassword)).Return
    }

    if ($RestartComputer)
    {
        shutdown.exe -f -r -t $RestartDelay -m $ComputerName -c "A reboot is required to complete the invocation of the Tpm."
    }
}

<#
.SYNOPSIS
    Gets the current status of BitLocker.
.DESCRIPTION
    Tests the current status of BitLocker Drive Encryption on an Encryptable Volume.  Only returns true if the volume is fully encrypted and the protection status is on.
.EXAMPLE
    Get-BitLockerStatus
.EXAMPLE
    Get-BitLockerStatus -ComputerName "mycomputer.mydomain.com" -DriveLetter C: -Verbose
.NOTES
    If no drive letter is specified, the default system drive will be used.
    The drive letter must be followed with a double colon.  IE: "C:".
    Use the -Verbose switch for user friendly STDOUT.
.LINKS
    https://github.com/necromorph1024/HPTpmAndBitLocker
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376483%28v=vs.85%29.aspx
#>
function Get-BitLockerStatus 
{    
    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        # ComputerName, Type string, System to evaluate BitLocker against.
        [Parameter(Position=0,
                   ValueFromPipeline=$true)]
        [string[]]
        $ComputerName=$env:COMPUTERNAME,

        # DriveLetter, Type string, Drive letter to evaluate BitLocker against.  if NullOrEmpty the default SystemDrive will be used.
        [Parameter(Position=1,
                   HelpMessage="Drive letter format must be letter followed by colon, 'C:'")]
        [ValidatePattern('[a-zA-Z]:')]
        [string]
        $DriveLetter
    )

    if (-not(Test-Connection -ComputerName $ComputerName -Quiet -Count 2)) 
    {
        throw "Failed to connect to $ComputerName.  Please ensure the system is available."
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
            throw "Failed to connect to the necassary WMI Namespaces, to get the system drive.  Verfy that you have sufficent rights to connect to the Win32_OperatingSystem and Win32_EncryptableVolume Namespaces."
        }
    }
    else 
    {
        $volume=Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
        if ($volume -eq $null) 
        {
            throw "Failed to enumarate the Win32_EncryptableVolume Namespace for $DriveLetter.  Please make sure the drive letter is correct and that the volume is accessable."
        }
    }

    $status=$volume.GetConversionStatus()
    switch ($status.ConversionStatus) 
    {
        0 { $state="FullyDecrypted" }
        1 { $state="FullyEncrypted" }
        2 { $state="EncryptionInProgress" }
        3 { $state="DecryptionInProgress" }
        4 { $state="EncryptionPaused" }
        5 { $state="DecryptionPaused" }
    }

    $percentage=$status.EncryptionPercentage

    if ($volume.GetProtectionStatus().ProtectionStatus -eq 0) 
    {
        $protection="ProtectionOff"
    }
    else 
    {
        $protection="ProtectonOn"
    }

    $bdeStatus=[PSCustomObject] @{
                                      'Protection'=$protection
                                      'State'     =$state
                                      'Percentage'=$percentage
                                 }
    return $bdeStatus
}

<#
.SYNOPSIS
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
    https://github.com/necromorph1024/HPTpmAndBitLocker
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376483%28v=vs.85%29.aspx
    http://technet.microsoft.com/en-us/library/dd875529%28v=ws.10%29.aspx
#>
function Invoke-BitLockerWithTpmAndNumricalKeyProtectors 
{    
    [CmdletBinding()]
    [OutputType([void])] 
    Param
    (
        # ComputerName, Type string, System to invoke BitLocker against.
        [Parameter(Position=0,
                   ValueFromPipeline=$true)]
        [string[]]
        $ComputerName=$env:COMPUTERNAME,

        # DriveLetter, Type string, Drive letter to invoke BitLocker against.  if NullOrEmpty the SystemDrive will be used.
        [Parameter(Position=1)]
        [ValidatePattern('[a-zA-Z]:')]
        [string]$DriveLetter,

        # ADKeyBackup, Type switch, Backups recovery information to the AD DS Object.
        [Parameter(position=2)]
        [switch]
        $ADKeyBackup=$false
    )

    if (-not(Get-TpmStatus -ComputerName $ComputerName).Enabled -eq "Yes" -or (-not(Get-TpmStatus -ComputerName $ComputerName).Activated -eq "Yes"))
    {
        throw "The Tpm is not properly configured to use as a Key Protector for BitLocker Drive Encryption."
    }

    $tpm=Get-WmiObject -Class Win32_Tpm -Namespace "root\CIMV2\Security\MicrosoftTpm" -ComputerName $ComputerName -ErrorAction Stop
    if (-not($tpm.IsOwned_InitialValue)) 
    {
        $charArray="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray()
        $random=""
        for ($x=0; $x -lt 15; $x++) 
        {
            $random+=$charArray | Get-Random
        }
        $tpm.TakeOwnership($tpm.ConvertToOwnerAuth($random).OwnerAuth) | Out-Null
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
            throw "Failed to connect to the necassary WMI Namespaces, to get the system drive.  Verfy that you have sufficent rights to connect to the Win32_OperatingSystem and Win32_EncryptableVolume Namespaces."
        }
    }
    else 
    {
        $volume=Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
        if ($volume -eq $null) 
        {
            throw "Failed to enumarate the Win32_EncryptableVolume Namespace for $DriveLetter.  Please make sure the drive letter is correct and that the volume is accessable."
        }
    }

    if (-not($volume.GetKeyProtectors(3).VolumeKeyProtectorID)) 
    {
        $volume.ProtectKeyWithNumericalPassword() | Out-Null
        if ($ADKeyBackup) 
        {
            try 
            {
                $volume.BackupRecoveryInformationToActiveDirectory($volume.GetKeyProtectors(3).VolumeKeyProtectorID) | Out-Null
            }
            catch 
            {
                throw "There was an error backing up the information to AD DS, ensure the proper infrastructure settings are inplace to use this option."
            }
        }
    }

    if (-not($volume.GetKeyProtectors(1).VolumeKeyProtectorID))
    {
        $volume.ProtectKeyWithTPM() | Out-Null
    }

    switch ($volume.GetConversionStatus().ConversionStatus) 
    {
        0 { $volume.Encrypt() | Out-Null }
        1 { if ($volume.ProtectionStatus -eq 0) { $volume.EnableKeyProtectors() | Out-Null } }
        4 { $volume.Encrypt() | Out-Null }
    }

    Get-BitLockerStatus -ComputerName $ComputerName -DriveLetter $volume.DriveLetter
}