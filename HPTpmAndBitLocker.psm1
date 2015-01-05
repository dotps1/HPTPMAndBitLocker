<#
.SYNOPSIS
    Converts the return values to user friendly text.
.DESCRIPTION
    Converts the return values from the .SetBIOSSetting() WMI Method to user firendly verbose output.
.INPUTS
	System.Int.
.OUTPUTS
	System.String.
.PARAMETER WmiMethodReturnValue
    The Return Property Value to be converted to verbose output.
.EXAMPLE
    Out-HPVerboseReturnValues -WmiMethodReturnValue 0
.EXAMPLE
    Out-HPVerboseReturnValues -WmiMethodReturnValue ((Get-WmiObject -Class HPBIOS_BIOSSettingInterface -Namespace "root\HP\InstrumentedBIOS").SetBIOSSetting("Setup Password"," ","MyPassword"))
.LINK
    http://h20331.www2.hp.com/HPsub/downloads/cmi_whitepaper.pdf  Page: 14
.LINK
    http://dotps1.github.io
#>
Function Get-HPVerboseReturnValues
{
    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [Alias("RetVal")]
        [Int]
        $WmiMethodReturnValue
    )

    switch ($WmiMethodReturnValue)
    {
        0 { return "Success" }
        1 { return "Not Supported" }
        2 { return "Unspecified Error" }
        3 { return "Timeout" }
        4 { return "Failed" }
        5 { return "Invalid Parameter" }
        6 { return "Access Denied " }
        defualt { return "Return Value Unknown" }
    }
}

<#
.SYNOPSIS
    Converts string to KBD encoded string.
.DESCRIPTION
    Converts UTF16 string to Keyboard Scan Hex Value (KBD).  Older HP BIOS's only accept this encoding method for setup passwords, useful for WMI BIOS Administration.
.INPUTS
	System.String.
.OUTPUTS
	System.String.
.PARAMETER UnicodeString
    String to be encoded with EN Keyboard Scan Code Hex Values.
.EXAMPLE
    ConvertTo-KBDString -UnicodeString "MyStringToConvert"
.LINK
    http://www.codeproject.com/Articles/7305/Keyboard-Events-Simulation-using-keybd_event-funct
.LINK
    http://msdn.microsoft.com/en-us/library/aa299374%28v%20=%20vs.60%29.aspx
.LINK
    http://h20331.www2.hp.com/HPsub/downloads/cmi_whitepaper.pdf  Page: 14
.LINK
    http://dotps1.github.io
#>
Function ConvertTo-KBDString
{
    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [Alias("UniStr")]
        [AllowEmptyString()]
        [String]
        $UnicodeString
    )

    $kbdHexVals = New-Object System.Collections.Hashtable
	$kbdHexVals."a" = "1E"
	$kbdHexVals."b" = "30"
	$kbdHexVals."c" = "2E"
	$kbdHexVals."d" = "20"
	$kbdHexVals."e" = "12"
	$kbdHexVals."f" = "21"
	$kbdHexVals."g" = "22"
	$kbdHexVals."h" = "23"
	$kbdHexVals."i" = "17"
	$kbdHexVals."j" = "24"
	$kbdHexVals."k" = "25"
	$kbdHexVals."l" = "26"
	$kbdHexVals."m" = "32"
	$kbdHexVals."n" = "31"
	$kbdHexVals."o" = "18"
	$kbdHexVals."p" = "19"
	$kbdHexVals."q" = "10"
	$kbdHexVals."r" = "13"
	$kbdHexVals."s" = "1F"
	$kbdHexVals."t" = "14"
	$kbdHexVals."u" = "16"
	$kbdHexVals."v" = "2F"
	$kbdHexVals."w" = "11"
	$kbdHexVals."x" = "2D"
	$kbdHexVals."y" = "15"
	$kbdHexVals."z" = "2C"
	$kbdHexVals."A" = "9E"
	$kbdHexVals."B" = "B0"
	$kbdHexVals."C" = "AE"
	$kbdHexVals."D" = "A0"
	$kbdHexVals."E" = "92"
	$kbdHexVals."F" = "A1"
	$kbdHexVals."G" = "A2"
	$kbdHexVals."H" = "A3"
	$kbdHexVals."I" = "97"
	$kbdHexVals."J" = "A4"
	$kbdHexVals."K" = "A5"
	$kbdHexVals."L" = "A6"
	$kbdHexVals."M" = "B2"
	$kbdHexVals."N" = "B1"
	$kbdHexVals."O" = "98"
	$kbdHexVals."P" = "99"
	$kbdHexVals."Q" = "90"
	$kbdHexVals."R" = "93"
	$kbdHexVals."S" = "9F"
	$kbdHexVals."T" = "94"
	$kbdHexVals."U" = "96"
	$kbdHexVals."V" = "AF"
	$kbdHexVals."W" = "91"
	$kbdHexVals."X" = "AD"
	$kbdHexVals."Y" = "95"
	$kbdHexVals."Z" = "AC"
	$kbdHexVals."1" = "02"
	$kbdHexVals."2" = "03"
	$kbdHexVals."3" = "04"
	$kbdHexVals."4" = "05"
	$kbdHexVals."5" = "06"
	$kbdHexVals."6" = "07"
	$kbdHexVals."7" = "08"
	$kbdHexVals."8" = "09"
	$kbdHexVals."9" = "0A"
	$kbdHexVals."0" = "0B"
	$kbdHexVals."!" = "82"
	$kbdHexVals."@" = "83"
	$kbdHexVals."#" = "84"
	$kbdHexVals."$" = "85"
	$kbdHexVals."%" = "86"
	$kbdHexVals."^" = "87"
	$kbdHexVals."&" = "88"
	$kbdHexVals."*" = "89"
	$kbdHexVals."(" = "8A"
	$kbdHexVals.")" = "8B"
	$kbdHexVals."-" = "0C"
	$kbdHexVals."_" = "8C"
	$kbdHexVals."=" = "0D"
	$kbdHexVals."+" = "8D"
	$kbdHexVals."[" = "1A"
	$kbdHexVals."{" = "9A"
	$kbdHexVals."]" = "1B"
	$kbdHexVals."}" = "9B"
	$kbdHexVals.";" = "27"
	$kbdHexVals.":" = "A7"
	$kbdHexVals."'" = "28"
	$kbdHexVals."`"" = "A8"
	$kbdHexVals."``" = "29"
	$kbdHexVals."~" = "A9"
	$kbdHexVals."\" = "2B"
	$kbdHexVals."|" = "AB"
	$kbdHexVals."," = "33"
	$kbdHexVals."<" = "B3"
	$kbdHexVals."." = "34"
	$kbdHexVals.">" = "B4"
	$kbdHexVals."/" = "35"
	$kbdHexVals."?" = "B5"

    foreach ($char in $UnicodeString.ToCharArray())
    {
        $kbdEncodedString += $kbdHexVals.Get_Item($char.ToString())
    }

    return $kbdEncodedString
}

<#
.SYNOPSIS
    Gets the current state of the setup password.  It is not possiable to return the current setup password value.
.DESCRIPTION
    This function will determine if the password is set on the system, automation of BIOS Settings cannot be used until the password is set.
.INPUTS
	System.String.
.OUTPUTS
	System.Boolean.
.PARAMETER ComputerName
    System to evaluate Setup Password state against.
.EXAMPLE
    Get-HPSetupPasswordIsSet
.EXAMPLE
    Get-HPSetupPasswordIsSet -ComputerName "mycomputer.mydomain.org"
.LINK
    http://dotps1.github.io
#>
Function Test-HPBiosSetupPasswordIsSet
{
    [CmdletBinding()]
    [OutputType([Bool])]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateScript({ if (Test-Connection -ComputerName $_ -Quiet -Count 2){ $true }})]
        [String[]]
        $ComputerName = $env:COMPUTERNAME
    )

    try
    {
        $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem -Namespace "root\CIMV2" -Property "Manufacturer" -ComputerName $ComputerName -ErrorAction Stop).Manufacturer
    }
    catch [System.Exception]
    {
        throw $_
    }

    if (-not($manufacturer -eq "Hewlett-Packard" -or $manufacturer -eq "HP"))
    {
        throw "Computer Manufacturer is not of type Hewlett-Packard.  This cmdlet can only be used on Hewlett-Packard systems."
    }

	try
	{
		$hpBios = Get-WmiObject -Class HP_BiosSetting -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction Stop
	}
	catch [System.Exception]
	{
		throw $_
	}

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
    Sets the Setup Password on an Hewlett-Packard Bios.
.DESCRIPTION
    This function can be used to set a password on the Bios, it can also be used to clear the password, the current password is needed to change the value.
    If a new value is being set, and not cleared, it must be between 8 and 30 characters.
.INPUTS
	System.String
.OUTPUTS
	None.
.PARAMETER ComputerName
    System to set Bios Setup Password.
.PARAMETER NewPassword
    The value of the password to be set.  The password can be cleared by using a space surrounded by double quotes, IE: " ".
.PARAMETER CurrentPassword
    The value of the current setup bios password.
.EXAMPLE
    Set-HPSetupPassword -NewSetupPassword "MyNewPassword"
.EXAMPLE
    Set-HPSetupPassword -ComputerName "mycomputer.mydomain.org" -NewSetupPassword " " -CurrentSetupPassword "MyCurrentPassword"
.EXAMPLE
    Set-HPSetupPassword -NewSetupPassword "MyNewSetupPassword" -CurrentSetupPassword "MyCurrentPassword"
.LINK
    http://dotps1.github.io
#>
Function Set-HPBiosSetupPassword
{
    [CmdletBinding()]
    [OutputType([Void])]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateScript({ if (Test-Connection -ComputerName $_ -Quiet -Count 2){ $true }})]
        [String[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
		[ValidateNotNull()]
		[ValidateScript({ if (($_.Length -ge 8 -and $_.Length -le 30) -or ($_ -eq " ")){ $true }})]
        [String]
        $NewPassword,

        [Parameter()]
		[ValidateNotNull()]
		[ValidateScript({ if ($_.Length -ge 8 -and $_.Length -le 30){ $true }})]
        [String]
        $CurrentPassword
    )

    try
    {
        $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem -Namespace "root\CIMV2" -Property "Manufacturer" -ComputerName $ComputerName -ErrorAction Stop).Manufacturer
        if (-not($manufacturer -eq "Hewlett-Packard" -or $manufacturer -eq "HP"))
        {
            throw "Computer Manufacturer is not of type Hewlett-Packard.  This cmdlet can only be used on Hewlett-Packard systems."
        }
    }
    catch [System.Exception]
    {
        throw $_
    }

	try
	{
		$hpBios = Get-WmiObject -Class HP_BiosSetting -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction Stop
		$hpBiosSettings = Get-WmiObject -Class HPBIOS_BIOSSettingInterface -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction stop
	}
	catch [System.Exception]
	{
		throw $_
	}

    switch (($hpBios | ?{ $_.Name -eq "Setup Password" }).SupportedEncoding)
    {
        "kbd" { 
            $NewSetupPassword = "<kbd/>"+(ConvertTo-KBDString -UnicodeString $NewPassword) 
            $CurrentSetupPassword = "<kbd/>"+(ConvertTo-KBDString -UnicodeString $CurrentPassword) 
		}
        "utf-16" { 
            $NewSetupPassword = "<utf-16/>"+$NewPassword 
            $CurrentSetupPassword = "<utf-16/>"+$CurrentPassword 
        }
        defualt  { 
			throw "Current setup password encoding unknown, exiting." 
		}
    }

    Write-Verbose -Message "Setting Bios Setup Password..."
    $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("Setup Password",$NewSetupPassword,$CurrentSetupPassword)).Return
	Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
}

<#
.SYNOPSIS
   Get the current status of the TPM.
.DESCRIPTION
   Tests the status of the Trusted Platform Module, only returns true if both enabled and activated.
.INPUTS
	System.String.
.OUTPUTS
	System.Boolean.
.PARAMETER ComputerName
    System to evaluate TPM against.
.EXAMPLE
   Get-TPMStatus
.EXAMPLE
   Get-TPMStatus -ComputerName "mycomputer.mydomain.org"
.LINK
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376484%28v%20=%20vs.85%29.aspx
.LINK
    http://dotps1.github.io
#>
Function Test-HPTPMEnabledAndActivated 
{
    [CmdletBinding()]
    [OutputType([Bool])]
    Param 
    (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateScript({ if (Test-Connection -ComputerName $_ -Quiet -Count 2){ $true }})]
        [String[]]
        $ComputerName = $env:COMPUTERNAME
    )

    try 
    {
        $tpm = Get-WmiObject -Class Win32_TPM -Namespace "root\CIMV2\Security\MicrosoftTPM" -ComputerName $ComputerName -ErrorAction Stop
    }
    catch [System.Exception]
    {
        throw $_
    }

	if ($tpm.IsEnabled_InitialValue -and $tpm.IsActivated_InitialValue)
	{
		return $true
	}
	else
	{
		return $false
	}
}

<#
.SYNOPSIS
    Enables the Trusted Platform Module.
.DESCRIPTION
    Enables and configures the required settings of the TPM in order to use the TPM Protector Type for BitLocker drive encryption.
    A system restart is required to complete this action, the default delay of this timer is 30 seconds if the restart switch is used.
.INPUTS
	System.String
.OUTPUTS
	None.
.PARAMETER ComputerName
    The HP Computer to enable and configure TPM.
.PARAMETER BiosSetupPassword
    The current Setup Password of the system Bios.
.PARAMETER RestartComputer
    Inovokes a restart of the computer upon completion of TPM Configuration.
.PARAMETER RestartDelay
    The amount of time in seconds before the computer restarts.
.EXAMPLE
    Invoke-HPTPM -SetupPassword "MyPassword"
.EXAMPLE
    Invoke-HPTPM -ComputerName "mycomputer.mydomain.org" -SetupPassword "MyPassword"
.EXAMPLE
    Invoke-HPTPM -SetupPassword "ABCD1234" -RestartComputer -RestartDelay 30
.LINK
    http://dotps1.github.io
#>
Function Invoke-HPTPM
{
    [CmdletBinding()]
    [OutputType([Void])]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateScript({ if (Test-Connection -ComputerName $_ -Quiet -Count 2){ $true }})]
        [String[]]
        $ComputerName = $env:ComputerName,

        [Parameter(Mandatory = $true)]
        [String]
        $BiosSetupPassword,

        [Parameter()]
        [Switch]
        $RestartComputer,

        [Parameter()]
        [ValidateRange(0,86400)]
        [Int]
        $RestartDelay = 30
    )

	if (Test-HPTPMEnabledAndActivated -ComputerName $ComputerName)
	{
		throw "The TPM is already properly configured."
	}

    if (-not (Test-HPBiosSetupPasswordIsSet -ComputerName $ComputerName))
    {
        throw "The Bios Setup Password must be set before this cmdlet can be used."
    }

	try
	{
		$hpBios = Get-WmiObject -Class HP_BiosSetting -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction Stop
		$hpBiosSettings = Get-WmiObject -Class HPBIOS_BIOSSettingInterface -Namespace "root\HP\InstrumentedBIOS" -ComputerName $ComputerName -ErrorAction stop
	}
	catch [System.Exception]
	{
		throw $_
	}
      
    switch (($hpBios | ?{ $_.Name -eq "Setup Password" }).SupportedEncoding)
    {
        "kbd" { 
			$BiosSetupPassword = "<kbd/>"+(ConvertTo-KBDString -UnicodeString $BiosSetupPassword) 
		}
        "utf-16" { 
			$BiosSetupPassword = "<utf-16/>"+$BiosSetupPassword 
		}
        defualt { 
			throw "Setup password encoding unknown, exiting." 
		}
    }

    Write-Verbose -Message "Enabling the Trusted Platform Module..."
    if (($hpBios | ?{ $_.Name -eq "Embedded Security Device" }) -ne $null)
    {
		$wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("Embedded Security Device","Device available",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }
    elseif (($hpBios | ?{ $_.Name -eq "Embedded Security Device Availability" }) -ne $null)
    {
        Out-HPVerboseReturnValues $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("Embedded Security Device Availability","Available",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }
    elseif (($hpBios | ?{ $_.Name -eq "TPM Device" }) -ne $null)
    {
        $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("TPM Device","Available",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }

    Write-Verbose -Message "Activating the Trusted Platform Module..."
    if (($hpBios | ?{ $_.Name -eq "Activate Embedded Security On Next Boot" }) -ne $null)
    {
        $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("Activate Embedded Security On Next Boot","Enable",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }
    elseif (($hpBios | ?{ $_.Name -eq "Activate TPM On Next Boot" }) -ne $null)
    {
        $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("Activate TPM On Next Boot","Enable",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }

    Write-Verbose -Message "Setting Trusted Platform Module Activation Policy..."
    if (($hpBios | ?{ $_.Name -eq "Embedded Security Activation Policy" }) -ne $null )
    {
        $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("Embedded Security Activation Policy","No prompts",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    } 
    elseif (($hpBios | ?{ $_.Name -eq "TPM Activation Policy" }) -ne $null)
    {
        $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("TPM Activation Policy","No prompts",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }

    Write-Verbose -Message "Setting Operating System Management of Trusted Platform Module..."
    if (($hpBios | ?{ $_.Name -eq "OS management of Embedded Security Device" }) -ne $null)
    {
        $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("OS management of Embedded Security Device","Enable",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }
    elseif (($hpBios | ?{ $_.Name -eq "OS Management of TPM" }) -ne $null)
    {
        $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("OS Management of TPM","Enable",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }

    Write-Verbose -Message "Setting Reset Capabilites of Trusted Platform Module for Operating System..."
    if (($hpBios | ?{ $_.Name -eq "Reset of Embedded Security Device through OS" }) -ne $null)
    {
        $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("Reset of Embedded Security Device through OS","Enable",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }
    elseif (($hpBios | ?{ $_.Name -eq "Reset of TPM from OS" }) -ne $null)
    {
        $wmiMethodReturnValue = ($hpBiosSettings.SetBIOSSetting("Reset of TPM from OS","Enable",$BiosSetupPassword)).Return
		Write-Verbose -Message (Get-HPVerboseReturnValues -WmiMethodReturnValue $wmiMethodReturnValue)
    }

    if ($RestartComputer.IsPresent)
    {
        shutdown.exe -f -r -t $RestartDelay -m $ComputerName -c "A reboot is required to complete the invocation of the TPM."
    }
}

<#
.SYNOPSIS
    Gets the current status of BitLocker.
.DESCRIPTION
    Tests the current status of BitLocker Drive Encryption on an Encryptable Volume.  Only returns true if the volume is fully encrypted and the protection status is on.
.INPUTS
	System.String.
.OUTPUTS
	System.Management.Automation.PSObject
.PARAMETER ComputerName
    System to evaluate BitLocker against.
.PARAMETER DriveLetter
    Drive letter to evaluate BitLocker against.  if NullOrEmpty the default SystemDrive will be used.
.EXAMPLE
    Get-BitLockerStatus
.EXAMPLE
    Get-BitLockerStatus -ComputerName "mycomputer.mydomain.com" -DriveLetter C:
.NOTES
    If no drive letter is specified, the default system drive will be used.
    The drive letter must be followed with a double colon.  IE: "C:".
.LINK
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376483%28v%20=%20vs.85%29.aspx
.LINK
    http://dotps1.github.io
#>
Function Get-BitLockerStatus 
{    
    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateScript({ if (Test-Connection -ComputerName $_ -Quiet -Count 2){ $true }})]
        [String[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(HelpMessage = "Drive letter format must be letter followed by colon, 'C:'")]
        [ValidatePattern('[a-zA-Z]:')]
        [String]
        $DriveLetter
    )

    if (-not ($DriveLetter)) 
    {
        try 
        {
            $drive = Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -ComputerName $ComputerName -Property SystemDrive -ErrorAction Stop
            $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$($drive.SystemDrive)'" -ComputerName $ComputerName -ErrorAction Stop
        }
        catch [System.Exception]
        {
            throw $_
        }
    }
    else 
    {
		try
		{
			$volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
			if ($volume -eq $null) 
			{
				throw "Failed to enumarate the Win32_EncryptableVolume Namespace for $DriveLetter.  Please make sure the drive letter is correct and that the volume is accessable."
			}
		}
		catch [System.Exception]
		{
			throw $_
		}
    }

    switch ($volume.GetConversionStatus().ConversionStatus) 
    {
        0 { $state = "FullyDecrypted" }
        1 { $state = "FullyEncrypted" }
        2 { $state = "EncryptionInProgress" }
        3 { $state = "DecryptionInProgress" }
        4 { $state = "EncryptionPaused" }
        5 { $state = "DecryptionPaused" }
    }

    if ($volume.GetProtectionStatus().ProtectionStatus -eq 0) 
    {
        $protection = "ProtectionOff"
    }
    else 
    {
        $protection = "ProtectionOn"
    }

    $bdeStatus = [PSObject] @{
		'Protection' = $protection
		'State'      = $state
		'Percentage' = $volume.GetConversionStatus().EncryptionPercentage
    }
    
	return $bdeStatus
}

<#
.SYNOPSIS
    Invokes BitLocker on a drive.
.DESCRIPTION
    Invokes BitLocker Drive Encryption on an Encryptable Volume with a TPM and Numrical Password Key Protectors.
    If the Trusted Platform Module is not currently owned, ownership will be taken with randomized 15 character password.
.INPUTS
    System.String.
.OUTPUTS
    None.
.PARAMETER ComputerName
    System to invoke BitLocker against.
.PARAMETER DriveLetter
    Drive letter to invoke BitLocker against.  if NullOrEmpty the SystemDrive will be used.
.PARAMETER ADKeyBackup
    Backups recovery information to the AD DS Object.
.EXAMPLE
    Invoke-BitLockerWithTPMAndNumricalKeyProtectors
.EXAMPLE
    Invoke-BitLockerWithTPMAndNumricalKeyProtectors -ComputerName "mycomputer.mydomain.org" -DriveLetter C: -ADKeyBackup $false
.NOTES
    ADKeyBackup switch requires proper TPM ACL Delegation in Active Directory to be used.
    This function will resume encryption if currently paused, or suspended.
    If used outside of the scope of this module, the Get-TPMStatus and Get-BitLockerStatus cmdlets are required.
.LINK
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376483%28v%20=%20vs.85%29.aspx
.LINK
    http://technet.microsoft.com/en-us/library/dd875529%28v%20=%20ws.10%29.aspx
.LINK
    http://dotps1.github.io
#>
Function Invoke-BitLockerWithTPMAndNumricalKeyProtectors 
{    
    [CmdletBinding()]
    [OutputType([Void])] 
    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateScript({ if (Test-Connection -ComputerName $_ -Quiet -Count 2){ $true }})]
        [String[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [ValidatePattern('[a-zA-Z]:')]
        [String]
        $DriveLetter,

        [Parameter()]
        [Switch]
        $ADKeyBackup
    )

    if (-not (Test-HPTPMEnabledAndActivated -ComputerName $ComputerName))
    {
        throw "The TPM is not properly configured to use as a Key Protector for BitLocker Drive Encryption.  Use the Get-Help Test-HPTPMEnabledAndActivated "
    }

    $tpm = Get-WmiObject -Class Win32_TPM -Namespace "root\CIMV2\Security\MicrosoftTPM" -ComputerName $ComputerName -ErrorAction Stop
    if (-not ($tpm.IsOwned_InitialValue)) 
    {
        $charArray = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray()
        $random = ""
        for ($x = 0; $x -lt 15; $x++) 
        {
            $random += $charArray | Get-Random
        }
        $tpm.TakeOwnership($tpm.ConvertToOwnerAuth($random).OwnerAuth) | Out-Null
    }

    if (-not ($DriveLetter)) 
    {
        try 
        {
            $drive = Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -ComputerName $ComputerName -Property SystemDrive -ErrorAction Stop
            $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$($drive.SystemDrive)'" -ComputerName $ComputerName -ErrorAction Stop
        }
        catch 
        {
            throw "Failed to connect to the necassary WMI Namespaces, to get the system drive.  Verfy that you have sufficent rights to connect to the Win32_OperatingSystem and Win32_EncryptableVolume Namespaces."
        }
    }
    else 
    {
        $volume = Get-WmiObject -Class Win32_EncryptableVolume -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$DriveLetter'" -ComputerName $ComputerName -ErrorAction Stop
        if ($volume -eq $null) 
        {
            throw "Failed to enumarate the Win32_EncryptableVolume Namespace for $DriveLetter.  Please make sure the drive letter is correct and that the volume is accessable."
        }
    }

    if (-not ($volume.GetKeyProtectors(3).VolumeKeyProtectorID)) 
    {
        $volume.ProtectKeyWithNumericalPassword() | Out-Null
        if ($ADKeyBackup.IsPresent) 
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

<#
.SYNOPSIS
    Queries ConfigMgr Database for workstaions where the BDEStatus is false.
.DESCRIPTION
    Queries ConfigMgr Database for any workstation that has completed a Hardware Inventory Scan, looks for the BitLockerProtectionStatus Value, 1 is fully encrypted and Protection is on, 0 for anything else.
    Also uses the inventoried file: 'Orginal System Loader' which is used by TrueCrypt to indicate full disk encryption.
.INPUTS
    None.
.OUTPUTS
    System.Array.
.PARAMETER SqlServer
    The SQL Server containing the ConfigMgr database.
.PARAMETER ConnectionPort
    Port to connect to SQL server with, defualt value is 1433.
.PARAMETER Database
    The name of the ConfigMgr database.
.PARAMETER IntergratedSecurity
    Use the currently logged on users credentials.
.EXAMPLE
    Get-UnEncryptedWorkstationsFromCMDB -Datbase CM_123
.EXAMPLE
    Get-UnEncryptedWorkstationsFromCMDB -SqlServer localhost -Database ConfigMgr -IntergratedSecurity
.NOTES
    The BDE Status of a workstation is not inventoried with ConfigMgr by default, it needs to be enabled in the client settings.
    The file 'Orginal System Loader' is not inventoried with ConfigMgr by default, it needs to be configured in the client settings.
    The file location is %ProgramData%\TrueCrypt\Original System Loader.
.LINK
    http://dotps1.github.io
#>
Function Get-UnEncryptedWorkstationsFromCMDB
{
    [CmdletBinding()]
    [OutputType([Array])]
    Param
    (
        [Parameter()]
        [ValidateScript({ if (-not(Test-Connection -ComputerName $_ -Quiet -Count 2)) { throw "Failed to connect to $_.  Please ensure the system is available." } else { $true } })]
        [String]
        $SqlServer = $env:COMPUTERNAME,

        [Parameter()]
        [ValidateRange(1,50009)]
        [Alias("Port")]
        [Int]
        $ConnectionPort = 1433,

        [Parameter(Mandatory = $true)]
        [String]
        $Database,

        [Parameter()]
        [Switch]
        $IntergratedSecurity
    )

    $sqlConnection = New-Object -TypeName System.Data.SqlClient.SqlConnection -Property @{ ConnectionString = "Server=$SqlServer,$ConnectionPort;Database=$Database;" }

    if ($IntergratedSecurity.IsPresent)
    {
        $sqlConnection.ConnectionString += "Integrated Security=true;"
    }
    else
    {
        $sqlCredentials = Get-Credential
        $sqlConnection.ConnectionString += "User ID=$($sqlCredentials.Username);Password=$($sqlCredentials.GetNetworkCredential().Password);"
    }
    
    try
    {
        $sqlConnection.Open()
    }
    catch [System.Exception]
    {
        throw $_
    }

    $sql = "WITH ct_collectedfiles( filename, 
       				                clientid )
                AS ( SELECT dbo.collectedfiles.filename, 
       			     dbo.collectedfiles.clientid
       		     FROM dbo.collectedfiles ), ct_everything( ComputerName, 
       										               DriveLetter, 
       										               BitLockerStatus )
                AS ( SELECT dbo.computer_system_data.name00 AS ComputerName, 
       			            LEFT( dbo.operating_system_data.systemdirectory00, 2 ) AS DriveLetter, 
       			            CASE dbo.encryptable_volume_data.protectionstatus00
       			            WHEN '1' THEN 'Enabled'
       			            WHEN '0' THEN CASE ct_collectedfiles.filename
       						              WHEN 'Original System Loader' THEN 'Enabled'
       						                  ELSE 'Disabled or Suspended'
       						              END
       			            END AS BitLockerStatus
       		           FROM dbo.operating_system_data
       			            JOIN dbo.encryptable_volume_data ON dbo.operating_system_data.machineid = dbo.encryptable_volume_data.machineid
       			            JOIN dbo.computer_system_data ON dbo.operating_system_data.machineid = dbo.computer_system_data.machineid
       			            LEFT JOIN ct_collectedfiles ON dbo.operating_system_data.machineid = ct_collectedfiles.clientid
       		           WHERE dbo.encryptable_volume_data.driveletter00 = LEFT( dbo.operating_system_data.systemdirectory00, 2 )
       		             AND dbo.operating_system_data.producttype00 <> '3'
       		             AND dbo.computer_system_data.manufacturer00 NOT LIKE '%VMware, Inc.%'
       		             AND dbo.computer_system_data.manufacturer00 NOT LIKE '%Xen%' )
               SELECT *
       	         FROM ct_everything
       	         WHERE BitLockerStatus = 'Disabled or Suspended'
       	         ORDER BY 'ComputerName' ASC"

    $results = (New-Object -TypeName System.Data.SqlClient.SqlCommand -Property @{ CommandText = $sql; Connection = $sqlConnection }).ExecuteReader()

    if ($results.HasRows)
    {
        while ($results.Read())
        {
            $results.GetEnumerator() | %{ New-Object -TypeName PSObject -Property @{  ComputerName    = $_["ComputerName"] 
                                                                                      DriveLetter     = $_["DriveLetter"]
                                                                                      BitLockerStatus = $_["BitLockerStatus"] }}
        }
    }

    $results.Close()
    $sqlConnection.Close()
}