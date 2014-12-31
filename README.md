###*THIS MODULE HAS THE ABILITY TO MODIFY BIOS SETTINGS USE AT YOUR OWN RISK*###

**Highly customized BitLocker PowerShell Module for TPM Administration and BitLocker Administration for HP Workstations.**

I have found the "MangeBde.exe" CLI tool a little cumbersome, so I am developing a "More Powerful" BitLocker  PowerShell Module.
Also, the BiosConfigurationUtility from HP is even more cumbersome to manage TPM, with the verbiage being slightly different between models, I need model specific configuration files for every pc I manage to activate and enable TPM.

This Modules contains the following Functions:
* Get-HPBiosSetupPasswordIsSet
* Test-HPBiosSetupPassword
* Test-HPTPMEnabledAndActivated 
* Invoke-HPTPM
* Get-BitLockerStatus
* Invoke-BitLockerWithTPMAndNumricalKeyProtectors
* Get-UnEncryptedWorkstationsFromCMDB

The first two functions are more for internal use of the module, the three HP tailored functions are *-HP* are tailored specifically for HP BIOS and TPM administration, essentially replacing the BiosConfigurationUtility usage TPM.  The remaining functions can be used on any workstation.
```PowerShell
# Configure TPM on HP Models:
Import-Module .\HPTpmAndBitLocker.psm1
# Current Setup Password, if there is not a current password, one will randomly be generated, and removed after configuration completes.
# A Setup Password is required for pragmatically modifying the BIOS.
$password = ""

if (-not (Test-HPTPMEnabledAndActivated))
{
	if(-not(Test-HPBiosSetupPasswordIsSet))
	{
		$password = powershell ". .\Scripts\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"
		$randomPasswordUsed = $true
		Set-HPBiosSetupPassword -NewPassword $password
	}

	Invoke-HPTPM -Password $password

	if ($randomPasswordUsed)
	{
		Set-HPBiosSetupPassword -NewPassword " " -CurrentPassword $password
	}
}
```
	
I have included a function in this module that will get unencrypted PCs from a SCCM database so you can foreach the value on the systems and enforce BDE.
```PowerShell
Import-Module HPTPMAndBitLocker
[String[]]$unEncryptedWorkStations = (Get-UnEncryptedWorkstationsFromCMDB -SqlServer SCCM_DB_Server -Database CM_ABC -IntergratedSecurity).ComputerName

foreach ($workstation in $unEncryptedWorkStations)
{
	# do things to Enforce BitLocker....
}
```
	
**UPDATE**

I have added a second script in the .\Scripts Directory called Enforce-Bde.ps1 that has a full enforcement and logging, just sent the params for your Logs Directory and for your ConfigMgr SQL Server.  You need to enable BitLockerDrive status in your ConfigMgr Client Settings to use this Script.
```PowerShell
# Globals

$SqlServer = [String]::Empty
$CCMDatabase = [String]::Empty

if ([String]::IsNullOrEmpty($SqlServer) -or [String]::IsNullOrEmpty($CCMDatabase))
{
	throw "You must provide the CCM SqlServerName and Database to use this script"
	exit
}

# End Globals

# Functions

<#
.SYNOPSIS
	Logs Events to a a logfile.
.DESCRIPTION
	Logs all errors foreach operation to a file.
.INPUT
    System.String
.OUTPUT
    None.
.EXAMPLE
	Write-LogEntry -Path C:\My.log -Event "MyEvent: Event"
#>
Function Write-LogEntry
{
	[CmdletBinding()]
	[OutputType([Void])]
	Param
	(
		# Path, Type string, File path to the log.
		[Parameter(Mandatory = $true)]
		[String]
		$Path,

		# Event, Type string, Event entry to append to the log.
		[parameter(Mandatory = $true,
					ValueFromPipeLineByPropertyName = $true)]
		[String[]]
		$Event
	)

	Add-Content $Path -Value ((Get-Date).ToLongDateString()+" "+(Get-Date).ToLongTimeString()+": "+$Event)
}

# End Functions

# Main

Import-Module HPTPMAndBitLocker
$password = PowerShell ". .\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"
$log = ".\Logs\$(Get-Date -Format yyyyMMdd)_Enforce-BDE.ps1.log"
[String[]]$unEncryptedWorkStations = (Get-UnEncryptedWorkstationsFromCCMDB -SqlServer $SqlServer -Database $CCMDatabase -IntergratedSecurity).ComputerName

Write-LogEntry -Path $log -Event "####################################"
Write-LogEntry -Path $log -Event "##### START OF ENFORCEMENT RUN #####"
Write-LogEntry -Path $log -Event "####################################"
Write-LogEntry -Path $log -Event ("Total Number of Unencrypted Workstations: $($unEncryptedWorkStations.Length)")

foreach ($computer in $unEncryptedWorkStations)
{
	Write-LogEntry -Path $log -Event "Attempting to ping $computer..."

	if (-not (Test-Connection $computer -Count 1 -ErrorAction SilentlyContinue))
	{
		Write-LogEntry -Path $log -Event $Error[0].ToString()
	}
	else
	{
		Write-LogEntry -Path $log -Event "Successfully contacted $computer."
			
		Write-LogEntry -Path $log -Event "Testing for TrueCrypt Disk Encryption on $computer..."
		if (Test-Path "$env:ProgramData\TrueCrypt\Original System Loader")
		{
			$SMSCli = [WmiClass]"\\$computer\root\ccm:SMS_Client"
			$SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000002}") | Out-Null
			Write-LogEntry -Path $log -Event "Computer is fully encrypted with TrueCrypt Full Disk Encryption, triggering ccm software inventory cycle for $computer..."
			break
		}
		else
		{
			Write-LogEntry -Path $log -Event "TrueCrypt Disk Encryption not detected on $computer..."
		}
		Write-LogEntry -Path $log -Event "Retrieving TPM status for $computer..."
		try
		{
            Write-LogEntry -Path $log -Event ("TPM Properly Configured: $(Test-HPTPMEnabledAndActivated -ComputerName $computer)") 
		}
		catch
		{
			Write-LogEntry -Path $log -Event $error[0].ToString()
			Continue
		}

		if (-not (Test-HPTPMEnabledAndActivated -ComputerName $computer))
		{
			Write-LogEntry -Path $log -Event "TPM is not properly configured on $computer."
			Write-LogEntry -Path $log -Event "Retrieving setup password state on $computer..."
			try
			{
				if (-not(Test-HPBiosSetupPasswordIsSet -ComputerName $computer))
				{
					Write-LogEntry -Path $log -Event "Setup password is set: False"
					Write-LogEntry -Path $log -Event ("Generating password: " + ($password = powershell ". .\Scripts\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"))
					Set-HPBiosSetupPassword -ComputerName $computer -NewPassword $password | %{ Write-LogEntry -Path $log -Event $_ }
				}
				Write-LogEntry -Path $log -Event "Setup password is set: True"
				Invoke-HPTPM -ComputerName $computer -Password $password | %{ Write-LogEntry -Path $log -Event $_ }
				Write-LogEntry -Path $log -Event "Removing Setup password from $computer..."
				Set-HPBiosSetupPassword -ComputerName $computer -NewPassword " " -CurrentPassword $password | %{ Write-LogEntry -Path $log -Event $_ }
				Write-LogEntry -Path $log -Event "System reboot required to complete TPM configuration.  BitLocker will be enforced on next run after reboot."
			}
			catch
			{
				Write-LogEntry -Path $log -Event $error[0].ToString()
				Continue
			}
		}
		else
		{
			Write-LogEntry -Path $log -Event "TPM is properly configured on $computer."
			Write-LogEntry -Path $log -Event "Retrieving BitLocker status on $computer..."
			Write-LogEntry -Path $log -Event ("Protection: $((Get-BitLockerStatus -ComputerName $computer).Protection)")
			Write-LogEntry -Path $log -Event ("State: $((Get-BitLockerStatus -ComputerName $computer).State)")
			Write-LogEntry -Path $log -Event ("Percentage: $((Get-BitLockerStatus -ComputerName $computer).Percentage)")
			if ((Get-BitLockerStatus -ComputerName $computer).Protection -eq "ProtectionOn")
			{
				$SMSCli = [WmiClass]"\\$computer\root\ccm:SMS_Client"
				$SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000001}") | Out-Null
				Write-LogEntry -Path $log -Event "Computer is fully encrypted and protection is on, triggering ccm hardware inventory cycle for $computer..."
			}
			elseif ((Get-BitLockerStatus -ComputerName $computer).State -ne "EncryptionInProgress")
			{
				Write-LogEntry -Path $log -Event "Invoking BitLocker drive encryption on $computer."
			
				Invoke-BitLockerWithTPMAndNumricalKeyProtectors -ComputerName $computer -ADKeyBackup | Out-Null

				Write-LogEntry -Path $log -Event ("Protection: $((Get-BitLockerStatus -ComputerName $computer).Protection)")
				Write-LogEntry -Path $log -Event ("State: $((Get-BitLockerStatus -ComputerName $computer).State)")
				Write-LogEntry -Path $log -Event ("Percentage: $((Get-BitLockerStatus -ComputerName $computer).Percentage)")
			}
		}
	}
}

Write-LogEntry -Path $log -Event "##################################"
Write-LogEntry -Path $log -Event "##### END OF ENFORCEMENT RUN #####"
Write-LogEntry -Path $log -Event "##################################"

# End Main
```