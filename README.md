###*THIS MODULE HAS THE ABILITY TO MODIFY BIOS SETTINGS USE AT YOUR OWN RISK*###

**Highly customized BitLocker PowerShell Module for TPM Administration and BitLocker Administration for HP Workstations.**

I have found the "MangeBde.exe" CLI tool a little cumbersome, so I am developing a "More Powerful" BitLocker  PowerShell Module.
Also, the BiosConfigurationUtility from HP is even more cumbersome to manage TPM, with the verbiage being slightly different between models, I need model specific configuration files for every pc I manage to activate and enable TPM.

This Modules contains the following Functions:
* Out-HPVerboseReturnValues
* ConvertTo-KBDString
* Get-HPSetupPasswordIsSet
* Set-HPSetupPassword
* Get-TPMStatus
* Invoke-HPTPM
* Get-BitLockerStatus
* Invoke-BitLockerWithTPMAndNumricalKeyProtectors

The first two functions are more for internal use of the module, the three HP tailored functions are *-HP* are tailored specifically for HP BIOS and TPM administration, essentially replacing the BiosConfigurationUtility usage TPM.  The remaining functions can be used on any workstation.

	# Configure TPM on HP Models:
	Import-Module .\HPTpmAndBitLocker.psm1
	# Current Setup Password, if there is not a current password, one will randomly be generated, and removed after configuration completes.
	# A Setup Password is required for pragmatically modifying the BIOS.
	$password = ""

	if (-not(Get-TPMStatus).Enabled -eq "Yes" -or (-not(Get-TPMStatus).Activated -eq "Yes"))
	{
		if(-not(Get-HPSetupPasswordIsSet))
		{
			$password = powershell ". .\Scripts\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"
			$randomPasswordUsed = $true
			Set-HPSetupPassword -NewPassword $password
		}

		Invoke-HPTPM -Password $password

		if ($randomPasswordUsed)
		{
			Set-HPSetupPassword -NewPassword " " -CurrentPassword $password
		}
	}
	
I have included a function script in the .\Scripts Directory that will get unencrypted PCs from a CCM database so you can foreach this function on the systems and enforce BDE.

	[string[]]$unEncryptedWorkStations=powershell ". .\Scripts\Get-UnEncryptedWorkstationsFromCCMDB.ps1; Get-UnEncryptedWorkstationsFromCCMDB -SqlServer SCCM_DB_Server -Database CM_ABC -IntergratedSecurity"
	
	foreach ($computer in $unEncryptedWorkStations)
	{
		# do things to enforce BitLocker....
	}
	
**UPDATE**

I have added a second script in the .\Scripts Directory called Enforce-Bde.ps1 that has a full enforcement and logging, just sent the params for your Logs Directory and for your ConfigMgr SQL Server.  You need to enable BitLockerDrive status in your ConfigMgr Client Settings to use this Script.
	
	####################################
	#Enforce-Bde.ps1
	#By Thomas Malkewitz @PowerShellSith
	#Enforce BitLocker Drive Encrytion on HP workstations using HPTPMAndBitLocker.psm1 and SCCM_DB_Server
	#USE AT YOUR OWN RISK
	####################################
	
	# Helper Log Function
	<#
	.SYNOPSIS
	   Logs Events to a a logfile.
	.DESCRIPTION
	   Logs all errors foreach operation to a file.
	.EXAMPLE
	   Write-LogEntry -Path C:\My.log -Event "MyEvent: Event"
	#>
	function Write-LogEntry
	{
		[CmdletBinding()]
		[OutputType([void])]
		Param
		(
			# Path, Type string, File path to the log.
			[Parameter(Mandatory=$true,
					   Position=0)]
			[string]
			$Path,

			# Event, Type string, Event entry to append to the log.
			[parameter(Mandatory=$true,
					   ValueFromPipeLineByPropertyName=$true,
					   Position=1)]
			[string[]]
			$Event
		)

		Add-Content $Path -Value ((Get-Date).ToLongDateString()+" "+(Get-Date).ToLongTimeString()+": "+$Event)
	}

	Import-Module HPTPMAndBitLocker
	$password = powershell ". .\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"
	$log = ".\Logs\"+(Get-Date -Format yyyyMMdd)+"_Enforce-BDE.ps1.log"
	[string[]]$unEncryptedWorkStations = powershell ". .\Scripts\Get-UnEncryptedWorkstationsFromCCMDB.ps1; Get-UnEncryptedWorkstationsFromCCMDB -SqlServer SQL_SERVER_HERE -Database CM_SITE_CODE -IntergratedSecurity"

	Write-LogEntry -Path $log -Event "####################################"
	Write-LogEntry -Path $log -Event "##### START OF ENFORCEMENT RUN #####"
	Write-LogEntry -Path $log -Event "####################################"
	Write-LogEntry -Path $log -Event ("Total Number of Unencrypted Workstations: " + $unEncryptedWorkStations.Length)

	foreach ($computer in $unEncryptedWorkStations)
	{
		Write-LogEntry -Path $log -Event "Attempting to ping $computer..."

		if (-not(Test-Connection $computer -Count 1 -ErrorAction SilentlyContinue))
		{
			Write-LogEntry -Path $log -Event $error[0].ToString()
		}
		else
		{
			Write-LogEntry -Path $log -Event "Successfully contacted $computer."
			
			Write-LogEntry -Path $log -Event "Testing for TrueCrypt Disk Encryption on $computer..."
			if (Test-Path "$env:ProgramData\TrueCrypt\Orginal System Loader")
			{
				$SMSCli=[wmiclass]"\\$computer\root\ccm:SMS_Client"
				$SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000002}") | Out-Null
				Write-LogEntry -Path $log -Event "Computer is fully encrypted with TrueCrypt Full Disk Encryption, triggering ccm software inventory cycle for $computer..."
				break
			}
			else
			{
				Write-LogEntry -Path $log -Event "TrueCrypt Disk Encryption not detected on $computer..."
			}
			Write-LogEntry -Path $log -Event "Retrieving tpm status for $computer..."
			try
			{
				Write-LogEntry -Path $log -Event ("TPM enabled: "+(Get-TPMStatus -ComputerName $computer).Enabled) 
				Write-LogEntry -Path $log -Event ("TPM activated: "+(Get-TPMStatus -ComputerName $computer).Activated) 
			}
			catch
			{
				Write-LogEntry -Path $log -Event $error[0].ToString()
				Continue
			}

			if ((Get-TPMStatus -ComputerName $computer).Enabled -ne "Yes" -or (Get-TPMStatus -ComputerName $computer).Activated -ne "Yes")
			{
				Write-LogEntry -Path $log -Event "TPM is not properly configured on $computer."
				Write-LogEntry -Path $log -Event "Retrieving setup password state on $computer..."
				try
				{
					if (-not(Get-HPSetupPasswordIsSet -ComputerName $computer))
					{
						Write-LogEntry -Path $log -Event "Setup password is set: False"
						Write-LogEntry -Path $log -Event ("Generating password: "+($password=powershell ". .\Scripts\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"))
						Set-HPSetupPassword -ComputerName $computer -NewPassword $password | %{ Write-LogEntry -Path $log -Event $_ }
					}
					Write-LogEntry -Path $log -Event "Setup password is set: True"
					Invoke-HPTPM -ComputerName $computer -Password $password | %{ Write-LogEntry -Path $log -Event $_ }
					Write-LogEntry -Path $log -Event "Removing Setup password from $computer..."
					Set-HPSetupPassword -ComputerName $computer -NewPassword " " -CurrentPassword $password | %{ Write-LogEntry -Path $log -Event $_ }
					Write-LogEntry -Path $log -Event "System reboot required to complete tpm configuration.  BitLocker will be enforced on next run after reboot."
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
				Write-LogEntry -Path $log -Event ("Protection: "+(Get-BitLockerStatus -ComputerName $computer).Protection)
				Write-LogEntry -Path $log -Event ("State: "+(Get-BitLockerStatus -ComputerName $computer).State)
				Write-LogEntry -Path $log -Event ("Percentage: "+(Get-BitLockerStatus -ComputerName $computer).Percentage)
				if ((Get-BitLockerStatus -ComputerName $computer).Protection -eq "ProtectionOn")
				{
					$SMSCli=[wmiclass]"\\$computer\root\ccm:SMS_Client"
					$SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000001}") | Out-Null
					Write-LogEntry -Path $log -Event "Computer is fully encrypted and protection is on, triggering ccm hardware inventory cycle for $computer..."
				}
				elseif ((Get-BitLockerStatus -ComputerName $computer).State -ne "EncryptionInProgress")
				{
					Write-LogEntry -Path $log -Event "Invoking BitLocker drive encryption on $computer."
			
					Invoke-BitLockerWithTPMAndNumricalKeyProtectors -ComputerName $computer -ADKeyBackup | Out-Null

					Write-LogEntry -Path $log -Event ("Protection: "+(Get-BitLockerStatus -ComputerName $computer).Protection)
					Write-LogEntry -Path $log -Event ("State: "+(Get-BitLockerStatus -ComputerName $computer).State)
					Write-LogEntry -Path $log -Event ("Percentage: "+(Get-BitLockerStatus -ComputerName $computer).Percentage)
				}
			}
		}
	}

	Write-LogEntry -Path $log -Event "##################################"
	Write-LogEntry -Path $log -Event "##### END OF ENFORCEMENT RUN #####"
	Write-LogEntry -Path $log -Event "##################################"