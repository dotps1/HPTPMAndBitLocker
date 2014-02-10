###*THIS MODULE HAS THE ABILITY TO MODIFY BIOS SETTINGS USE AT YOUR OWN RISK*###

**Highly customized BitLocker PowerShell Module for TPM Administration and BitLocker Administration for HP Workstations.**

I have found the "MangeBde.exe" CLI tool a little cumbersome, so I am developing a "More Powerful" BitLocker Module.
Also, the BiosConfigurationUtility from HP is even more cumbersome, with the verbiage being slightly different between models, i need model specific configuration files for every pc I manage.  And a single command cannot be passed to that utility which is ridiculous, so this is a "One Stop Shop" for those tasks.

I have included a new script at the root called Enforce-Bde.ps1 which will incorporate a random password to set for the Bios Setup Password, make the configuration changes and then remove it.  This script can be ran at start up to fully enforce Bde on HPs.
If there is a known current password, it can be provided at the top of the script, else one will be randomly generated, then removed.  The return codes are used to detect events in SCCM task sequence to trigger reboots, allowing the Task sequence to wait for the reboot then enable bitlocker after the system is back up.

	<#
		Enforce-Bde.ps1
		Use this script in conjunction with the the HpTpmAndBitLocker Module to enforce BitLocker Drive Encryption with SCCM
		If the TPM needs to be enabled, it will return a 3010, which can be identified for a reboot, else return a 0.
	#>
	Import-Module .\Modules\HpTpmAndBitLocker.psm1
	#Current Setup password, if there is not a current password, one will randomly be generated, and removed after configuration completes.
	$password=""

	if (-not(Get-TpmStatus).Enabled -eq "Yes" -or (-not(Get-TpmStatus).Activated -eq "Yes"))
	{
		if(-not(Get-HpSetupPasswordIsSet))
		{
			$password=powershell ". .\Scripts\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"
			$randomPasswordUsed=$true
			Set-HpSetupPassword -NewPassword $password
		}

		Invoke-HpTpm -Password $password

		if ($randomPasswordUsed)
		{
			Set-HpSetupPassword -NewPassword " " -CurrentPassword $password
		}
			
		exit 3010
	}

	exit 0