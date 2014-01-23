**Highly customized BitLocker PowerShell Module for TPM Administration and BitLocker Administration for HP Workstations.**

I have found the "MangeBde.exe" CLI tool a little cumbersome, so I am developing a "More Powerful" BitLocker Module.
Also, the BiosConfigurationUtility from HP is even more cumbersome, with the verbiage being slightly different between models, i need model specific configuration files for every pc I manage.  And a single command cannot be passed to that utility which is ridiculous, so this is a "One Stop Shop" for those tasks.

BDE can be enforced using this simple logic on all models with a TPM:

	if ((Get-TpmStatus) -and (-not(Get-BitLockerStatus)))
	{
		Invoke-BitLockerWithTpmAndNumricalKeyProtectors -ADKeyBackup
	}

Doesn't get much easier then that.  

I have included a new script at the root called Enforce-Bde.ps1 which will incoroperate a random password to set for the Bios Setup Password, make the configuration changes and then remove it.  This script can be ran at start up to fully enforce Bde on HPs.
If there is a known current password, it can be provided at the top of the script, else one will be randomly generated, then removed.

	##Enforce-Bde.ps1
	Import-Module .\HpTpmAndBitLocker.psm1
	#Current Setup password, if there is not a current password, one will randomly be generated, and removed after configuration completes.
	$password=""

	if (-not(Get-TpmStatus))
	{
		if(-not(Get-HpSetupPasswordIsSet))
		{
			$password=powershell ". .\Scripts\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"
			$randomPasswordUsed=$true
			Set-HpSetupPassword -NewSetupPassword $password
		}
		Invoke-HpTpm -SetupPassword $password
		if ($randomPasswordUsed)
		{
			Set-HpSetupPassword -NewSetupPassword " " -CurrentSetupPassword $password
		}
		
		Restart-Computer -Delay 30 -Force -Wait 
	}
	elseif (-not(Get-BitLockerStatus))
	{
		Invoke-BitLockerWithTpmAndNumricalKeyProtectors -ADKeyBackup
	}