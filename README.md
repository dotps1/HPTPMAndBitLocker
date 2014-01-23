**Highly customized BitLocker Powershell Module for TPM Administration and BitLocker Administration for HP Workstations.**

I have found the "MangeBde.exe" CLI tool a little cumbersome, so I am developing a "More Powerful" BitLocker Module.
Also, the BiosConfigurationUtility from HP is even more cumbersome, with the verbiage being slightly different between models, i need model specific configuration files for every pc I manage.  And a single command cannot be passed to that utility which is ridiculous, so this is a "One Stop Shop" for those tasks.

BDE can be enforced using this simple logic on all models with a TPM:

	if ((Get-TpmStatus) -and (-not(Get-BitLockerStatus)))
	{
		Invoke-BitLockerWithTpmAndNumricalKeyProtectors -ADKeyBackup
	}

Doesn't get much easier then that.  

I have included a new script at the root called Enforce-Bde.ps1 which will incoroperate a random password to set for the Bios Setup Password, make the configuration changes and then remove it.  This script can be ran at start up to fully enforce Bde on HPs

	##Enforce-Bde.ps1
	Import-Module .\HpTpmAndBitLocker.psm1
	$password=powershell ". .\Scripts\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"

	if (-not(Get-TpmStatus))
	{
		if(-not(Get-HpSetupPasswordIsSet))
		{
			Set-HpSetupPassword -NewSetupPassword $password
		}
		Invoke-HpTpm -SetupPassword $password
		Set-HpSetupPassword -NewSetupPassword " " -CurrentSetupPassword $password
		Restart-Computer -Delay 30 -Force -Wait 
	}
	elseif (-not(Get-BitLockerStatus))
	{
		Invoke-BitLockerWithTpmAndNumricalKeyProtectors -ADKeyBackup
	}