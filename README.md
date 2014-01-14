**Highly customized BitLocker Powershell Module for TPM Administration and BitLocker Administration for HP Workstations.**

I have found the "MangeBde.exe" CLI tool a little cumbersome, so I am developing a "More Powerful" BitLocker Module.
Also, the BiosConfigurationUtility from HP is even more cumbersome, with the verbiage being slightly different between models, i need model specific configuration files for every pc I manage.  And a single command cannot be passed to that utility which is ridiculous, so this is a "One Stop Shop" for those tasks.

BDE can be enforced using this simple logic on all models with a TPM:

	if ((Get-TpmStatus) -and (-not(Get-BitLockerStatus)))
	{
		Invoke-BitLockerWithTpmAndNumricalKeyProtectors -ADKeyBackup
	}

Doesn't get much easier then that.  

For HPs, this logic can fully implement BDE, even if the TPM is not active:

	if (-not(Get-TpmStatus))
	{
		if(-not(Get-HpSetupPasswordIsSet))
		{
			Set-HpSetupPassword -NewSetupPassword MySetupPassword
		}
		Invoke-HpTpm -SetupPassword MySetupPassword -RestartComputer -Restart Delay 30
	}
	elseif (-not(Get-BitLockerStatus))
	{
		Invoke-BitLockerWithTpmAndNumricalKeyProtectors -ADKeyBackup
	}
	
With that running at start-up, will full enforce BDE.