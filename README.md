###*THIS MODULE HAS THE ABILITY TO MODIFY BIOS SETTINGS USE AT YOUR OWN RISK*###

**Highly customized BitLocker PowerShell Module for TPM Administration and BitLocker Administration for HP Workstations.**

I have found the "MangeBde.exe" CLI tool a little cumbersome, so I am developing a "More Powerful" BitLocker Module.
Also, the BiosConfigurationUtility from HP is even more cumbersome, with the verbiage being slightly different between models, I need model specific configuration files for every pc I manage.  And a single command cannot be passed to that utility which is ridiculous, so this is a "One Stop Shop" for those tasks.


	Import-Module .\HpTpmAndBitLocker.psm1
	#Current Setup Password, if there is not a current password, one will randomly be generated, and removed after configuration completes.
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
	}
	
I have included a function script in the .\Scripts Directory that will get unencrypted PCs from a CCM database so you can foreach this function on the systems and enforce BDE.

	[string[]]$unEncryptedWorkStations=powershell ". .\Scripts\Get-UnEncryptedWorkstationsFromCCMDB.ps1; Get-UnEncryptedWorkstationsFromCCMDB -SqlServer SCCM_DB_Server -Database CM_ABC -IntergratedSecurity"
	
	foreach ($computer in $unEncryptedWorkStations)
	{
		# do things.
	}
	
**UPDATE**

I have added a second script in the .\Scripts Directory called Enforce-Bde.ps1 that has a full enforcement and logging, just sent the params for your Logs Directory and for your ConfigMgr SQL Server.