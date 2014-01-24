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
		
	Restart-Computer -Force
}
elseif (-not(Get-BitLockerStatus))
{
	Invoke-BitLockerWithTpmAndNumricalKeyProtectors -ADKeyBackup
}