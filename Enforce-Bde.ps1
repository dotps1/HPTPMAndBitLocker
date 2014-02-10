<#
    Enforce-Bde.ps1
    Use this script in conjunction with the the HpTpmAndBitLocker Module to enforce BitLocker Drive Encryption with SCCM
    If the TPM needs to be enabled, it will return a 3010, which can be identifed for a reboot, else return a 0.
#>
Import-Module .\Modules\HpTpmAndBitLocker.psm1
#Current Setup password, if there is not a current password, one will randomly be generated, and removed after configuration completes.
$password=""

if (-not(Get-TpmStatus -ComputerName).Enabled -eq "Yes" -or (-not(Get-TpmStatus -ComputerName).Activated -eq "Yes"))
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