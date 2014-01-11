Highly customized BitLocker Powershell Module for TPM Administration and BitLocker Administration.

I have found the "MangeBde.exe" CLI tool a little cumbersome, so I am developing a "More Powerfull" BitLocker Module.
Currently it supports the retrevial of the TPM State and the BitLocker State as well as Invoking BitLocker with TPM and Numrical Key Protectors.

I am also working on an HPBios Module that has the ability to enable the TPM, it can be found here:
https://github.com/necromorph1024/HPBiosConfigurationPowershellModule

In my current Domain Envrionment, with this module, I can enforce BDE with the following logic:

If ((Get-TpmStatus) -and (-not(Get-BitLockerStatus -ADKeyBackup $true)))
{
	Invoke-BitLockerWithTpmAndNumricalKeyProtectors
}

Doesn't get much easier then that.  

As the HPBios Module develops, I will be able to enable the TPM (on HP's) when the Get-TpmStatus returns $false.