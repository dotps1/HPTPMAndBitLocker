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