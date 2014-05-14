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

Import-Module HpTpmAndBitLocker
$password = powershell ". .\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"
$log = ".\Logs\"+(Get-Date -Format yyyyMMdd)+"_Enforce-Bde.ps1.log"
[string[]]$unEncryptedWorkStations = powershell ". .\Scripts\Get-UnEncryptedWorkstationsFromCCMDB.ps1; Get-UnEncryptedWorkstationsFromCCMDB -SqlServer SQL_SERVER_HERE -Database CM_SITE_CODE -IntergratedSecurity"

Write-LogEntry -Path $log -Event "####################################"
Write-LogEntry -Path $log -Event "##### START OF ENFORCEMENT RUN #####"
Write-LogEntry -Path $log -Event "####################################"
Write-LogEntry -Path $log -Event ("Total Number of Unencrypted Workstaitons: " + $unEncryptedWorkStations.Length)

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
        Write-LogEntry -Path $log -Event "Retrieving tpm status for $computer..."
        try
        {
            Write-LogEntry -Path $log -Event ("Tpm enabled: "+(Get-TpmStatus -ComputerName $computer).Enabled) 
            Write-LogEntry -Path $log -Event ("Tpm activated: "+(Get-TpmStatus -ComputerName $computer).Activated) 
        }
        catch
        {
            Write-LogEntry -Path $log -Event $error[0].ToString()
            Continue
        }

        if ((Get-TpmStatus -ComputerName $computer).Enabled -ne "Yes" -or (Get-TpmStatus -ComputerName $computer).Activated -ne "Yes")
        {
            Write-LogEntry -Path $log -Event "Tpm is not properly configured on $computer."
            Write-LogEntry -Path $log -Event "Retrieving setup password state on $computer..."
            try
            {
                if (-not(Get-HpSetupPasswordIsSet -ComputerName $computer))
                {
                    Write-LogEntry -Path $log -Event "Setup password is set: False"
                    Write-LogEntry -Path $log -Event ("Generating password: "+($password=powershell ". .\Scripts\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"))
                    Set-HpSetupPassword -ComputerName $computer -NewPassword $password | %{ Write-LogEntry -Path $log -Event $_ }
                }
                Write-LogEntry -Path $log -Event "Setup password is set: True"
                Invoke-HpTpm -ComputerName $computer -Password $password | %{ Write-LogEntry -Path $log -Event $_ }
                Write-LogEntry -Path $log -Event "Removeing Setup password from $computer..."
                Set-HpSetupPassword -ComputerName $computer -NewPassword " " -CurrentPassword $password | %{ Write-LogEntry -Path $log -Event $_ }
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
            Write-LogEntry -Path $log -Event "Tpm is properly configured on $computer."
            Write-LogEntry -Path $log -Event "Retrieving bitlocker status on $computer..."
            Write-LogEntry -Path $log -Event ("Protection: "+(Get-BitLockerStatus -ComputerName $computer).Protection)
            Write-LogEntry -Path $log -Event ("State: "+(Get-BitLockerStatus -ComputerName $computer).State)
            Write-LogEntry -Path $log -Event ("Percentage: "+(Get-BitLockerStatus -ComputerName $computer).Percentage)
            if ((Get-BitLockerStatus -ComputerName $computer).Protection -eq "ProtectionOn")
            {
                $SMSCli=[wmiclass]"\\$computer\root\ccm:SMS_Client"
                $SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000001}") | Out-Null
                Write-LogEntry -Path $log -Event "Computer is fully encrypted and protection is on, triggering ccm hardware inventory cycle for $computer..."
            }
            elseif (Test-Path "$env:ProgramData\TrueCrypt\Orginal System Loader")
            {
                $SMSCli=[wmiclass]"\\$computer\root\ccm:SMS_Client"
                $SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000002}") | Out-Null
                Write-LogEntry -Path $log -Event "Computer is fully encrypted with True Crypt Full Disk Encryption, triggering ccm software enventory cycle for $computer..."
            }
            elseif ((Get-BitLockerStatus -ComputerName $computer).State -ne "EncryptionInProgress")
            {
                Write-LogEntry -Path $log -Event "Invoking bitlocker drive encryption on $computer."
        
                Invoke-BitLockerWithTpmAndNumricalKeyProtectors -ComputerName $computer -ADKeyBackup | Out-Null

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