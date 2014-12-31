# Globals

$SqlServer = [String]::Empty
$CCMDatabase = [String]::Empty

if ([String]::IsNullOrEmpty($SqlServer) -or [String]::IsNullOrEmpty($CCMDatabase))
{
	throw "You must provide the CCM SqlServerName and Database to use this script"
	exit
}

# End Globals

# Functions

<#
.SYNOPSIS
	Logs Events to a a logfile.
.DESCRIPTION
	Logs all errors foreach operation to a file.
.INPUT
    System.String
.OUTPUT
    None.
.EXAMPLE
	Write-LogEntry -Path C:\My.log -Event "MyEvent: Event"
#>
Function Write-LogEntry
{
	[CmdletBinding()]
	[OutputType([Void])]
	Param
	(
		# Path, Type string, File path to the log.
		[Parameter(Mandatory = $true)]
		[string]
		$Path,

		# Event, Type string, Event entry to append to the log.
		[parameter(Mandatory = $true,
					ValueFromPipeLineByPropertyName = $true)]
		[string[]]
		$Event
	)

	Add-Content $Path -Value ((Get-Date).ToLongDateString()+" "+(Get-Date).ToLongTimeString()+": "+$Event)
}

# End Functions

# Main

Import-Module HPTPMAndBitLocker
$password = powershell ". .\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"
$log = ".\Logs\$(Get-Date -Format yyyyMMdd)_Enforce-BDE.ps1.log"
[String[]]$unEncryptedWorkStations = (Get-UnEncryptedWorkstationsFromCCMDB -SqlServer $SqlServer -Database $CCMDatabase -IntergratedSecurity).ComputerName

Write-LogEntry -Path $log -Event "####################################"
Write-LogEntry -Path $log -Event "##### START OF ENFORCEMENT RUN #####"
Write-LogEntry -Path $log -Event "####################################"
Write-LogEntry -Path $log -Event ("Total Number of Unencrypted Workstations: $($unEncryptedWorkStations.Length)")

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
			
		Write-LogEntry -Path $log -Event "Testing for TrueCrypt Disk Encryption on $computer..."
		if (Test-Path "$env:ProgramData\TrueCrypt\Original System Loader")
		{
			$SMSCli = [WmiClass]"\\$computer\root\ccm:SMS_Client"
			$SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000002}") | Out-Null
			Write-LogEntry -Path $log -Event "Computer is fully encrypted with TrueCrypt Full Disk Encryption, triggering ccm software inventory cycle for $computer..."
			break
		}
		else
		{
			Write-LogEntry -Path $log -Event "TrueCrypt Disk Encryption not detected on $computer..."
		}
		Write-LogEntry -Path $log -Event "Retrieving TPM status for $computer..."
		try
		{
            Write-LogEntry -Path $log -Event ("TPM Propoerly Configured: $(Test-HPTPMEnabledAndActivated -ComputerName $computer)") 
		}
		catch
		{
			Write-LogEntry -Path $log -Event $error[0].ToString()
			Continue
		}

		if (-not (Test-HPTPMEnabledAndActivated -ComputerName $computer))
		{
			Write-LogEntry -Path $log -Event "TPM is not properly configured on $computer."
			Write-LogEntry -Path $log -Event "Retrieving setup password state on $computer..."
			try
			{
				if (-not(Get-HPBiosSetupPasswordIsSet -ComputerName $computer))
				{
					Write-LogEntry -Path $log -Event "Setup password is set: False"
					Write-LogEntry -Path $log -Event ("Generating password: " + ($password = powershell ". .\Scripts\New-RandomPassword.ps1; New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers"))
					Set-HPBiosSetupPassword -ComputerName $computer -NewPassword $password | %{ Write-LogEntry -Path $log -Event $_ }
				}
				Write-LogEntry -Path $log -Event "Setup password is set: True"
				Invoke-HPTPM -ComputerName $computer -Password $password | %{ Write-LogEntry -Path $log -Event $_ }
				Write-LogEntry -Path $log -Event "Removing Setup password from $computer..."
				Set-HPBiosSetupPassword -ComputerName $computer -NewPassword " " -CurrentPassword $password | %{ Write-LogEntry -Path $log -Event $_ }
				Write-LogEntry -Path $log -Event "System reboot required to complete TPM configuration.  BitLocker will be enforced on next run after reboot."
			}
			catch
			{
				Write-LogEntry -Path $log -Event $error[0].ToString()
				Continue
			}
		}
		else
		{
			Write-LogEntry -Path $log -Event "TPM is properly configured on $computer."
			Write-LogEntry -Path $log -Event "Retrieving BitLocker status on $computer..."
			Write-LogEntry -Path $log -Event ("Protection: $((Get-BitLockerStatus -ComputerName $computer).Protection)")
			Write-LogEntry -Path $log -Event ("State: $((Get-BitLockerStatus -ComputerName $computer).State)")
			Write-LogEntry -Path $log -Event ("Percentage: $((Get-BitLockerStatus -ComputerName $computer).Percentage)")
			if ((Get-BitLockerStatus -ComputerName $computer).Protection -eq "ProtectionOn")
			{
				$SMSCli = [WmiClass]"\\$computer\root\ccm:SMS_Client"
				$SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000001}") | Out-Null
				Write-LogEntry -Path $log -Event "Computer is fully encrypted and protection is on, triggering ccm hardware inventory cycle for $computer..."
			}
			elseif ((Get-BitLockerStatus -ComputerName $computer).State -ne "EncryptionInProgress")
			{
				Write-LogEntry -Path $log -Event "Invoking BitLocker drive encryption on $computer."
			
				Invoke-BitLockerWithTPMAndNumricalKeyProtectors -ComputerName $computer -ADKeyBackup | Out-Null

				Write-LogEntry -Path $log -Event ("Protection: $((Get-BitLockerStatus -ComputerName $computer).Protection)")
				Write-LogEntry -Path $log -Event ("State: $((Get-BitLockerStatus -ComputerName $computer).State)")
				Write-LogEntry -Path $log -Event ("Percentage: $((Get-BitLockerStatus -ComputerName $computer).Percentage)")
			}
		}
	}
}

Write-LogEntry -Path $log -Event "##################################"
Write-LogEntry -Path $log -Event "##### END OF ENFORCEMENT RUN #####"
Write-LogEntry -Path $log -Event "##################################"

# End Main