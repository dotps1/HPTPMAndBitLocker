<#
.SYNOPSIS
    Queries ConfigMgr Database for BitLockerProtectionStatus Boolean Value. 
.DESCRIPTION
    Queries ConfigMgr Database for any workstation that has completed a Hardware Inventory Scan, looks for the BitLockerProtectionStatus Value, 1 is fully encrypted and Protection is on, 0 for anything else.
    Also uses the inventoried file: 'Orginal System Loader' which is used by TrueCrypt to indicate full disk encryption.
.EXAMPLE
    Get-UnEncryptedWorkstations
.EXAMPLE
    Get-UnEncryptedWorkstations -SqlServer localhost -Database ConfigMgr -IntergratedSecurity
.NOTES
    The BDE Status of a workstation is not inventoried with ConfigMgr by default, it needs to be enabled in the client settings..
    The file 'Orginal System Loader' is not inventoried with ConfigMgr by default, it needs to be configured in the client settings.
    The file location is %ProgramData%\TrueCrypt\Original System Loader.
.LINK
    https://gist.github.com/necromorph1024/9215724
#>
function Get-UnEncryptedWorkstations
{
    [CmdletBinding()]
    [OutputType([array])]
    Param
    (
        # SqlServer, Type string, The SQL Server containing the ConfigMgr database.
        [Parameter(Mandatory=$true,
                   Position=0)]
        [string]
        $SqlServer=$env:COMPUTERNAME,

        # ConnectionPort, Type int, Port to connect to SQL server with, defualt value is 1433.
        [parameter(Position=1)]
        [ValidateRange(1,50009)]
        [Alias("Port")]
        [int]
        $ConnectionPort=1433,

        # Database, Type string, The name of the ConfigMgr database.
        [Parameter(Mandatory=$true,
                   Position=2)]
        [string]
        $Database,

        # IntergratedSecurity, Type switch, Use the currently logged on users credentials.
        [switch]
        $IntergratedSecurity
    )

    $sqlConnection=New-Object System.Data.SqlClient.SqlConnection
    $sqlConnection.ConnectionString="Server=$SqlServer,$ConnectionPort;Database=$Database;Integrated Security="
    if ($IntergratedSecurity)
    {
        $sqlConnection.ConnectionString+="true;"
    }
    else
    {
        $sqlCredentials=Get-Credential
        $sqlConnection.ConnectionString+="false;User ID=$($sqlCredentials.Username);Password=$($sqlCredentials.GetNetworkCredential().Password);"
    }
    
    try
    {
        $sqlConnection.Open()
    }
    catch
    {
        throw $Error[0].Exception.Message
    }

    $sqlCMD=New-Object System.Data.SqlClient.SqlCommand
    $sqlCMD.CommandText="with ct_CollectedFiles (FileName,ClientID) as
                        (select   dbo.CollectedFiles.FileName,
		                          dbo.CollectedFiles.ClientID
                         from     dbo.CollectedFiles),

                        ct_Everything (ComputerName,DriveLetter,BitLockerStatus) as
                        (select   dbo.Computer_System_DATA.Name00                       as ComputerName,
                                  left(dbo.Operating_System_DATA.SystemDirectory00, 2)  as DriveLetter,
	                              case dbo.ENCRYPTABLE_VOLUME_DATA.ProtectionStatus00
		                               when '1' then 'Enabled'
			                           when '0' then case ct_CollectedFiles.FileName
							                              when 'Original System Loader' then 'Enabled'
							                              else 'Disabled or Suspended'
							                         end
	                              end                                                   as BitLockerStatus
                         from     dbo.Operating_System_DATA
	                         join dbo.ENCRYPTABLE_VOLUME_DATA on dbo.Operating_System_DATA.MachineID = dbo.ENCRYPTABLE_VOLUME_DATA.MachineID
	                         join dbo.Computer_System_DATA    on dbo.Operating_System_DATA.MachineID = dbo.Computer_System_DATA.MachineID
	                         left join ct_CollectedFiles      on dbo.Operating_System_DATA.MachineID = ct_CollectedFiles.ClientID
                         where    dbo.ENCRYPTABLE_VOLUME_DATA.DriveLetter00 = left(dbo.Operating_System_DATA.SystemDirectory00, 2)
                             and  dbo.Operating_System_Data.ProductType00 <> '3'
	                         and  dbo.Computer_System_DATA.Manufacturer00 not like '%VMware, Inc.%' and dbo.Computer_System_DATA.Manufacturer00 not like '%Xen%')

                        select    *
                        from      ct_Everything
                        where     BitLockerStatus = 'Disabled or Suspended'
                        order by  'ComputerName' asc"
    $sqlCMD.Connection = $sqlConnection

    $results=$sqlCMD.ExecuteReader()
    If ($results.HasRows)
    {
        While ($results.Read())
        {
            $workstations+=@($results["ComputerName"])
        }
        return $workstations
    }

    $results.Close()
    $sqlConnection.Close()
}