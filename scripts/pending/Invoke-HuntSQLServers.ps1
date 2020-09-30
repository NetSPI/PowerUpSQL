# ------------------------------------------
# Function:  Invoke-HuntSQLServers
# ------------------------------------------
# Author: Scott Sutherland, NetSPI
# License: 3-clause BSD
# Version 1.2
# Requires PowerUpSQL
function Invoke-HuntSQLServers
{
    <#
            .SYNOPSIS
            This function wraps around PowerUpSQL functions to inventory access to SQL Server instances associated with
            Active Directory domains, and attempts to enumerate sensitive data.
            .PARAMETER Username
            Domain account to authenticate to Active Directory.
            .PARAMETER Password
            Domain password to authenticate to Active Directory.
            .PARAMETER DomainController
            Domain controller to authenticated to. Requires username/password or credential.
            .PARAMETER Threads
            Number of concurrent tasks to run at once.
            .PARAMETER CheckMgmt
            Perform SPN discovery of MSServerClusterMgmtAPI SPN as well.  This is much slower.
            .PARAMETER CheckAll
            Attempt to log into all identify instances even if they dont respond to UDP requests.
            .PARAMETER Output Directory
            File path where all csv and html report will be exported.
            .EXAMPLE
            Run as current domain user on domain joined system.  Only targets instances that respond to UDP scan.
            PS C:\> Invoke-HuntSQLServers -OutputDirectory C:\temp\
            .EXAMPLE
            Run as current domain user on domain joined system.  Target all instances found during SPN discovery.
            PS C:\> Invoke-HuntSQLServers -CheckAll -OutputDirectory C:\temp\
            .EXAMPLE
            Run as current domain user on domain joined system.  Target all instances found during SPN discovery.
            Also, check for management servers that commonly have unregistered instances via additional UDP scan.
            PS C:\> Invoke-HuntSQLServers -CheckAll -CheckMgmt -OutputDirectory C:\temp\
             .EXAMPLE
            Run as alernative domain user against alertative domain:
            PS C:\> runas /netonly /user domain\user powershell_ise.exe
            PS C:\> import-module PowerUpSQL 
            PS C:\> Invoke-HuntSQLServers -CheckAll -OutputDirectory C:\temp\ -DomainController 192.168.1.1 -Username domain\user -Password MyPassword
            .EXAMPLE
            Full output example.
            PS C:\> Invoke-HuntSQLServers -OutputDirectory C:\temp\

              ----------------------------------------------------------------
             | Invoke-HuntSQLServers                                          |
              ----------------------------------------------------------------
             |                                                                |
             | This function automates the following tasks:                   |
             |                                                                |
             | Instance Discovery                                             |
             | o Determine current computer's domain                          |
             | o Query the domain controller via LDAP for SQL Server instances|
             | o Filter for instances that respond to UDP scans               |
             |                                                                |
             | Access Discovery                                               |
             | o Filter for instances that can be logged into                 |
             | o Filter for instances that provide sysadmin access            |
             | o Identify potentially excessive role members (sysadmin)       |
             | o Identify shared SQL Server service accounts                  |
             | o Summarize versions that could be logged into                 |
             |                                                                |
             | Data Target Discovery: Database Targets                        |
             | o Filter based on database name                                |
             | o Filter based on database encryption                          |
             |                                                                |
             | Data Target Discovery: Sensitive Data                          |
             | o Social security numbers via column name                      |
             | o Credit card numbers via column name                          |
             |                                                                |
             | Data Target Discovery: Passwords                               |
             | o Passwords via column names                                   |
             | o Passwords in agent jobs (sysadmin)                           |
             | o Passwords in stored procedures (sysadmin)                    |
             |                                                                |
              ----------------------------------------------------------------
             | Note: This can take hours to run in large environments.        |
              ----------------------------------------------------------------
             [*] Results will be written to C:\temp\test1
             [*] Start time: 09/30/2001 12:59:51
             [*] Verifying connectivity to the domain controller
             [*] - Targeting domain domain.com
             [*] - Confirmed connection to domain controller myfirstdc.domain.com
             [*] -------------------------------------------------------------
             [*] INSTANCE DISCOVERY
             [*] -------------------------------------------------------------
             [*] Querying LDAP for SQL Server SPNs (mssql*).
             [*] - 100 SQL Server SPNs were found across 50 computers.
             [*] - Writing list of SQL Server SPNs to C:\temp\domain.com-SQL-Server-Instance-SPNs.csv
             [*] Performing UDP scanning 50 computers.
             [*] - 50 instances responded.
             [*] -------------------------------------------------------------
             [*] ACCESS DISCOVERY
             [*] -------------------------------------------------------------
             [*] Attempting to log into 50 instances found via SPN query.
             [*] - 25 could be logged into.
             [*] Listing sysadmin access.
             [*] - 2 SQL Server instances provided sysadmin privileges.
             [*] Attempting to grab role members from 4 instances.
             [*] - This usually requires special privileges
             [*] - 5 role members were found.
             [*] Identifying excessive role memberships.
             [*] - 5 were found.
             [*] Identifying shared SQL Server service accounts.
             [*] - 6 shared accounts were found.
             [*] Creating a list of accessible SQL Server instance versions.
             [*] - 3 versions were found that could be logged into.
             [*] -------------------------------------------------------------
             [*] DATABASE TARGET DISCOVERY
             [*] -------------------------------------------------------------
             [*] Querying for all non-default accessible databases.
             [*] - 10 accessible non-default databases were found.
             [*] Filtering for databases using transparent encryption.
             [*] -  2 databases were found using encryption.
             [*] Filtering for databases with names that contain ACH.
             [*] -  4 database names contain ACH.
             [*] Filtering for databases with names that contain finance.
             [*] -  1 database names contain finance.
             [*] Filtering for databases with names that contain chd.
             [*] -  6 database names contain chd.
             [*] Filtering for databases with names that contain enclave.
             [*] -  7 database names contain enclave.
             [*] Filtering for databases with names that contain pos.
             [*] -  2 database names contain pos.
             [*] -------------------------------------------------------------
             [*] SENSITIVE DATA TARGET DISCOVERY
             [*] -------------------------------------------------------------
             [*] Search accessible non-default databases for table names containing SSN.
             [*] - 1 table columns found containing SSN.
             [*] Search accessible non-default databases for table names containing CARD.
             [*] - 7 table columns found containing CARD.
             [*] Search accessible non-default databases for table names containing CREDIT.
             [*] - 3 table columns found containing CREDIT.
             [*] -------------------------------------------------------------
             [*] PASSWORD TARGET DISCOVERY
             [*] -------------------------------------------------------------
             [*] Search accessible non-default databases for table names containing PASSWORD.
             [*] - 4 table columns found containing PASSWORD.
             [*] Search accessible non-default databases for agent source code containing PASSWORD.
             [*] - 1 agent jobs containing PASSWORD.
             [*] Search accessible non-default databases for stored procedure source code containing PASSWORD.
             [*] - 0 stored procedures containing PASSWORD.
  
              ----------------------------------------------------------------
              SQL SERVER HUNT SUMMARY REPORT                                  
              ----------------------------------------------------------------
              Scan Summary                                                   
              ----------------------------------------------------------------
              o Domain     : DOMAIN.COM
              o Start Time : 09/30/2001 12:59:51
              o Stop Time  : 09/30/2001 13:00:17
              o Run Time   : 00:00:25.7371541
  
              ----------------------------------------------------------------
              Instance Summary                                               
              ----------------------------------------------------------------
              o 100 SQL Server instances found via SPN LDAP query.
              o 50 SQL Server instances responded to port 1434 UDP requests.
  
              ----------------------------------------------------------------
              Access Summary                                                 
              ----------------------------------------------------------------
  
              Access:
              o 25 SQL Server instances could be logged into.
              o 5 SQL Server instances provided sysadmin access.
              o 5 SQL Server role members were enumerated. *requires privileges
              o 5 excessive role assignments were identified.
              o 6 Shared SQL Server service accounts found.
  
              Below are the top 5:
              o 10 SQLSVC_PROD
              o  5 SQLSVC_UAT
              o  5 SQLSVC_QA
              o  2 SQLSVC_DEV
              o  2 SQLApp
  
              Below is a summary of the versions for the accessible instances:
              o 10 Standard Edition (64-bit)
              o  5 Express Edition  (64-bit)
              o 10 Express Edition           
  
              ----------------------------------------------------------------
              Database Summary                        
              ----------------------------------------------------------------
              o 10 accessible non-default databases were found.
              o 2 databases were found configured with transparent encryption.
              o 4 database names contain ACH.
              o 1 database names contain finance.
              o 6 database names contain chd.
              o 7 database names contain enclave.
              o 2 database names contain pos.
  
              ----------------------------------------------------------------
              Sensitive Data Access Summary                     
              ----------------------------------------------------------------
              o 1 sample rows were found for columns containing SSN.
              o 7 sample rows were found for columns containing CREDIT.
              o 3 sample rows were found for columns containing CARD.
  
              ----------------------------------------------------------------
              Password Access Summary                               
              ----------------------------------------------------------------
              o 4 sample rows were found for columns containing PASSWRORD.
              o 1 agent jobs potentially contain passwords. *requires sysadmin
              o 0 stored procedures potentially contain passwords. *requires sysadmin
  
              ----------------------------------------------------------------
             [*] Saving results to C:\temp\demo.com-Share-Inventory-Summary-Report.html
    #>    
    [CmdletBinding()]
    Param(
       [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user. For computer lookup.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user. For computer lookup.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against. For computer lookup.')]
        [string]$DomainController,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads to process at once.')]
        [int]$Threads = 100,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Perform SPN discovery of MSServerClusterMgmtAPI SPN as well.  This is much slower.')]
        [switch]$CheckMgmt,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Attempt to log into all identify instances even if they dont respond to UDP requests.')]
        [switch]$CheckAll,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Directory to output files to.')]
        [string]$OutputDirectory
    )

   Begin
   {        
        Write-Output "  ----------------------------------------------------------------" 
        Write-Output " | Invoke-HuntSQLServers                                          |"
        Write-Output "  ----------------------------------------------------------------"         
        Write-Output " |                                                                |"
        Write-Output " | This function automates the following tasks:                   |"
        Write-Output " |                                                                |"
        Write-Output " | Instance Discovery                                             |"
        Write-Output " | o Determine current computer's domain                          |"
        Write-Output " | o Query the domain controller via LDAP for SQL Server instances|"
        Write-Output " | o Filter for instances that respond to UDP scans               |"
        Write-Output " |                                                                |"
        Write-Output " | Access Discovery                                               |"
        Write-Output " | o Filter for instances that can be logged into                 |"
        Write-Output " | o Filter for instances that provide sysadmin access            |"
        Write-Output " | o Identify potentially excessive role members (sysadmin)       |"
        Write-Output " | o Identify shared SQL Server service accounts                  |"
        Write-Output " | o Summarize versions that could be logged into                 |"
        Write-Output " |                                                                |"
        Write-Output " | Data Target Discovery: Database Targets                        |"
        Write-Output " | o Filter based on database name                                |"                     
        Write-Output " | o Filter based on database encryption                          |"
        Write-Output " |                                                                |"
        Write-Output " | Data Target Discovery: Sensitive Data                          |"
        Write-Output " | o Social security numbers via column name                      |"
        Write-Output " | o Credit card numbers via column name                          |"
        Write-Output " |                                                                |"
        Write-Output " | Data Target Discovery: Passwords                               |"
        Write-Output " | o Passwords via column names                                   |"
        Write-Output " | o Passwords in agent jobs (sysadmin)                           |"
        Write-Output " | o Passwords in stored procedures (sysadmin)                    |"
        Write-Output " |                                                                |"
        Write-Output "  ----------------------------------------------------------------"  
        Write-Output " | Note: This can take hours to run in large environments.        |"
        Write-Output "  ----------------------------------------------------------------"
        Write-Output " [*] Results will be written to $OutputDirectory"        

        # Verify PowerUpSQL was loaded
        $CheckForPowerUpSQL = Test-Path Function:\Get-SQLAuditDatabaseSpec
        if($CheckForPowerUpSQL -eq $false)
        {
            Write-Output " [-] This function requires PowerUpSQL: www.powerupsql.com"
            Write-Output " [!] Aborting execution."
            break
        }

        # Verify an output direcotry has been provided
        if(-not $OutputDirectory)
        {
            Write-Output " [-] -OutputDirectory parameter was not provided."
            Write-Output " [!] Aborting execution."
            break
        }

        # Get start time
        $StartTime = Get-Date
        Write-Output " [*] Start time: $StartTime"
        $StopWatch =  [system.diagnostics.stopwatch]::StartNew()

        # Get domain controller
        
        # Set target domain and domain  
        Write-Output " [*] Verifying connectivity to the domain controller"        
        if(-not $DomainController){
            
            # If no dc is provided then use environmental variables
            $DCHostname = $env:LOGONSERVER -replace("\\","")
            $TargetDomain = $env:USERDNSDOMAIN
        }else{                
            $DCRecord = Get-domainobject -LdapFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -DomainController $DomainController -Username $username -Password $Password | select -first 1 | select properties -expand properties -ErrorAction SilentlyContinue
            [string]$DCHostname = $DCRecord.dnshostname
            [string]$DCCn = $DCRecord.cn
            [string]$TargetDomain = $DCHostname -replace ("$DCCn\.","") 
        }
                
        if($DCHostname)
        {
            Write-Output " [*] - Targeting domain $TargetDomain"
            Write-Output " [*] - Confirmed connection to domain controller $DCHostname"                         
        }else{
            Write-Output " [*] - There appears to have been an error connecting to the domain controller."
            Write-Output " [*] - Aborting."
            break
        }  
   }

   Process
   {

        # ------------------------------------------
        # Instance Discovery
        # ------------------------------------------

        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] INSTANCE DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Get SQL Server instances
        if($CheckMgmt){
            Write-Output " [*] Querying LDAP for SQL Server SPNs (mssql* and MSServerClusterMgmtAPI)."
            Write-Output " [*] - WARNING: You have chosen to target MSServerClusterMgmtAPI"
            Write-Output " [*]            It will yield more results, but will be much slower."
            $AllInstances = Get-SQLInstanceDomain -CheckMgmt
        }else{
            Write-Output " [*] Querying LDAP for SQL Server SPNs (mssql*)."
            $AllInstances = Get-SQLInstanceDomain 
        }
        
        $AllInstancesCount = $AllInstances.count
        $AllComputers = $AllInstances | Select ComputerName -Unique
        $AllComputersCount = $AllComputers.count
        Write-Output " [*] - $AllInstancesCount SQL Server SPNs were found across $AllComputersCount computers."

        # Save list of SQL Server instances to a file
        write-output " [*] - Writing list of SQL Server SPNs to $OutputDirectory\$TargetDomain-SQL-Server-Instance-SPNs.csv"
        $AllInstances | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-All.csv"

        # Perform UDP scanning of identified SQL Server instances on udp port 1434
        write-output " [*] Performing UDP scanning $AllComputersCount computers."
        $UDPInstances = $AllComputers | Where-Object ComputerName -notlike "" | Get-SQLInstanceScanUDPThreaded -Threads 100
        $UDPInstancesCount = $UDPInstances.count
        Write-Output " [*] - $UDPInstancesCount instances responded."
        $UDPInstances | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-UDPResponse.csv"

        # ------------------------------------------
        # Access Discovery
        # ------------------------------------------

        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] ACCESS DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Check if targeting all or just those that responded to UDP
        if($CheckAll){

            # Attempt to log into instances that found via SPNs
            Write-Output " [*] Attempting to log into $AllInstancesCount instances found via SPN query."
            $LoginAccess = $AllInstances | Get-SQLServerInfoThreaded -Threads 100
            $LoginAccessCount = $LoginAccess.count 
            Write-Output " [*] - $LoginAccessCount could be logged into."
            $LoginAccess | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-LoginAccess.csv"    

        }else{

            # Attempt to log into instances that responded to UDP
            Write-Output " [*] Attempting to log into $UDPInstancesCount instances that responded to UDP scan."
            $LoginAccess = $UDPInstances | Get-SQLServerInfoThreaded -Threads 100
            $LoginAccessCount = $LoginAccess.count 
            Write-Output " [*] - $LoginAccessCount could be logged into."
            $LoginAccess | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-LoginAccess.csv"
        }

        # Filter for instances with sysadmin privileges
        Write-Output " [*] Listing sysadmin access."
        $LoginAccessSysadmin = $LoginAccess | Where-Object IsSysadmin -like "Yes"
        $LoginAccessSysadminCount = $LoginAccessSysadmin.count 
        Write-Output " [*] - $LoginAccessSysadminCount SQL Server instances provided sysadmin privileges."
        $LoginAccessSysadmin | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-LoginAccess-Sysadmin.csv"

        # Attempt to obtain a list of role members from SQL Server instance (requrie sysadmin)
        Write-Output " [*] Attempting to grab role members from $LoginAccessCount instances."
        Write-Output " [*] - This usually requires special privileges"
        $RoleMembers = $LoginAccess | Get-SQLServerRoleMember
        $RoleMembersCount = $RoleMembers.count 
        Write-Output " [*] - $RoleMembersCount role members were found."
        $RoleMembers | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-RoleMembers.csv"

        # Filter for common explicit role assignments for Everyone, Builtin\Users, Authenticated Users, and Domain Users
         Write-Output " [*] Identifying excessive role memberships."
        $ExcessiveRoleMemberships = $RoleMembers |
        ForEach-Object{

            # Filter for broad groups
            if (($_.PrincipalName -eq "Everyone") -or ($_.PrincipalName -eq "BUILTIN\Users") -or ($_.PrincipalName -eq "Authenticated Users") -or ($_.PrincipalName -like "*Domain Users") )            
            {
                $_
            }            
        }
        $ExcessiveRoleMembershipsCount = $ExcessiveRoleMemberships.count
        Write-Output " [*] - $ExcessiveRoleMembershipsCount were found."
        $ExcessiveRoleMemberships | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-RoleMembers-Excessive.csv"

        # Create a list of share service accounts from the instance information
        Write-Output " [*] Identifying shared SQL Server service accounts."
        $SharedAccounts = $AllInstances |  Group-Object DomainAccount | Sort-Object Count -Descending  | Where Count -GT 4 |  Select Count, Name
        $SharedAccountsCount = $SharedAccounts.count
        Write-Output " [*] - $SharedAccountsCount shared accounts were found."
        $SharedAccounts | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-SharedAccounts.csv"
 
        # Create a summary of the affected SQL Server versions
        Write-Output " [*] Creating a list of accessible SQL Server instance versions."
        $SQLServerVersions = $LoginAccess |  Group-Object SQLServerEdition | Sort-Object Count -Descending | Select Count, Name
        $SQLServerVersionsCount = $SQLServerVersions.count
        Write-Output " [*] - $SQLServerVersionsCount versions were found that could be logged into."
        $SQLServerVersions | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-VersionSummary.csv"
                  
        # ------------------------------------------
        # Data Discovery: Databse Targets
        # ------------------------------------------

        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] DATABASE TARGET DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Get a list of all accessible non-default databases from SQL Server instances
        Write-Output " [*] Querying for all non-default accessible databases."
        $Databases = $LoginAccess | Get-SQLDatabaseThreaded -NoDefaults -HasAccess
        $DatabasesCount = $Databases.count
        Write-Output " [*] - $DatabasesCount accessible non-default databases were found."
        $Databases | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases.csv"

        # Filter for potential high value databases if transparent encryption is used
        Write-Output " [*] Filtering for databases using transparent encryption."
        $DatabasesEnc = $Databases | Where-Object {$_.is_encrypted –eq “TRUE”} 
        $DatabasesEncCount =  $DatabasesEnc.count
        Write-Output " [*] - $DatabasesEncCount databases were found using encryption."
        $DatabasesEnc | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases-Encrypted.csv"

        # Filter for potential high value databases based on keywords       
        Write-Output " [*] Filtering for databases with names that contain ACH."
        $DatabasesACH = $Databases | Where-Object {$_.DatabaseName –like “*ACH*”} 
        $DatabasesACHCount = $DatabasesACH.count
        Write-Output " [*] - $DatabasesACHCount database names contain ACH."
        $DatabasesACH | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases-ach.csv"

        Write-Output " [*] Filtering for databases with names that contain finance."
        $DatabasesFinance  = $Databases | Where-Object {$_.DatabaseName –like “*finance*”} 
        $DatabasesFinanceCount = $DatabasesFinance.count
        Write-Output " [*] - $DatabasesFinanceCount database names contain finance."
        $DatabasesFinance | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases-finance.csv"

        Write-Output " [*] Filtering for databases with names that contain pci."
        $DatabasesPCI = $Databases | Where-Object {$_.DatabaseName –like “*pci*”}
        $DatabasesPCICount = $DatabasesPCI.count
        Write-Output " [*] - $DatabasesPCICount database names contain pci."
        $DatabasesPCI | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases-pci.csv" 

        Write-Output " [*] Filtering for databases with names that contain chd."
        $DatabasesCHD = $Databases | Where-Object {$_.DatabaseName –like “*chd*”} 
        $DatabasesCHDCount = $DatabasesCHD.count
        Write-Output " [*] - $DatabasesCHDCount database names contain chd."
        $DatabasesCHD | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases-chd.csv"

        Write-Output " [*] Filtering for databases with names that contain enclave."
        $DatabasesEnclave = $Databases | Where-Object {$_.DatabaseName –like “*enclave*”}
        $DatabasesEnclaveCount = $DatabasesEnclave.count
        Write-Output " [*] - $DatabasesEnclaveCount database names contain enclave."
        $DatabasesEnclave | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases-enclave.csv"

        Write-Output " [*] Filtering for databases with names that contain pos."
        $DatabasesPOS = $Databases | Where-Object {$_.DatabaseName –like “*pos*”} 
        $DatabasesPOSCount = $DatabasesPOS.count
        Write-Output " [*] - $DatabasesPOSCount database names contain pos."
        $DatabasesPOS | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases-pos.csv"

        # ------------------------------------------
        # Data Discovery: Sensitive Data Targets
        # ------------------------------------------

        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] SENSITIVE DATA TARGET DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Target Social security numbers via column name
        Write-Output " [*] Search accessible non-default databases for table names containing SSN."
        $SSNNumbers = $LoginAccess | Get-SQLColumnSampleDataThreaded -SampleSize 2 -NoDefaults -Threads 20 -Keywords "ssn"
        $SSNNumbersCount = $SSNNumbers.count
        Write-Output " [*] - $SSNNumbersCount table columns found containing SSN."
        $SSNNumbers | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Data-ssn.csv"

        # Target credit numbers via column name
        Write-Output " [*] Search accessible non-default databases for table names containing CARD."
        $ccCards = $LoginAccess | Get-SQLColumnSampleDataThreaded -SampleSize 2 -NoDefaults -ValidateCC -Threads 20 -Keywords "card"
        $ccCardsCount = $ccCards.count
        Write-Output " [*] - $ccCardsCount table columns found containing CARD."
        $ccCards | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Data-card.csv"

        Write-Output " [*] Search accessible non-default databases for table names containing CREDIT."
        $ccCredit = $LoginAccess | Get-SQLColumnSampleDataThreaded -SampleSize 2 -NoDefaults -ValidateCC -Threads 20 -Keywords "credit"
        $ccCreditCount = $ccCredit.count
        Write-Output " [*] - $ccCreditCount table columns found containing CREDIT."
        $ccCredit | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Data-credit.csv"

        # ------------------------------------------
        # Data Discovery: Password Targets
        # ------------------------------------------
        
        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] PASSWORD TARGET DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Target passwords based on column names
        Write-Output " [*] Search accessible non-default databases for table names containing PASSWORD."
        $ColumnPasswords = $LoginAccess | Get-SQLColumnSampleDataThreaded  -SampleSize 2 -NoDefaults -Threads 20 -Keywords "password"
        $ColumnPasswordsCount = $ColumnPasswords.count
        Write-Output " [*] - $ColumnPasswordsCount table columns found containing PASSWORD."
        $ColumnPasswords | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Passswords-ColumnName.csv"

        # Target passwords in agent jobs (requires privileges)
        Write-Output " [*] Search accessible non-default databases for agent source code containing PASSWORD."
        $AgentPasswords = $LoginAccess | Get-SQLAgentJob  -Keyword "password"
        $AgentPasswordsCount = $AgentPasswords.count
        Write-Output " [*] - $AgentPasswordsCount agent jobs containing PASSWORD."
        $AgentPasswords | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Passswords-AgentJobs.csv"

        # Target passwords in stored procedures (requires privileges)
        Write-Output " [*] Search accessible non-default databases for stored procedure source code containing PASSWORD."
        $SpPasswords = $LoginAccess | Get-SQLStoredProcedure  -Keyword "password"
        $SpPasswordsCount = $SpPasswords.count
        Write-Output " [*] - $SpPasswordsCount stored procedures containing PASSWORD."
        $SpPasswords | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Passswords-Procedures.csv"                                                             
   }

   End
   {
        # Get run time
        $EndTime = Get-Date
        $StopWatch.Stop()
        $RunTime = $StopWatch | Select-Object Elapsed -ExpandProperty Elapsed

        # ------------------------------------------
        # Console Report
        # ------------------------------------------

        # Generate summary console output
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  SQL SERVER HUNT SUMMARY REPORT                                  "        
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Scan Summary                                                   "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  o Domain     : $TargetDomain"
        Write-Output "  o Start Time : $StartTime"
        Write-Output "  o Stop Time  : $EndTime"
        Write-Output "  o Run Time   : $RunTime"
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Instance Summary                                               "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  o $AllInstancesCount SQL Server instances found via SPN LDAP query."
        Write-Output "  o $UDPInstancesCount SQL Server instances responded to port 1434 UDP requests."    
        Write-Output "  "   
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Access Summary                                                 "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  "
        Write-Output "  Access:"
        Write-Output "  o $LoginAccessCount SQL Server instances could be logged into."
        Write-Output "  o $LoginAccessSysadminCount SQL Server instances provided sysadmin access."        
        Write-Output "  o $RoleMembersCount SQL Server role members were enumerated. *requires privileges"
        Write-Output "  o $ExcessiveRoleMembershipsCount excessive role assignments were identified."
        Write-Output "  o $SharedAccountsCount Shared SQL Server service accounts found."
        Write-Output "  "
        Write-Output "  Below are the top 5:"

        # Display top 5 most common service accounts
        $SqlServiceAccountTop5 = $SharedAccounts | Select-Object count,name -First 5
        $SqlServiceAccountTop5 |
        Foreach{
            
            $CurrentCount = $_.count
            $CurrentName = $_.name
            Write-Output "  o $CurrentCount $CurrentName"                                          
        } 
        
        Write-Output "  "
        Write-Output "  Below is a summary of the versions for the accessible instances:"

        # Display all SQL Server instance version counts
        $LoginAccess | Group-Object SQLServerEdition | Sort-Object count -Descending | Select-Object count,name |
        Foreach{
            
            $CurrentCount = $_.count
            $CurrentName = $_.name
            Write-Output "  o $CurrentCount $CurrentName"                                       
        } 

        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Database Summary                        "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  o $DatabasesCount accessible non-default databases were found."        
        Write-Output "  o $DatabasesEncCount databases were found configured with transparent encryption."
        Write-Output "  o $DatabasesACHCount database names contain ACH."        
        Write-Output "  o $DatabasesFinanceCount database names contain finance."
        Write-Output "  o $DatabasesCHDCount database names contain chd."       
        Write-Output "  o $DatabasesEnclaveCount database names contain enclave."
        Write-Output "  o $DatabasesPOSCount database names contain pos."
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Sensitive Data Access Summary                     "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  o $SSNNumbersCount sample rows were found for columns containing SSN."
        Write-Output "  o $ccCreditCount sample rows were found for columns containing CREDIT."
        Write-Output "  o $ccCardsCount sample rows were found for columns containing CARD."
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Password Access Summary                               "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  o $ColumnPasswordsCount sample rows were found for columns containing PASSWRORD."
        Write-Output "  o $AgentPasswordsCount agent jobs potentially contain passwords. *requires sysadmin"
        Write-Output "  o $SpPasswordsCount stored procedures potentially contain passwords. *requires sysadmin"
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"  

        # ------------------------------------------
        # HTML Report
        # ------------------------------------------
        
        $HTMLReport1 = @"        
        <HTML>
         <HEAD>
         </HEAD>
         <BODY>
            <H1>SQL SERVER HUNT SUMMARY REPORT</H1>
            <strong>Domain:</strong>$TargetDomain<Br>
			
			<H3>Scan Summary</H3>
			<ul>
				<li>Start Time: $StartTime</li>
				<li>End Time: $EndTime</li>
				<li>Run Time: $RunTime</li>
			</ul>
            
            <H3>Instance Summary</H3>
            
            <ul>
             <li>$AllInstancesCount SQL Server instances found via SPN LDAP query.</li>
             <li>$UDPInstancesCount SQL Server instances responded to port 1434 UDP requests.</li>        
            </ul>
            
            <H3>Access Summary</H3>
            
            <ul>
             <li>$LoginAccessCount SQL Server instances could be logged into.</li>
             <li>$LoginAccessSysadminCount SQL Server instances provided sysadmin access.</li>
             <li>$RoleMembersCount SQL Server role members were enumerated. *Requires privileges</li>             
             <li>$ExcessiveRoleMembershipsCount excessive role assignments were identified.</li>             
             <li>
                 $SharedAccountsCount Shared SQL Server service accounts found.<br>
                 Below are the top 5:
                 <ul>
"@
                                     
                # Display top 5 most common service accounts
                $SqlServiceAccountTop5 = $SharedAccounts | Select-Object count,name -First 5
                $HTMLReport2 = $SqlServiceAccountTop5 |
                Foreach{
            
                    $CurrentCount = $_.count
                    $CurrentName = $_.name
                    Write-Output "<li>$CurrentCount $CurrentName</li>"                                                         
                } 

        $HTMLReport3 = @"   
                </ul>
              </li>                       
              <li>
                Below is a summary of the versions for the accessible instances:
                <ul>
"@
                # Display all SQL Server instance version counts
                $HTMLReport4 = $LoginAccess | Group-Object SQLServerEdition | Sort-Object count -Descending | Select-Object count,name |
                Foreach{
            
                    $CurrentCount = $_.count
                    $CurrentName = $_.name
                    Write-Output "<li>$CurrentCount $CurrentName</li>"                                      
                }             

        $HTMLReport5 = @" 
                </ul>
              </li>
            </ul>

            <H3>Database Summary</H3>
            
            <ul>
             <li>$DatabasesCount accessible non-default databases were found.</li>
             <li>$DatabasesEncCount databases were found configured with transparent encryption.</li>
             <li>$DatabasesACHCount database names contain ACH.</li>             
             <li>$DatabasesFinanceCount database names contain FINANCE</li>
             <li>$DatabasesCHDCount database names contain CHD.</li>
             <li>$DatabasesEnclaveCount database names contain ENCLAVE.</li>
             <li>$DatabasesPOSCount database names contain POS</li>
            </ul>           

            <H3>Sensitive Data Access Summary</H3>
            
            <ul>
             <li>$SSNNumbersCount sample rows were found for columns containing SSN.</li>
             <li>$ccCreditCount sample rows were found for columns containing CREDIT.</li>  
             <li>$ccCardsCount sample rows were found for columns containing CARD.</li>           
            </ul>

            <H3>Password Access Summary</H3>
            
            <ul>
             <li>$ColumnPasswordsCount sample rows were found for columns containing PASSWORD.</li>
             <li>$AgentPasswordsCount agent jobs potentially contain passwords. *Privileges required</li>
             <li>$SpPasswordsCount stored procedures potentially contain passwords. *Privileges requried</li>             
            </ul>        
         </BODY>
        </HTML>   
"@
        $HTMLReport = $HTMLReport1 + $HTMLReport2 + $HTMLReport3 + $HTMLReport4 + $HTMLReport5
        Write-Output " [*] Saving results to $OutputDirectory\$TargetDomain-Share-Inventory-Summary-Report.html"        
        $HTMLReport | Out-File "$OutputDirectory\$TargetDomain-SQLServer-Summary-Report.html"
   }
}	
