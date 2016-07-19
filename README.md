
## ![alt tag](hhttps://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/scripts/PowerUpLogoSm.png) PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server
The PowerUpSQL module includes functions that support SQL Server discovery, auditing for common weak configurations, and privilege escalation on scale.  It is intended to be used during internal penetration tests and red team engagements. However, PowerUpSQL also includes many functions that could be used by administrators to quickly inventory the SQL Servers in their ADS domain.

PowerUpSQL was designed with six objectives in mind:
* Easy Server Discovery: Discovery functions can be used to blindly identify local, domain, and non-domain SQL Server instances on scale.
* Easy Server Auditing: The Invoke-SQLAudit function can be used to audit for common high impact vulnerabilities and weak configurations using the current login's privileges.  Also, Invoke-SQLDumpInfo can be used to quickly inventory databases, privileges, and other information.
* Easy Server Exploitation: The Invoke-SQLEscalatePriv function attempts to obtain sysadmin privileges using identified vulnerabilities. 
* Scalability: Multi-threading is supported on core functions so they can be executed against many SQL Servers quickly.
* Flexibility: PowerUpSQL functions support the PowerShell pipeline so they can be used together, and with other scripts.
* Portability: Default .net libraries are used and there are no dependencies on SQLPS or the SMO libraries. Functions have also been designed so they can be run independently. As a result, it's easy to use on any Windows system with PowerShell v3 installed.


### Module Information
* Author: Scott Sutherland (@_nullbind), NetSPI - 2016
* Contributors: Antti Rantasaari and Eric Gruber (@egru)
* License: BSD 3-Clause
* Required Dependencies: PowerShell v.3
 
### Installing the Module
* Option 1: Install it from the PowerShell Gallery.  This requires local administrative privileges and will permanently install the module.

    `Install-Module -Name PowerUpSQL`

* Option 2: Download the project and import it.  This does not require administrative privileges and will only be imported into the current session.  However, it may be blocked by restrictive execution policies.

    `Import-Module PowerUpSQL.psd1`
* Option 3: Load it into a session via a download cradle.  This does not require administrative privileges and will only be imported into the current session.  It should not be blocked by executions policies.

    `IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1")`

     Note: To run as an alternative domain user, use the runas command to launch PowerShell first. 

    `runas /noprofile /netonly /user:domain\user PowerShell.exe`

### Getting Command Help
* To list functions from the module, type: `Get-Command -Module PowerUpSQL`
* To list help for a function, type: `Get-Help FunctionName`

Below are the functions included in this module.  I've provided a list of the ones completed so far, but I've also outlined the intended development roadmap. The high level roadmap includes adding functions, adding multi-threading to all common functions, and testing against SQL Server version 2000 to 2014.  At the moment most of the testing was done on versions 2008-2014. Also, as a general note, use the verbose flag to monitor the progress of executing functions.

### Discovery Functions 

These functions can be used for enumerating SQL Server instances.  Discovered instances can then be piped into other PowerUpSQL functions.

|Function Name|Description |
|:--------------------------------|:-----------|
|Get-SQLInstanceFile|Returns SQL Server instances from a file.  One per line.| 
|Get-SQLInstanceLocal|Returns SQL Server instances from the local system based on a registry search.|
|Get-SQLInstanceDomain|Returns a list of SQL Server instances discovered by querying a domain controller for systems with registered MSSQL service principal names.  The function will default to the current user's domain and logon server, but an alternative domain controller can be provided. UDP scanning of management servers is optional.|
|Get-SQLInstanceScanUDP|Returns SQL Server instances from UDP scan results.|
|Get-SQLInstanceScanUDPThreaded|Returns SQL Server instances from UDP scan results and supports threading.|

**Examples:**
	
	Get-SQLInstanceDomain -Verbose | Get-SQLServerInfo -Verbose
	Get-SQLInstanceLocal -Verbose | Get-SQLServerInfo -Verbose
	Get-SQLServerInfo -Verbose -Instance "SQLSERVER1\MYINSTANCE"
	Get-SQLServerInfo -Verbose -Instance "SQLSERVER1\MYINSTANCE" -Username MyUser -Password MyPassword
	Get-SQLServerInfo -Verbose -Instance "SQLSERVER1\MYINSTANCE" -Credential MyUser
	
**Roadmap:**
	
	Get-SQLInstanceScanTCP - Returns SQL Server instances from TCP scan results.
	Get-SQLInstanceBroadcast - Returns SQL Server instances from UDP broadcast.

### Primary Attack Functions

These are the functions used to quickly dump database information, audit for common vulnerabilities, and attempt to obtain sysadmin privileges.

|Function Name                 |Description |
|:-----------------------------|:-----------|
|Invoke-SQLDumpInfo|This can be used to dump SQL Server and database information to csv or xml files.  This can be handy for doing a quick inventory of databases, logins, privileges etc.|
|Invoke-SQLAudit|This can be used to review the SQL Server and databases for common configuration weaknesses and provide a vulnerability report along with recommendations for each item.|
|Invoke-SQLEscalatePriv|This can be used to obtain sysadmin privileges via identified configuration weaknesses.|

**Examples:**

	Get-SQLInstanceDomain -Verbose | Invoke-SQLDumpInfo -Verbose
	Get-SQLInstanceLocal -Verbose | Invoke-SQLAudit -Verbose
	Invoke-SQLEscalatePriv -Verbose -Instance "SQLSERVER1\MyInstance" -Username MyUser -Password MyPassword


### Core Functions

These functions are used to test connections, execute SQL Server queries, and execute OS commands.  All other functions use these core functions.  However, they can also be executed independently. 

|Function Name                 |Description |
|:-----------------------------|:-----------|
|Get-SQLConnectionTest|Tests if the current Windows account or provided SQL Server login can log into an SQL Server.
|Get-SQLConnectionTestThreaded|Tests if the current Windows account or provided SQL Server login can log into an SQL Server and supports threading.|
|Get-SQLQuery|Executes a query on target SQL servers.|
|Get-SQLQueryThreaded|Executes a query on target SQL servers and supports threading.|
|Invoke-SQLOSCmd|Execute command on the operating system as the SQL Server service account using xp_cmdshell. Supports threading, raw output, and table output.|

**Examples:**

	Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10 
	Get-SQLInstanceDomain -Verbose | Invoke-SQLOSCmd -Verbose -Threads 10 -Command "whoami"
	
### Common Functions

These functions are used for common information gathering tasks.  Similar to core functions, the common functions can be executed by themselves, but are also used by other functions in the PowerUpSQL module.

|Function Name                 |Description |
|:-----------------------------|:-----------|
|Get-SQLAuditDatabaseSpec|Returns Audit database specifications from target SQL Servers.|
|Get-SQLAuditServerSpec|Returns Audit server specifications from target SQL Servers.|
|Get-SQLColumn|Returns column information from target SQL Servers. Supports keyword search.|
|Get-SQLColumnSampleData|Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers.|
|Get-SQLColumnSampleDataThreaded|Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers. Supports host threading.|
|Get-SQLDatabase|Returns database information from target SQL Servers.|
|Get-SQLDatabase|Returns database information from target SQL Servers. Supports host threading.|
|Get-SQLDatabasePriv|Returns database user privilege information from target SQL Servers.|
|Get-SQLDatabaseRole|Returns database role information from target SQL Servers.|
|Get-SQLDatabaseRoleMember|Returns database role member information from target SQL Servers.|
|Get-SQLDatabaseSchema|Returns schema information from target SQL Servers. |	
|Get-SQLDatabaseUser|Returns database user information from target SQL Servers.|
|Get-SQLServerConfiguration|Returns configuration settings from sp_configure.  Output includes advanced options if the connecting user is a sysadmin.|
|Get-SQLServerCredential|Returns credentials from target SQL Servers.|
|Get-SQLServerInfo|Returns basic server and user information from target SQL Servers.|
|Get-SQLServerInfoThreaded|Returns basic server and user information from target SQL Servers. Supports host threading.|
|Get-SQLServerLink|Returns link servers from target SQL Servers.|
|Get-SQLServerLogin|Returns logins from target SQL Servers.|
|Get-SQLServerPriv|Returns SQL Server login privilege information from target SQL Servers.|
|Get-SQLServerRole|Returns SQL Server role information from target SQL Servers.|
|Get-SQLServerRoleMember|Returns SQL Server role member information from target SQL Servers.|
|Get-SQLServiceAccount|Returns a list of service account names for SQL Servers services by querying the registry with xp_regread.  This can be executed against remote systems.|
|Get-SQLSession|Returns active sessions from target SQL Servers.|
|Get-SQLStoredProcure|Returns stored procedures from target SQL Servers.|	
|Get-SQLSysadminCheck|Check if login is has sysadmin privilege on the target SQL Servers.|
|Get-SQLTable|Returns table information from target SQL Servers.|
|Get-SQLTriggerDdl|Returns DDL trigger information from target SQL Servers.  This includes logon triggers.|
|Get-SQLTriggerDml|Returns DML trigger information from target SQL Servers.|
|Get-SQLView|Returns view information from target SQL Servers.|

**Examples:**

	Get-SQLInstanceLocal | Get-SQLDatabase -Verbose -NoDefaults
	Get-SQLInstanceLocal | Get-SQLColumnSampleData -Keywords "account,credit,card" -SampleSize 5 -ValidateCC 

**Roadmap:**
	
	Get-SQLProxyAccount - Returns proxy accounts from target SQL Servers.
	Get-SQLTempObject - Returns temp objects from target SQL Servers.	
	Get-SQLCachePlan - Returns cache plans from target SQL Servers.	
	Get-SQLQueryHistory - Returns recent query history from target SQL Servers.	
	Get-SQLHiddenSystemObject - Returns hidden system objects from target SQL Servers.	 
	
### Audit Functions

These functions are used for identifying weak configurations that can lead to unauthorized access.  Invoke-SQLAudit can be used to run all of them at once. Also, all of the audit functions support an exploit flag.  In most cases that means the script will try to add your login to the sysadmin server role.

|Function Name                 |Description |Obtains Sysadmin Privs|
|:-----------------------------|:-----------|:---------|
|Invoke-SQLAuditPrivCreateProcedure|Check if the current login has the CREATE PROCEDURE permission.  Attempt to use permission to obtain sysadmin privileges.|No|
|Invoke-SQLAuditPrivImpersonateLogin|Check if the current login has the IMPERSONATE permission on any sysadmin logins. Attempt to use permission to obtain sysadmin privileges.|Yes|
|Invoke-SQLAuditPrivServerLink|Check if SQL Server links exist that are preconfigured with alternative credentials that can be impersonated. Provide example queries for execution on remote servers.|Yes|
Invoke-SQLAuditPrivDbChaining|Check if database ownership chaining is enabled at the server or databases levels.|No|
|Invoke-SQLAuditPrivTrustworthy|Check if any database have been flagged as trusted.|No|
|Invoke-SQLAuditPrivXpDirtree|Checks if the xp_dirtree stored procedure is executable.  Uses Inveigh to obtain password hash for the SQL Server service account. Note: Capture likelihood is better when longer timeouts are set.|Yes|
|Invoke-SQLAuditPrivXpFileexist|Checks if the xp_fileexist stored procedure is executable.  Uses Inveigh to obtain password hash for the SQL Server service account. Note: Capture likelihood is better when longer timeouts are set.|Yes|
|Invoke-SQLAuditRoleDbDdlAdmin|Check if the current login has the DB_DdlAdmin role in any databases.  Attempt to use permission to obtain sysadmin privileges.|No|
|Invoke-SQLAuditRoleDbOwner|Check if the current login has the DB_OWNER role in any databases.  Attempt to use permission to obtain sysadmin privileges.|Yes|
|Invoke-SQLAuditSampleDataByColumn|Check if the current login can access any database columns that contain the word password. Supports column name keyword search and custom data sample size.  For better data searches use Get-SQLColumnSampleData.|No|
|Invoke-SQLAuditWeakLoginPw|This can be used for online dictionary attacks. It also support auto-discovery of SQL Logins for testing if you already have a least privilege account.|Yes|

**Examples:** 

	Get-SQLInstanceLocal | Invoke-SQLAuditPrivImpersonateLogin -Verbose
	
**Roadmap:**
	
	Create-SqlAuditPrivCreateStartUpProc
	Invoke-SQLAuditCrawlOwnershipChain	
	Invoke-SQLAuditCrawlServerLink
	Invoke-SQLAuditDictionaryAttackOffline
	Invoke-SQLAuditDictionaryAttackOnline
	Invoke-SQLAuditImpersonateDatabaseUser
	Invoke-SQLAuditPrivAdministerBulkOps
	Invoke-SQLAuditPrivAgentJob 
	Invoke-SQLAuditPrivAlterAssembly	
	Invoke-SQLAuditPrivAlterServerLogin
	Invoke-SQLAuditPrivAlterServerRole
	Invoke-SQLAuditPrivControlServer
	Invoke-SQLAuditPrivControlServer
	Invoke-SQLAuditPrivCreateAssembly -CLR -Binary -C
	Invoke-SQLAuditPrivCreateStartUpSP
	Invoke-SQLAuditPrivCreateTriggerDDL
	Invoke-SQLAuditPrivCreateTriggerDML
	Invoke-SQLAuditPrivCreateTriggerLOGON
	Invoke-SQLAuditPrivExternalAssembly
	Invoke-SqlAuditPrivInjectUncPath - https://github.com/nullbind/Powershellery/blob/master/Stable-ish/MSSQL/Get-SQLServiceAccountPwHash.ps1
	Invoke-SqlAuditPrivXpCmdshell
	Invoke-SQLAuditRoledbAccessAdmin	
	Invoke-SQLAuditRoledbSecurityAdmin
	Invoke-SQLAuditSQLi-ImpersonateDatabaseUser - https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/
	Invoke-SQLAuditSQLi-ImpersonateLogin - https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/
	Invoke-SQLAuditSQLi-ImpersonateSignedSp - https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/
	Invoke-SQLOSAdmintoSysadmin - https://github.com/nullbind/Powershellery/blob/master/Stable-ish/MSSQL/Invoke-SqlServerServiceImpersonation-Cmd.ps1


### Persistence Functions

These functions are used for maintaining access to the SQL Server using various methods.  The roadmap for development is below.  I've included a few links to standalone scripts that have not been integrated yet.

**Roadmap:**
	
	Get-SQLPersistAssembly						  
	Get-SQLPersistSp						
	Get-SQLPersistSpStartup	- https://github.com/nullbind/Powershellery/blob/master/Stable-ish/MSSQL/Invoke-SqlServer-Persist-StartupSp.psm1					 
	Get-SQLPersistTriggerDml					  
	Get-SQLPersistTriggerDdl - https://github.com/nullbind/Powershellery/blob/master/Stable-ish/MSSQL/Invoke-SqlServer-Persist-TriggerDDL.psm1					  
	Get-SQLPersistTriggerLogon - https://github.com/nullbind/Powershellery/blob/master/Stable-ish/MSSQL/Invoke-SqlServer-Persist-TriggerLogon.psm1					
	Get-SQLPersistView							   
	Get-SQLPersistInternalObject				
	Get-SQLPersistAgentJob						 
	Get-SQLPersistXstatus						   
	Get-SQLPersistSkeletonKey					  
	Get-SQLPersistFullPrivLogin					
	Get-SQLPersistImpersonateSysadmin	

### Password Recovery Functions

These functions are used for recovering authentication tokens of varous types.  The roadmap for development is below.  I've included a few links to standalone scripts that have not been integrated yet.
	
**Roadmap:**
	
	Get-SQLRecoverPwCredential - https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLAllCredentials.psm1	
	Get-SQLRecoverPwServerLink - https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLLinkPasswords.psm1	
	Get-SQLRecoverPWProxyAccount - https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLAllCredentials.psm1	
	Get-SQLRecoverLoginHash	
	Get-SQLRecoverMasterKey						 
	Get-SQLRecoverMachineKey		
	Get-SQLRecoverPwAutoLogon
	Get-SQLRecoverPwLsaSecrets
	Get-SQLRecoverPwLogonOn

### Data Exfiltration Functions

These functions are used for exfiltrating data out of SQL Server.  The roadmap for development is below.  

**Roadmap:**
	
	Get-SQLExfilHttp							   
	Get-SQLExfilHttps							      
	Get-SQLExfilDns								      
	Get-SQLExfilSmb								     
	Get-SQLExfilSmtp							     
	Get-SQLExfilFtp								      
	Get-SQLExfilServerLink						  
	Get-SQLExfilAdHocQuery					
	
### Utility Functions

These are essentially helper functions.  Some of them are used by other PowerUpSQL functions, but all of them can be run independently.

|Function Name                 |Description |
|:-----------------------------|:-----------|
|Get-SQLConnectionObject | Creates a object for connecting to SQL Server.|
|Get-SQLFuzzObjectName | Enumerates objects based on object id using OBJECT_NAME() and only the Public role.|	
|Get-SQLFuzzDatabaseName | Enumerates databases based on database id using DB_NAME() and only the Public role.|
|Get-SQLFuzzServerLogin | Enumerates SQL Server Logins based on login id using SUSER_NAME() and only the Public role.|
|Get-SQLFuzzDomainAccount | Enumerates domain groups, computer accounts, and user accounts based on domain RID using SUSER_SNAME() and only the Public role.  Note: In a typical domain 10000 or more is recommended for the EndId.|
|Get-ComputerNameFromInstance | Parses computer name from a provided instance.|
|Get-SQLServiceLocal | Returns local SQL Server services.|
|Create-SQLFileXpDll | Used to create CPP DLLs with exported functions that can be imported as extended stored procedures in SQL Server. Supports arbitrary command execution.|
|Get-DomainSpn | Returns a list of SPNs for the target domain. Supports authentication from non domain systems.|
|Get-DomainObject | Used to query domain controllers via LDAP.  Supports alternative credentials from non-domain system.|

**Examples:** 

	Get-SQLFuzzServerLogin -Verbose -Instance "SQLSVR1\Instance1"

**Roadmap:**

	Get-SQLDatabaseOrphanUser             		
	Get-SQLDatabaseUser- add fuzzing option		
	Get-SQLDecryptedStoreProcedure            	
	Get-SQLDownloadFile				
	Get-SQLDownloadFileAdHocQuery			
	Get-SQLDownloadFileAssembly             	
	Get-SQLDownloadFileBulkInsert			
	Get-SQLDownloadFileServerLine			
	Get-SQLDownloadFileXpCmdshell			
	Get-SQLInstalledSoftware			
	Get-SQLServerLogin - add fuzzing option		
	Get-SQLUploadFile				
	Get-SQLUploadFileAdHocQuery             	
	Get-SQLUploadFileAgent				
	Get-SQLUploadFileAssembly             		
	Get-SQLUploadFileServerLink             	
	Get-SQLUploadFileXpCmdshell             	
	Invoke-SqlOSCmdAdHoQueryMd			
	Invoke-SqlOSCmdAgentActiveX            	
	Invoke-SqlOSCmdAgentAnalysis			
	Invoke-SqlOSCmdAgentCmdExe			
	Invoke-SqlOSCmdAgentPs			
	Invoke-SqlOSCmdAgentVbscript			
	Invoke-SqlOSCmdAssembly             		
	Invoke-SqlOSCmdServerLinkMd			
	Invoke-SqlOSCmdSsisExecuteProcessTask
	Create-SQLFileCLRDll
	Create-SQLFileXpDll

### Third Party Functions

A few PowerUpSQL functions use the third party functions below.

|Function Name                 |Description |
|:-----------------------------|:-----------|
|Invoke-Parallel|A PowerShell function created by Warren F. ( RamblingCookieMonster) for running multiple threads in PowerShell via runspaces.
|Invoke-Inveigh|A Windows PowerShell LLMNR/NBNS spoofer/man-in-the-middle tool create by Kevin Robertson.|
|Test-IsLuhnValid|Valdidate a number based on the Luhn Algorithm.  Function written by Oyvind Kallstad.|

