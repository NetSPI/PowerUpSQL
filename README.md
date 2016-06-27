To use the module, type `Import-Module PowerUpSQL.psm1`

To list functions from the module, type `Get-Command -Module PowerUpSQL`

To run as an alternative domain user, use the runas command to launch PowerShell first. Example: `runas /noprofile /netonly /user:domain\user PowerShell.exe`

## PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server

The PowerUpSQL module includes functions to support common attack workflows against SQL Server. However, I've also included many functions that could be used by administrators for SQL Server inventory and other auditing tasks.

It was designed with six objectives in mind:
* Scalability: Auto-discovery of sql server instances, pipeline support, and multi-threading on core functions is supported so commands can be executed against many SQL Servers quickly.  Multi-threading is currently a work in progress.  For now, I'm developing a seperate multi-threaded function for each existing function.
* Portability: Default .net libraries are used, and there are no dependancies on smo library or sqlps so commands can be run without having to install SQL Server. Also, functions are designed so they can run independantly.
* Flexibility: Most of the PowerUpSQL functions support the PowerShell pipeline so they can be used together, and with other scripts.
* Support Easy SQL Server Discovery: Discovery functions help users blindly identify local, domain, and non-domain SQL Server instances.
* Support Easy SQL Server Auditing: Invoke-PowerUpSQL audits for common high impact vulnerabilities and weak configurations by default.
* Support Easy SQL Server Exploitation: Invoke-PowerUpSQL can leverage SQL Server vulnerabilities to obtain sysadmin privileges to illistrate risk.

Script Information
* Author: Scott Sutherland (@_nullbind), NetSPI - 2016
* Version: 1.0.0.0
* Version Name: SQL Configuration Offensive Tools and Techniques (SCOTT) Edition
* Description: PowerUpSQL is a offensive toolkit that supports common attack workflow against SQL Server.
* License: BSD 3-Clause
* Required Dependencies: None
* Optional Dependencies: None

Below are the functions included in this module.  Many of them are complete, but I've also outlined the intended evelopment roadmap. High levle roadmap Goals include adding roadmapped modules, adding multi-threading to all common functions, and  testing against SQL Server version 2000 to 2014.

### Discovery Functions 

These functions can be used for enumerating SQL Server instances.  Discovered instances can then be piped into other PowerUpSQL functions.

Example: Get-SQLInstanceDomain -Verbose | Get-SQLServerInfo -Verbose

|Function Name|Description |Status    |
|:--------------------------------|:-----------|:---------|
|Get-SQLInstanceFile|Returns SQL Server instances from a file.  One per line. |Complete|
|Get-SQLInstanceLocal|Returns SQL Server instances from the local system based on a registry search.|Complete|
|Get-SQLInstanceDomain|Returns a list of SQL Server instances discovered by querying a domain controller for systems with registered MSSQL service principal names.  The function will default to the current user's domain and logon server, but an alternative domain controller can be provided. UDP scanning of management servers is optional.|Complete|
|Get-SQLInstanceScanUDP|Returns SQL Server instances from UDP scan results.|Complete|

	Roadmap:
	
	Get-SQLInstanceScanTCP - Returns SQL Server instances from TCP scan results.
	Get-SQLInstanceBroadcast - Returns SQL Server instances from UDP broadcast.

### Core Functions

These functions are used to test connections, execute SQL Server queries, and execute OS commands.  All other functions use these core functions.  However, they can also be executed independently. 

Example: Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 20 

Example: Get-SQLInstanceDomain -Verbose | Invoke-SQLOSCmd -Verbose -Threads 20 -Command "whoami"

|Function Name                 |Description |Status    |
|:-----------------------------|:-----------|:---------|
|Get-SQLConnectionTest|Tests if the current Windows account or provided SQL Server login can log into an SQL Server.|Complete|
|Get-SQLConnectionTestThreaded|Tests if the current Windows account or provided SQL Server login can log into an SQL Server and supports threading.|Complete|
|Get-SQLQuery|Executes a query on target SQL servers.|Complete|
|Get-SQLQueryThreaded|Executes a query on target SQL servers and supports threading.|Complete|
|Invoke-SQLOSCmd|Execute command on the operating system as the SQL Server service account using xp_cmdshell. Supports threading, raw output, and table output.|Complete|
	
### Common Functions

These functions are used for common information gathering tasks.  Similar to core functions, the common functions can be executed as standalone functions, but are also used other functions in the PowerUpSQL module.

Example: Get-SQLInstanceLocal | Get-SQLDatabase -Verbose -NoDefaults

Example: Get-SQLInstanceLocal | Get-SQLColumnSampleData -Keywords "account,credit,card" -SampleSize 5 -CheckCC 

|Function Name                 |Description |Status    |
|:-----------------------------|:-----------|:---------|
|Get-SQLAuditDatabaseSpec|Returns Audit database specifications from target SQL Servers.|Complete|
|Get-SQLAuditServerSpec|Returns Audit server specifications from target SQL Servers.|Complete|
|Get-SQLColumn|Returns column information from target SQL Servers. Supports keyword search.|Complete|
|Get-SQLColumnSampleData|Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers.|Complete|
|Get-SQLDatabase|Returns database information from target SQL Servers.|Complete|
|Get-SQLDatabasePriv|Returns database user privilege information from target SQL Servers.|Complete|
|Get-SQLDatabaseRole|Returns database role information from target SQL Servers.|Complete|
|Get-SQLDatabaseRoleMember|Returns database role member information from target SQL Servers.|Complete|
|Get-SQLDatabaseSchema|Returns schema information from target SQL Servers. |Complete|	
|Get-SQLDatabaseUser|Returns database user information from target SQL Servers.|Complete|
|Get-SQLServerCredential|Returns credentials from target SQL Servers.|Complete|
|Get-SQLServerInfo|Returns basic server and user information from target SQL Servers.|Complete|
|Get-SQLServerLink|Returns link servers from target SQL Servers.|Complete|
|Get-SQLServerLogin|Returns logins from target SQL Servers.|Complete|
|Get-SQLServerPriv|Returns SQL Server login privilege information from target SQL Servers.|Complete|
|Get-SQLServerRole|Returns SQL Server role information from target SQL Servers.|Complete|
|Get-SQLServerRoleMember|Returns SQL Server role member information from target SQL Servers.|Complete|
|Get-SQLServiceAccount|Returns a list of service account names for SQL Servers services by querying the registry with xp_regread.  This can be executed against remote systems.|Complete|
|Get-SQLSession|Returns active sessions from target SQL Servers.|Complete|
|Get-SQLStoredProcure|Returns stored procedures from target SQL Servers.|Complete|	
|Get-SQLSysadminCheck|Check if login is has sysadmin privilege on the target SQL Servers.|Complete|
|Get-SQLTable|Returns table information from target SQL Servers.|Complete|
|Get-SQLTriggerDdl|Returns DDL trigger information from target SQL Servers.  This includes logon triggers.|Complete|
|Get-SQLTriggerDml|Returns DML trigger information from target SQL Servers.|Complete|
|Get-SQLView|Returns view information from target SQL Servers.|Complete|

	Roadmap:
	
	Get-SQLProxyAccount - Returns proxy accounts from target SQL Servers.
	Get-SQLTempObject - Returns temp objects from target SQL Servers.	
	Get-SQLCachePlan - Returns cache plans from target SQL Servers.	
	Get-SQLQueryHistory - Returns recent query history from target SQL Servers.	
	Get-SQLHiddenSystemObject - Returns hidden system objects from target SQL Servers.	 
	
### Privilege Escalation Functions

These functions are used for obtaining sysadmin privileges from various levels of access in SQL Server.  Invoke-PowerUpSQL can be used to run all privileges escalation functions against provided SQL Server instances.

Example: Get-SQLInstanceLocal | Invoke-SQLEscalate-ImpersonateLogin -Verbose

Example: Get-SQLInstanceLocal | Invoke-PowerUpSQL -Verbose

|Function Name                 |Description |Status    |
|:-----------------------------|:-----------|:---------|
|Invoke-SQLEscalate-CreateProcedure|Check if the current login has the CREATE PROCEDURE permission.  Attempt to use permission to obtain sysadmin privileges.|Complete|
|Invoke-SQLEscalate-DbOwnerRole|Check if the current login has the DB_OWNER role in any databases.  Attempt to use permission to obtain sysadmin privileges.|Complete|
|Invoke-SQLEscalate-ImpersonateLogin|Check if the current login has the IMPERSONATE permission on any sysadmin logins. Attempt to use permission to obtain sysadmin privileges.|Complete|
|Invoke-SQLEscalate-SampleDataByColumn|Check if the current login can access any database columns that contain the word password. Supports column name keyword search and custom data sample size.  For better data searches use Get-SQLColumnSampleData.|Complete|
|Invoke-PowerUpSQL|Run all privilege escalation checks.  There is an options to auto-escalation to sysadmin.|Complete|

	Roadmap:
	
	Invoke-SQLEscalate-AgentJob 
	Invoke-SQLEscalate-SQLi-ImpersonateLogin - https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/
	Invoke-SQLEscalate-SQLi-ImpersonateDatabaseUser - https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/
	Invoke-SQLEscalate-SQLi-ImpersonateSignedSp - https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/
	Invoke-SQLEscalate-CreateStartUpSP
	Invoke-SQLEscalate-CreateServerLink
	Invoke-SQLEscalate-CrawlServerLink
	Invoke-SQLEscalate-CreateAssembly -CLR -Binary -C
	Invoke-SQLEscalate-CreateTriggerDDL
	Invoke-SQLEscalate-CreateTriggerLOGON
	Invoke-SQLEscalate-CreateTriggerDML
	Invoke-SQLEscalate-StealServiceToken
	Invoke-SQLEscalate-ControlServer
	Invoke-SQLEscalate-DDLAdmin
	Invoke-SqlInjectUncPath - https://github.com/nullbind/Powershellery/blob/master/Stable-ish/MSSQL/Get-SQLServiceAccountPwHash.ps1
	Create-SqlStoredProcedure - db_owner, db_ddladmin, db_securityadmin, or db_accessadmin
	Invoke-SqlCmdExecXpCmdshell
	Create-SqlStoredProcedureStartUp
	Create-SqlAgentJob
	Invoke-SQLEscalate-CrawlOwnershipChain
	Invoke-SQLEscalate-PrivAlterServerLogin
	Invoke-SQLEscalate-PrivAlterServerRole
	Invoke-SQLEscalate-PrivExternalAssembly
	Invoke-SQLEscalate-PrivAdministerBulkOps
	Invoke-SQLEscalate-PrivControlServer
	Invoke-SQLEscalate-DictionaryAttackOnline
	Invoke-SQLEscalate-DictionaryAttackOffline
	Invoke-SQLEscalate-ImpersonateDatabaseUser
	Invoke-SQLOSAdmintoSysadmin - https://github.com/nullbind/Powershellery/blob/master/Stable-ish/MSSQL/Invoke-SqlServerServiceImpersonation-Cmd.ps1

### Persistence Functions

These functions are used for maintaining access to the SQL Server using various methods.  The roadmap for development is below.  I've included a few links to standalone scripts that have not been integrated yet.

	Roadmap:
	
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
	
	Roadmap:
	
	Get-SQLRecoverPwCredential - https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLAllCredentials.psm1	
	Get-SQLRecoverPwServerLink - https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLLinkPasswords.psm1	
	Get-SQLRecoverPWProxyAccount - https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLAllCredentials.psm1	
	Get-SQLRecoverPwAutoLogon					 
	Get-SQLRecoverLoginHash						 
	Get-SQLRecoverMasterKey						 
	Get-SQLRecoverMachineKey		

### Data Exfiltration Functions

These functions are used for exfiltrating data out of SQL Server.  The roadmap for development is below.  

	Roadmap:
	
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

Example: Get-SQLFuzzServerLogin -Verbose -Instance "SQLSVR1\Instance1"

|Function Name                 |Description |Status    |
|:-----------------------------|:-----------|:---------|
|Get-SQLConnectionObject | Creates a object for connecting to SQL Server.|Complete|
|Get-SQLFuzzObjectName | Enumerates objects based on object id using OBJECT_NAME() and only the Public role.|Complete|	
|Get-SQLFuzzDatabaseName | Enumerates databases based on database id using DB_NAME() and only the Public role.|Complete|
|Get-SQLFuzzServerLogin | Enumerates SQL Server Logins based on login id using SUSER_NAME() and only the Public role.|Complete|
|Get-SQLFuzzDomainAccount | Enumerates domain groups, computer accounts, and user accounts based on domain RID using SUSER_SNAME() and only the Public role.  Note: In a typical domain 10000 or more is recommended for the EndId.|Complete|
|Get-ComputerNameFromInstance | Parses computer name from a provided instance.|Complete|
|Get-SQLServiceLocal | Returns local SQL Server services.|Complete|
|Create-SQLFile-XPDLL | Used to create CPP DLLs with exported functions that can be imported as extended stored procedures in SQL Server. Supports arbitrary command execution.|Complete|
|Get-DomainSpn | Returns a list of SPNs for the target domain. Supports authentication from non domain systems.|Complete|
|Get-DomainObject | Used to query domain controllers via LDAP.  Supports alternative credentials from non-domain system.|Complete|
	
	Roadmap:

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
	Create-SQLFile-XPDLLCLR
	Create-SQLFile-XPDLLBinary

### Third Party Functions

These are functions developed by third parties.  Most of them have been modified slightly.

|Function Name                 |Description |Status    |
|:-----------------------------|:-----------|:---------|
|Invoke-Parallel|Modified version of RamblingCookieMonster's (Warren F) function that supports importing functions from the current session.|Complete|
|Test-IsLuhnValid|Valdidate a number based on the Luhn Algorithm.  Function written by ØYVIND KALLSTAD.|Complete|
