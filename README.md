To use the module, type `Import-Module PowerUpSQL.psm1`

To list functions from the module, type `Get-Command -Module PowerUpSQL`

To run as an alternative domain user, use the runas command to launch PowerShell first.

Example: `runas /noprofile /netonly /user:domain\user PowerShell.exe`

## PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server

The PowerUpSQL module includes functions to support common attack workflows against SQL Server. However, I've also included many functions that could be used by administrators for SQL Server inventory and other auditing tasks.

It was designed with six objectives in mind:
* Scalability: Auto-discovery of sql server instances, pipeline support, and multi-threading on core functions is supported so commands can be executed against many SQL Servers quickly.
* Portability: Default .net libraries are used and there are no dependancies on SQLPS or the SMO libraries. Also, functions are designed so they can run independantly.
* Flexibility: PowerUpSQL functions support the PowerShell pipeline so they can be used together, and with other scripts.
* Easy Server Discovery: Blindly identify local, domain, and non-domain SQL Server instances on scale using discovery functions.
* Easy Server Auditing: Invoke-SQLAudit audits for common high impact vulnerabilities and weak configurations.  Also, Invoke-SQLDumpInfo can be used to quickly inventory databases, privileges, and other information.
* Easy Server Exploitation: Invoke-SQLEscalatePriv uses identify vulnerabilities to obtain sysadmin privileges.

Script Information
* Author: Scott Sutherland (@_nullbind), NetSPI - 2016
* Version: 1.0.0.0
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
|Get-SQLInstanceFile|Returns SQL Server instances from a file.  One per line.| 
|Get-SQLInstanceLocal|Returns SQL Server instances from the local system based on a registry search.|
|Get-SQLInstanceDomain|Returns a list of SQL Server instances discovered by querying a domain controller for systems with registered MSSQL service principal names.  The function will default to the current user's domain and logon server, but an alternative domain controller can be provided. UDP scanning of management servers is optional.|
|Get-SQLInstanceScanUDP|Returns SQL Server instances from UDP scan results.|

	Roadmap:
	
	Get-SQLInstanceScanTCP - Returns SQL Server instances from TCP scan results.
	Get-SQLInstanceBroadcast - Returns SQL Server instances from UDP broadcast.

### Primary Attack Functions

These are the functions used to quickly dump databse information, audit for common vulnerabilities, and attempt to obtain sysadmin privileges.

|Function Name                 |Description |Status    |
|:-----------------------------|:-----------|:---------|
|Get-SQLDumpInfo|This can be used to dump SQL Server and database information to csv or xml files.  This can be handy for doing a quick inventory of databases, logins, privileges etc.|
|Get-SQLAudit|This can be used to review the SQL Server and databases for common configuration weaknesses and provide a vulnerability report along with recommendations for each item.|
|Get-SQLEscalatePriv|This can be used to obtain sysadmin privileges via the identify weak configurations.  Think of it like get-system, but for SQL Server.|


### Core Functions

These functions are used to test connections, execute SQL Server queries, and execute OS commands.  All other functions use these core functions.  However, they can also be executed independently. 

Example: Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 20 

Example: Get-SQLInstanceDomain -Verbose | Invoke-SQLOSCmd -Verbose -Threads 20 -Command "whoami"

|Function Name                 |Description |Status    |
|:-----------------------------|:-----------|:---------|
|Get-SQLConnectionTest|Tests if the current Windows account or provided SQL Server login can log into an SQL Server.
|Get-SQLConnectionTestThreaded|Tests if the current Windows account or provided SQL Server login can log into an SQL Server and supports threading.|
|Get-SQLQuery|Executes a query on target SQL servers.|
|Get-SQLQueryThreaded|Executes a query on target SQL servers and supports threading.|
|Invoke-SQLOSCmd|Execute command on the operating system as the SQL Server service account using xp_cmdshell. Supports threading, raw output, and table output.|
	
### Common Functions

These functions are used for common information gathering tasks.  Similar to core functions, the common functions can be executed as standalone functions, but are also used other functions in the PowerUpSQL module.

Example: Get-SQLInstanceLocal | Get-SQLDatabase -Verbose -NoDefaults

Example: Get-SQLInstanceLocal | Get-SQLColumnSampleData -Keywords "account,credit,card" -SampleSize 5 -CheckCC 

|Function Name                 |Description |Status    |
|:-----------------------------|:-----------|:---------|
|Get-SQLAuditDatabaseSpec|Returns Audit database specifications from target SQL Servers.|
|Get-SQLAuditServerSpec|Returns Audit server specifications from target SQL Servers.|
|Get-SQLColumn|Returns column information from target SQL Servers. Supports keyword search.|
|Get-SQLColumnSampleData|Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers.|
|Get-SQLDatabase|Returns database information from target SQL Servers.|
|Get-SQLDatabasePriv|Returns database user privilege information from target SQL Servers.|
|Get-SQLDatabaseRole|Returns database role information from target SQL Servers.|
|Get-SQLDatabaseRoleMember|Returns database role member information from target SQL Servers.|
|Get-SQLDatabaseSchema|Returns schema information from target SQL Servers. |	
|Get-SQLDatabaseUser|Returns database user information from target SQL Servers.|
|Get-SQLServerCredential|Returns credentials from target SQL Servers.|
|Get-SQLServerInfo|Returns basic server and user information from target SQL Servers.|
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

	Roadmap:
	
	Get-SQLProxyAccount - Returns proxy accounts from target SQL Servers.
	Get-SQLTempObject - Returns temp objects from target SQL Servers.	
	Get-SQLCachePlan - Returns cache plans from target SQL Servers.	
	Get-SQLQueryHistory - Returns recent query history from target SQL Servers.	
	Get-SQLHiddenSystemObject - Returns hidden system objects from target SQL Servers.	 
	
### Audit Functions

These functions are used for identifying weak configurations that can lead to unauthorized access.  Invoke-SQLAudit can be used to run all of them at once.

Example: Get-SQLInstanceLocal | Invoke-SQLAuditPrivImpersonateLogin -Verbose

|Function Name                 |Description |Provide Sysadmin   |
|:-----------------------------|:-----------|:---------|
|Invoke-SQLAuditPrivCreateProcedure|Check if the current login has the CREATE PROCEDURE permission.  Attempt to use permission to obtain sysadmin privileges.|No|
|Invoke-SQLAuditPrivImpersonateLogin|Check if the current login has the IMPERSONATE permission on any sysadmin logins. Attempt to use permission to obtain sysadmin privileges.|Yes|
|Invoke-SQLAuditPrivServerLink|Check if SQL Server links exist that are preconfigured with alternative credentials that can be impersonated. Provide example queries for execution on remote servers.|Yes|
|Invoke-SQLAuditPrivTrustworthy|Check if any database have been flagged as trusted.|No|
|Invoke-SQLAuditRoleDbDdlAdmin|Check if the current login has the DB_DdlAdmin role in any databases.  Attempt to use permission to obtain sysadmin privileges.|No|
|Invoke-SQLAuditRoleDbOwner|Check if the current login has the DB_OWNER role in any databases.  Attempt to use permission to obtain sysadmin privileges.|Yes|
|Invoke-SQLAuditSampleDataByColumn|Check if the current login can access any database columns that contain the word password. Supports column name keyword search and custom data sample size.  For better data searches use Get-SQLColumnSampleData.|No|
|Invoke-SQLAuditWeakLoginPw|This can be used for online dictionary attacks. It also support auto-discovery of SQL Logins for testing if you already have a least privilege account.|Yes|


	Roadmap:
	
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
