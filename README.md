To use the module, type `Import-Module PowerUpSQL.psm1`

## PowerUpSQL: An Offensive Toolkit for SQL Server

The PowerUpSQL module includes functions to support common attack workflows against SQL Server. However, I've also included many functions that could be used by administrators for SQL Server inventory and other auditing tasks.

It was designed with six objectives in mind:
* Scalability: Auto-discovery of sql server instances, pipeline support, and multi-threading on core functions is supported so commands can be executed against many SQL Servers quickly.  Multi-threading is currently a work in progress.  For now, I'm developing a seperate multi-threaded function for each existing function.
* Portability: Default .net libraries are used, and there are no SMO dependancies so commands can be run without having to install SQL Server. Also, functions are designed so they can run independantly.
* Flexibility: Most of the PowerUpSQL functions support the PowerShell pipeline so they can be used together, and with other scripts.
* Support Easy SQL Server Discovery: Discovery functions help users blindly identify local, domain, and non-domain SQL Server instances.
* Support Easy SQL Server Auditing: Invoke-PowerUpSQL audits for common high impact vulnerabilities and weak configurations by default.
* Support Easy SQL Server Exploitation: Invoke-PowerUpSQL can leverage SQL Server vulnerabilities to obtain sysadmin privileges to illistrate risk.


Script Information
* Author: Scott Sutherland (@_nullbind), NetSPI - 2016
* License: BSD 3-Clause
* Required Dependencies: PowerShell v3 (or later)
* Optional Dependencies: None 

Below are the functions included in this module.  Many are complete, but I've also outlined the intended roadmap.

### Discovery Functions:  
	Get-SQLInstanceFile			-   [Complete] 	- Returns SQL Server instances from a file.  One per line.
	Get-SQLInstanceLocal		-   [Complete] 	- Returns SQL Server instances from the local system based on a registry search.
	Get-SQLInstanceDomain		-   [Complete] 	- Returns SQL Server instances from LDAP query results. Based on SPNs and UDP scanning of management servers.
	Get-SQLInstanceScanUDP		-   [Complete] 	- Returns SQL Server instances from UDP scan results.

### Core Functions:
	Get-SQLConnectionTest			-   [Complete] 	- Tests if the current Windows account or provided SQL Server login can log into an SQL Server.
	Get-SQLConnectionTestThreaded	-   [Complete] 	- Tests if the current Windows account or provided SQL Server login can log into an SQL Server and supports threading.
	Get-SQLQuery					-   [Complete] 	- Executes a query on target SQL servers.
	Get-SQLQueryThreaded			-   [Complete] 	- Executes a query on target SQL servers and supports threading.
	Invoke-SQLOSCmd					-   [Complete] 	- Execute command on the operating system as the SQL Server service account using xp_cmdshell. Supports threading, raw output, and table output.
	
### Common Functions:	
	Get-SQLAuditDatabaseSpec	-   [Complete] 	- Returns Audit database specifications from target SQL Servers.
	Get-SQLAuditServerSpec		-   [Complete] 	- Returns Audit server specifications from target SQL Servers.
	Get-SQLColumn				-   [Complete] 	- Returns column information from target SQL Servers. Supports keyword search.
	Get-SQLColumnSampleData		-   [Complete] 	- Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers.
	Get-SQLDatabase				-   [Complete] 	- Returns database information from target SQL Servers.
	Get-SQLDatabasePriv			-   [Complete] 	- Returns database user privilege information from target SQL Servers.
	Get-SQLDatabaseRole			-   [Complete]	- Returns database role information from target SQL Servers.
	Get-SQLDatabaseRoleMember	-   [Complete]	- Returns database role member information from target SQL Servers.
	Get-SQLDatabaseSchema		-   [Complete] 	- Returns schema information from target SQL Servers. 			
	Get-SQLDatabaseUser			-   [Complete] 	- Returns database user information from target SQL Servers.
	Get-SQLServerCredential		-   [Complete] 	- Returns credentials from target SQL Servers.
	Get-SQLServerInfo			-   [Complete] 	- Returns basic server and user information from target SQL Servers.
	Get-SQLServerLink			-   [Complete] 	- Returns link servers from target SQL Servers. 
	Get-SQLServerLogin			-   [Complete] 	- Returns logins from target SQL Servers.
	Get-SQLServerPriv			-   [Complete] 	- Returns SQL Server login privilege information from target SQL Servers.
	Get-SQLServerRole			-   [Complete] 	- Returns SQL Server role information from target SQL Servers.
	Get-SQLServerRoleMember		-   [Complete] 	- Returns SQL Server role member information from target SQL Servers.
	Get-SQLServiceAccount		-   [Complete] 	- Returns a list of local SQL Server services.
	Get-SQLSession				-   [Complete] 	- Returns active sessions from target SQL Servers.
	Get-SQLStoredProcure		-   [Complete] 	- Returns stored procedures from target SQL Servers.	
	Get-SQLSysadminCheck		-   [Complete] 	- Check if login is has sysadmin privilege on the target SQL Servers. 
	Get-SQLTable				-   [Complete] 	- Returns table information from target SQL Servers.
	Get-SQLTriggerDdl			-   [Complete] 	- Returns DDL trigger information from target SQL Servers.  This includes logon triggers.
	Get-SQLTriggerDml			-   [Complete] 	- Returns DML trigger information from target SQL Servers.
	Get-SQLView					-   [Complete] 	- Returns view information from target SQL Servers.

	Roadmap:
	
	Get-SQLProxyAccount			-   [Roadmap]	- Returns proxy accounts from target SQL Servers.
	Get-SQLTempObject			-   [Roadmap] 	- Returns temp objects from target SQL Servers.	
	Get-SQLCachePlan			-   [Roadmap] 	- Returns cache plans from target SQL Servers.	
	Get-SQLQueryHistory			-   [Roadmap] 	- Returns recent query history from target SQL Servers.	
	Get-SQLHiddenSystemObject	-   [Roadmap] 	- Returns hidden system objects from target SQL Servers.	 
	
### Privilege Escalation Functions:
	Invoke-SQLEscalate-CreateProcedure      -   [Complete] 	- Get sysadmin using create procedure privileges.
	Invoke-SQLEscalate-DbOwnerRole          -   [Complete] 	- Get sysadmin using dbowner privileges.
	Invoke-SQLEscalate-ImpersonateLogin     -   [Complete] 	- Get sysadmin using impersonate login privileges.
	Invoke-SQLEscalate-SampleDataByColumn   -   [Complete] 	- Find password and potentially sensitive data.  Support column name keyword search and custom data sample size.
	Invoke-PowerUpSQL                       -   [Complete] 	- Run all privilege escalation checks.  There is an options to auto-escalation to sysadmin.

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

### Persistence Functions: 

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

### Password Recovery Functions:
	
	Roadmap:
	
	Get-SQLRecoverPwCredential - https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLAllCredentials.psm1	
	Get-SQLRecoverPwServerLink - https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLLinkPasswords.psm1	
	Get-SQLRecoverPWProxyAccount - https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLAllCredentials.psm1	
	Get-SQLRecoverPwAutoLogon					 
	Get-SQLRecoverLoginHash						 
	Get-SQLRecoverMasterKey						 
	Get-SQLRecoverMachineKey		

### Data Exfiltration Functions:

	Roadmap:
	
	Get-SQLExfilHttp							   
	Get-SQLExfilHttps							      
	Get-SQLExfilDns								      
	Get-SQLExfilSmb								     
	Get-SQLExfilSmtp							     
	Get-SQLExfilFtp								      
	Get-SQLExfilServerLink						  
	Get-SQLExfilAdHocQuery					
	
### Utility Functions:
	Get-SQLConnectionObject			-   [Complete] 	- Creates a object for connecting to SQL Server.
	Get-SQLFuzzObjectName			-   [Complete] 	- Enumerates objects based on object id using OBJECT_NAME() and only the Public role.
	Get-SQLFuzzDatabaseName			-   [Complete] 	- Enumerates databases based on database id using DB_NAME() and only the Public role.
	Get-SQLFuzzServerLogin			-   [Complete] 	- Enumerates SQL Server Logins based on login id using SUSER_NAME() and only the Public role.
	Get-SQLFuzzDomainAccount		-   [Complete] 	- Enumerates domain accounts based on domain RID using SUSER_SNAME() and only the Public role.
	Get-ComputerNameFromInstance	-   [Complete] 	- Parses computer name form a provided instance.
	Get-SQLServiceLocal				-   [Complete] 	- Returns local SQL Server services.
	Create-SQLFile-XPDLL			-   [Complete] 	- Used to create DLLs with exported functions that can be imported as extended stored procedures in SQL Server. Supports arbitrary command execution.
	Get-DomainSpn					-   [Complete] 	- Returns a list of SPNs for the target domain. Supports authentication from non domain systems. (consider moving to utility)
	Get-DomainObject				-   [Complete] 	- Used to query domain controllers via LDAP.  Based on @Harmj0y's function to query LDAP.		 (consider moving to utility)
	
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

### Third Party Functions:
	Invoke-Parallel					-   [Complete] 	- Modified version of RamblingCookieMonster's function that supports importing functions from the current session.
	Test-IsLuhnValid				-   [Complete] 	- Valdidate a number based on the Luhn Algorithm.  Function written by ØYVIND KALLSTAD.
