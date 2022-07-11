
/*
[S]QL Server [A]nalysis and [S]ecurity [A]udit [T]ool (SASAT) 
Created by Rudy Panigas

This script will analyse the SQL Server setting and produce a report on the findings
The report shows the summary of the server's information, analyses of possible dangerous setting and 
analyses the security configuration. If security issues are found, explanation(s) and recommendation(s) 
are show and how to made the change(s) with either SSMS or T-SQL script(s). This script works on SQL 2012 and higher.

***********************************************************************************************************************************
    *    
  *   *	  Disclaimer ** Use this script at your own risk. The author does not take any responsiblities for correctness of report. 
 *  !  *                All findings should be reviewed with production DBAs, auditors and Microsoft support. **  
*       *
*********
************************************************************************************************************************************

Apr 10, 2015 - Version 1.0 - 1.9  -Initial build
Apr 16, 2015 - Version 2.0 - 2.3  -Testing and correcting errors 
Apr 20, 2015 - Version 2.4  -Added server inventory output and audit analysis
Apr 20, 2015 - Version 2.5  -Added remediation scripts
Apr 21, 2015 - Version 2.6  -Added totals and percentage passed 
Apr 21, 2015 - Version 2.7  -Removed testing section
May 15, 2015 - Version 2.8  -Added check for xp_fixeddrives and Trace Flag detection
May 28, 2015 - Version 2.9  -Change some wording and web link verification
May 29, 2015 - Version 3.0  -Tweaked the output of results. Change name to SASAT (Server Analysis and Security Audit Tool)
Jun 01, 2015 - Version 3.1  -Change incorrect logic with default trace file detection. 
                            -Tested the script on SQL 2005, 2008, 2008R2, 2012 and 2014 with no issues 
				            - Added audit for login authentication
Jun 12, 2015 - Version 3.2  -Removed the need to change the sp_configure 'show advanced options'
				            -Added audit for 'sa' account 
Jun 15, 2015 - Version 3.3  -Changed output format for better viewing
Aug 20, 2015 - Version 3.4  -Changed output results format for better viewing. Tested all HTTP links
Aug 21, 2015 - Version 3.5  -Added detection of SysAdmin Members and ServerAdmin Members
Aug 24, 2015 - Version 3.6  -Changes to output of numbered steps. Added display for sp_configure with effect of changes
Aug 27, 2015 - Version 3.7  -Changed output format for better viewing
Sep 02, 2015 - Version 3.8  -Added detection of Instance and provide steps for manual analysis 
Sep 03, 2015 - Version 3.9  -Removed the need to display of sp_configure at end of report. Code commented out 
                            -Changed output for sys and Server Admin display
Sep 04, 2015 - Version 4.0  -Added detection of SQL installation on physical or virtual server
Sep 15, 2015 - Version 4.1  -Correct port number detection for NULL value. Added IP detection 
Sep 15, 2015 - Version 4.2  -Changed detection of Name Pipe or TCP connection
Sep 16, 2015 - Version 4.3  -Updated URL links
Sep 17, 2015 - Version 4.4  -Changed output for Trace Flag information. Fixed detection of xp_cmdshell
Sep 21, 2015 - Version 4.5  -Changed output for better reading of results
Oct 13, 2015 - Version 4.6  -Changed output for better reading of results, again
Oct 28, 2015 - Version 4.7  -Added display of total memory of server
Jan 06, 2016 - Version 4.8  -Added detection of Trustworthy setting on databases
Jan 08, 2016 - Version 4.9  -Provide list of section that have failed the analyses/audit

*/
----------------------- Version Control -------------------------------*/
DECLARE @UpdatedDate VARCHAR(30)
SET @UpdatedDate = 'Jan 08, 2016 - Version 4.9'

SET NOCOUNT ON;
PRINT ''
PRINT '							SQL Server Analysis and Security Audit Tool (SASAT)'
PRINT '							***************************************************' 
PRINT '								Current version: ' +@UpdatedDate
PRINT ' '
PRINT 'This script will analyse/audit your SQL Server settings and report on the findings. The report shows the summary of SQL'
PRINT 'server''s information, analyse possible dangerous settings and analyses the security configuration. If issues are detected'
PRINT 'then explanations, recommendations and how to make changes (either with SSMS or with T-SQL scripts) are shown.'
PRINT ' '
PRINT '		 					The following (33) SQL Server settings are reviewed'
PRINT ''
PRINT '	TRUSTWORTHY databases			Allow Remote Access				Cross DB Ownership Chaining		Max Worker Threads'
PRINT '	Priority Boost					Lightweight Pooling				Startup Stored Procedures		Affinity64 Mask'
PRINT '	Affinity I/O Mask				Affinity64 I/O Mask				CLR enabled						Database Mail XPs'
PRINT '	OLE Automation Procedures		Ad Hoc Distributed Queries		sa account						Remote Admin Connections'
PRINT '	Default Trace file				Default SQL Port Number			xp_dirtree						xp_fixeddrives'
PRINT '	xp_enumgroups					xp_servicecontrol				xp_subdirs						xp_regaddmultistring'
PRINT '	xp_regdeletekey					xp_regdeletevalue				xp_regenumvalues				xp_regremovemultistring'
PRINT '	xp_regwrite						xp_regwrite						Audit Level						xp_cmdshell'
PRINT '	Server Authentication'
PRINT ''
DECLARE 
	 @CurrentDate NVARCHAR(12) -- Current data/time
	,@SQLServerName NVARCHAR(50) --Set SQL Server Name
	,@NodeName1 NVARCHAR(50) -- Name of node 1 if clustered
	,@NodeName2 NVARCHAR(50) -- Name of node 2 if clustered
	--,@NodeName3 NVARCHAR(50) /* -- remove remarks if more than 2 node cluster */
	--,@NodeName4 NVARCHAR(50) /*-- remove remarks if more than 2 node cluster */
	,@AccountName NVARCHAR(50) -- Account name used
	,@StaticPortNumber NVARCHAR(50) -- Static port number
	,@INSTANCENAME NVARCHAR(30) -- SQL Server Instance Name
	,@VALUENAME NVARCHAR(20) -- Detect account used in SQL 2005, see notes below
	,@KERB NVARCHAR(50) -- Is Kerberos used or not
	,@DomainName NVARCHAR(50) -- Name of Domain
	,@IP NVARCHAR(20)  -- IP address used by SQL Server
	,@InstallDate NVARCHAR(20) -- Installation date of SQL Server
	,@ProductVersion NVARCHAR(30) -- Production version
	,@MachineName NVARCHAR(30) -- Server name
	,@ServerName NVARCHAR(30) -- SQL Server name
	,@EDITION NVARCHAR(30) --SQL Server Edition
	,@ProductLevel NVARCHAR(20) -- Product level
	,@ISClustered NVARCHAR(20) -- System clustered
	,@ISIntegratedSecurityOnly NVARCHAR(50) -- Security level
	,@ISSingleUser NVARCHAR(20) -- System in Single User mode
	,@COLLATION NVARCHAR(30)  -- Collation type
	,@physical_CPU_Count VARCHAR(4) -- CPU count
	,@EnvironmentType VARCHAR(15) -- Physical or Virtual
	,@MachineType INT -- Server type 
	,@MaxMemory NVARCHAR(10) -- Max memory
	,@MinMemory NVARCHAR(10) -- Min memory
	,@TotalMEMORYinBytes NVARCHAR(10) -- Total memory
	,@TotalMEMORYinMegaBytes NVARCHAR(10) -- Converted value of physical server memory in megabytes
	,@ErrorLogLocation VARCHAR(500) -- location of error logs
	,@TraceFileLocation VARCHAR(100) -- location of trace files
	,@LinkServers VARCHAR(2) -- Number of linked servers found
	,@FileStreams  VARCHAR(2) -- Is FileStreams enabled
	,@BackUpCompression VARCHAR(2) -- Is backup compression enabled
	,@TestResultCounter NUMERIC (3,0) -- tracks total tests passed and is used in final reporting section
	,@ResultsPercentage NUMERIC (3,0) -- Results as percentage passed
	,@TotalAutomatedTests NUMERIC (3,0) --Total automated test
	,@DefaultTraceEnabled VARCHAR(2) -- Is default trace enabled
	,@xp_cmdshellEnabled VARCHAR(2) -- Is command shell enabled
	,@RemoteAdminConnections VARCHAR(2) -- is remote admin connection enabled
	,@xp_dirtreeEnabled NVARCHAR(10) -- is xp_dirtree enabled
	,@xp_fixeddrivesEnabled NVARCHAR(10) -- is xp_emumgroups enabled
	,@xp_enumgroupsEnabled NVARCHAR(10) -- is xp_emumgroups enabled
	,@xp_servicecontrolEnabled  NVARCHAR(10)  -- is xp_servicecontrol enabled
	,@xp_subdirsEnabled NVARCHAR(10)  -- is xp_subdirs enabled
	,@xp_regaddmultistringEnabled  NVARCHAR(10) -- is xp_readdmultistring enabled
	,@xp_regdeletekeyEnabled  NVARCHAR(10)  -- is xp_regdeletekey enabled
	,@xp_regdeletevalueEnabled NVARCHAR(10)  -- is xp_regdeletevalue enabled
	,@xp_regenumvaluesEnabled NVARCHAR(10)   -- is xp_regnumvalues enabled
	,@xp_regremovemultistringEnabled  NVARCHAR(10)  -- is xp_regremovemultistring enabled 
	,@xp_regwriteEnabled NVARCHAR(10) -- is xp_regwrite enabled
	,@xp_regreadEnabled NVARCHAR(10)  -- is xp_regread enabled 
	,@SADisabled NVARCHAR(15) -- is the 'sa' account enabled
	,@TRANSPORT NVARCHAR(20) -- Connection type
	,@AuditLevel int -- Connection audit levels
	,@AuditLvltxt VARCHAR(50) -- Connection audit levels description

SET @TestResultCounter = 0 -- setting counter to zero
SET @ResultsPercentage = 0 -- setting percentage to zero
SET @TotalAutomatedTests = 33 -- setting total number of automated test
SET @CurrentDate = (SELECT GETDATE())
SET @ServerName = (SELECT @@SERVERNAME)

CREATE TABLE #SASATFailed  -- Record sections that have failed audit
(AuditName NVARCHAR(50));

PRINT '							Report generated for '''+@ServerName+''' SQL Server on '+@CurrentDate
PRINT ' '
PRINT '										******** SQL Server Summary ********'
PRINT ' '
SET @SQLServerName = (SELECT @@ServerName) 
PRINT '					* Detected - SQL Server name\Instance name --> '+@SQLServerName

SET @InstallDate = (SELECT  createdate FROM sys.syslogins where sid = 0x010100000000000512000000)
PRINT '					* Detected - Installation Date --> '+@InstallDate

SET @MachineName = (SELECT CONVERT(char(100), SERVERPROPERTY('MachineName'))) 
PRINT '					* Detected - Machine Name --> '+@MachineName

SET @InstanceName = (SELECT CONVERT(char(50), SERVERPROPERTY('InstanceName')))
IF (@InstanceName IS NULL) SET @InstanceName = 'Default Instance'
PRINT '					* Detected - Instance Name --> '+@InstanceName

SET @EDITION = (SELECT CONVERT(char(30), SERVERPROPERTY('EDITION')))
PRINT '					* Detected - Edition and BIT Level --> '+@EDITION 

SET @ProductLevel = (SELECT CONVERT(char(30), SERVERPROPERTY('ProductLevel')))
PRINT '					* Detected - Production Service Pack Level --> '+@ProductLevel 
SET @ProductVersion = (SELECT CONVERT(char(30), SERVERPROPERTY('ProductVersion')))
PRINT '					* Detected - Production Version --> '+@ProductVersion

IF @ProductVersion LIKE '6.5%' 
BEGIN
	 SET @ProductVersion = 'SQL Server 6.5' 
	 SET @MachineType = 6
END

IF @ProductVersion LIKE '7.0%' 
BEGIN
	SET @ProductVersion = 'SQL Server 7' 
	SET @MachineType = 7
END

IF @ProductVersion LIKE '8.0%' 
BEGIN
	SET @ProductVersion = 'SQL Server 2000' 
	SET @MachineType = 8
END

IF @ProductVersion LIKE '9.0%' 
BEGIN
	SET @ProductVersion = 'SQL Server 2005'   
	SET @MachineType = 9
END

IF @ProductVersion LIKE '10.0%'  
BEGIN
	SET @ProductVersion = 'SQL Server 2008'  
	SET @MachineType = 10
END

IF @ProductVersion LIKE '10.50%' 
BEGIN
	SET @ProductVersion = 'SQL Server 2008R2'  
	SET @MachineType = 10
END

IF @ProductVersion LIKE '11.0%' 
BEGIN
	SET @ProductVersion = 'SQL Server 2012'  
	SET @MachineType = 11
END

IF @ProductVersion LIKE '12.0%' 
BEGIN
	SET @ProductVersion = 'SQL Server 2014'  
	SET @MachineType = 12
END

IF @ProductVersion LIKE '14.0%' 
BEGIN
	SET @ProductVersion = 'SQL Server 2016' 
	SET @MachineType = 14  -- for future use
END

IF @ProductVersion LIKE '15.0%' 
BEGIN
	SET @ProductVersion = 'SQL Server 2018' 
	SET @MachineType = 15  -- for future use
END
PRINT '					* Detected - Production Name --> '+@ProductVersion 

IF  @MachineType >= 11 
BEGIN
		IF(SELECT virtual_machine_type FROM sys.dm_os_sys_info) = 1
			SET @EnvironmentType = 'Virtual'
		IF(SELECT virtual_machine_type FROM sys.dm_os_sys_info) = 0
		 	SET @EnvironmentType = 'Physical'
		PRINT '					* Detected - Environment Type --> '+@EnvironmentType
END

SET @physical_CPU_Count = (SELECT cpu_count FROM sys.dm_os_sys_info)
PRINT '					* Detected - Logical CPU Count --> '+@physical_CPU_Count

SET @TotalMEMORYinBytes = CONVERT(NVARCHAR(10),(select physical_memory_kb from sys.dm_os_sys_info))
SET @TotalMEMORYinMegaBytes = (@TotalMEMORYinBytes /(1024)) 
PRINT '					* Detected - Total Memory (Megabytes) --> '+@TotalMEMORYinMegaBytes

SET @MaxMemory = CONVERT(NVARCHAR(10), (SELECT VALUE FROM SYS.CONFIGURATIONS where Name like 'max server memory%'))
SET @MinMemory = CONVERT(NVARCHAR(10), (SELECT VALUE FROM SYS.CONFIGURATIONS where Name like 'min server memory%'))
PRINT '					* Detected - Maximum Memory (Megabytes) --> '+@MaxMemory
PRINT '					* Detected - Minimum Memory (Megabytes) --> '+@MinMemory

SET @IP = (SELECT DEC.Local_Net_Address FROM sys.dm_exec_connections AS DEC WHERE DEC.session_id = @@SPID)

IF (@IP IS NULL)
BEGIN
	PRINT '					* Detected - IP Address --> No connection with IP address made'
END
ELSE
BEGIN
	PRINT '					* Detected - IP Address --> '+@IP
	SET @StaticPortNumber = (SELECT local_tcp_port FROM sys.dm_exec_connections WHERE session_id = @@SPID)
	PRINT '					* Detected - Port Number --> '+@StaticPortNumber
END

SET @DomainName = (SELECT DEFAULT_DOMAIN())
PRINT '					* Detected - Default Domain Name --> '+@DomainName
-------------------------------------------------------------------------------------------------------------------------
--For Service Account Name - This line will work on SQL 2008R2 and higher only

SET @AccountName = (SELECT top 1 service_account FROM sys.dm_server_services)
EXECUTE  master.dbo.xp_instance_regread
		@rootkey      = N'HKEY_LOCAL_MACHINE',
		@key          = N'SYSTEM\CurrentControlSet\Services\MSSQLServer',
		@value_name   = N'ObjectName',
		@value        = @AccountName OUTPUT

-- -- Use this section, instead of the above if your are scanning SQL Servers 2008 and lower
--EXECUTE  master.dbo.xp_instance_regread
--		@rootkey      = N'HKEY_LOCAL_MACHINE',
--		@key          = N'SYSTEM\CurrentControlSet\Services\MSSQLServer',
--		@value_name   = N'ObjectName',
--		@value        = @AccountName OUTPUT
-------------------------------------------------------------------------------------------------------------------------
PRINT '					* Detected - Service Account name --> '+@AccountName

IF (SELECT CONVERT(char(30), SERVERPROPERTY('ISClustered'))) = 1
	SET @ISClustered = 'Clustered'
ELSE
	SET @ISClustered = 'Not Clustered'
PRINT '					* Detected - Clustered Status --> '+@ISClustered 

--cluster node names. Modify if there are more than 2 nodes in cluster
SELECT NodeName INTO #nodes FROM sys.dm_os_cluster_nodes 
	IF @@rowcount = 0 
	BEGIN 
		SET @NodeName1 = 'NONE' -- NONE for no cluster
	END
	ELSE
	BEGIN
		SET @NodeName1 = (SELECT top 1 NodeName from #nodes)
		SET @NodeName2 = (SELECT NodeName from #nodes where NodeName <> @NodeName1)
		-- Add code here if more that 2 node cluster
		--SET @NodeName3 = (SELECT NodeName from #nodes where NodeName <> @NodeName1 AND NodeName <> @NodeName2)
		--SET @NodeName4 = (SELECT NodeName from #nodes where NodeName <> @NodeName1 AND NodeName <> @NodeName2 AND NodeName <> @NodeName3)
    END

IF @NodeName1 = 'NONE'
BEGIN
	PRINT '					* Detected - Cluster --> SQL Server is not clustered'
END
ELSE
BEGIN
	PRINT '					* Detected - cluster node 1 --> '+@NodeName1
	PRINT '					* Detected - cluster node 2 --> '+@NodeName2
	-- Add code here if more that 2 node cluster
	-- PRINT '					* Detected - cluster node 3 --> '+@NodeName3
	-- PRINT '					* Detected - cluster node 4 --> '+@NodeName4
END 

SELECT net_transport, auth_scheme INTO #KERBINFO FROM sys.dm_exec_connections WHERE session_id = @@spid
IF @@rowcount = 0 
	BEGIN 
		SET @KERB = 'Kerberos not used in TCP network transport'
	END
	ELSE
	BEGIN
		SET @KERB = 'TCP is using Kerberos'
	END
PRINT '					* Detected - Kerberos --> '+@KERB

IF (SELECT CONVERT(char(30), SERVERPROPERTY('ISIntegratedSecurityOnly'))) = 1
	SET @ISIntegratedSecurityOnly = 'Windows Authentication Security Mode'
ELSE
	SET @ISIntegratedSecurityOnly = 'SQL Authentication and Windows Authentication Mode '
PRINT '					* Detected - Security Mode --> '+@ISIntegratedSecurityOnly 

EXEC MASTER.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', 
			N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', @AuditLevel OUTPUT

SELECT @AuditLvltxt = CASE 
		WHEN @AuditLevel = 0	THEN 'None'
		WHEN @AuditLevel = 1	THEN 'Successful logins only'
		WHEN @AuditLevel = 2	THEN 'Failed logins only'
		WHEN @AuditLevel = 3	THEN 'Both successful and failed logins'
		ELSE 'Unknown'
		END
PRINT '					* Detected - Audit Level --> ' + @AuditLvltxt

IF (SELECT CONVERT(char(30), SERVERPROPERTY('ISSingleUser'))) = 1
	SET @ISSingleUser = 'Single User'
ELSE
	SET @ISSingleUser = 'Multi User'
PRINT '					* Detected - User Mode --> '+@ISSingleUser 

SET @FileStreams = CONVERT(NVARCHAR(10), (SELECT VALUE FROM SYS.CONFIGURATIONS where Name like 'filestream access%'))
IF (SELECT @FileStreams) = 1
	PRINT '					* Detected - FileStreams --> Enabled'
ELSE
	PRINT '					* Detected - FileStreams --> Disabled'

SET @BackUpCompression = CONVERT(NVARCHAR(10), (SELECT VALUE FROM SYS.CONFIGURATIONS where Name like 'backup compression%'))
IF (SELECT @BackUpCompression) = 1
	PRINT '					* Detected - Backup Compression --> Enabled'
ELSE
	PRINT '					* Detected - Backup Compression --> Disabled'

SET @COLLATION = (SELECT CONVERT(char(30), SERVERPROPERTY('COLLATION')))
PRINT '					* Detected - Collation Type --> '+@COLLATION 

SET @ErrorLogLocation = (SELECT REPLACE(CAST(SERVERPROPERTY('ErrorLogFileName') AS VARCHAR(500)), 'ERRORLOG',''))
PRINT '					* Detected - SQL Server Errorlog Location --> ' +@ErrorLogLocation

SET @DefaultTraceEnabled = CONVERT(NVARCHAR(1), (SELECT VALUE FROM SYS.CONFIGURATIONS where Name like 'default trace%'))
IF (SELECT @DefaultTraceEnabled) = 1
	PRINT '					* Detected - Default Trace File --> Enabled'
ELSE
	PRINT '					* Detected - Default Trace File --> Disabled'

SET @TraceFileLocation = (SELECT REPLACE(CONVERT(VARCHAR(100),SERVERPROPERTY('ErrorLogFileName')), '\ERRORLOG','\log.trc'))
PRINT '					* Detected - SQL Server Default Trace Location --> ' +@TraceFileLocation

CREATE TABLE #TraceStats
(TraceFlag INT, [Status] INT, [Global] INT, [Session] INT);

INSERT INTO #TraceStats
EXEC ('DBCC TRACESTATUS WITH NO_INFOMSGS')

IF (SELECT COUNT(*) FROM #TraceStats) = 0
BEGIN
	PRINT '					* Detected - Trace Flags Setting -->  No Trace Flags settings detected'
END
ELSE
BEGIN
PRINT '					* Detected - Trace Flags Setting --> Trace Flags Detected'

DECLARE @TraceFlagValue NVARCHAR(10)
		,@TraceFlagStatus NVARCHAR(10)
		,@TraceFlagGlobal NVARCHAR(10)
		,@TraceFlagSession NVARCHAR(10)

	DECLARE TraceFlagSet CURSOR LOCAL FAST_FORWARD FOR (SELECT TraceFlag, [Status], [Global], [Session] FROM #TraceStats)

	OPEN TraceFlagSet
	FETCH NEXT FROM TraceFlagSet INTO @TraceFlagValue, @TraceFlagStatus, @TraceFlagGlobal, @TraceFlagSession
		WHILE @@FETCH_STATUS = 0
		BEGIN
			IF @TraceFlagGlobal = 0 
				BEGIN
					SET @TraceFlagGlobal = 'No'
				END
				ELSE
					SET @TraceFlagGlobal = 'Yes'
			IF @TraceFlagSession = 0 
				BEGIN
					SET @TraceFlagSession = 'No'
				END
				ELSE 
					SET @TraceFlagSession = 'Yes'
			PRINT'								Using TraceFlag = ' +@TraceFlagValue
			PRINT'											Status = ' +@TraceFlagStatus
			PRINT'											Use Globally = '+@TraceFlagGlobal
			PRINT'											Used in Session = '+ @TraceFlagSession
			FETCH NEXT FROM TraceFlagSet INTO @TraceFlagValue, @TraceFlagStatus, @TraceFlagGlobal, @TraceFlagSession
		END

	CLOSE TraceFlagSet
	DEALLOCATE TraceFlagSet
		
END
SET @LinkServers = (SELECT COUNT(*) FROM sys.servers WHERE is_linked ='1')
PRINT '					* Detected - Number of Link Servers --> ' +@LinkServers

PRINT ' '
PRINT '					* Detected - SysAdmin Members'
IF (SELECT COUNT(*) FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1) = 0
BEGIN
	PRINT ' '
	PRINT '					** No Sysadmin Accounts Detected ** '
END

ELSE
BEGIN
	SELECT CONVERT (NVARCHAR(40), name) COLLATE DATABASE_DEFAULT as 'SysAdmin '
	into #SysAdminAccount FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1

	DECLARE @AdminAccounts VARCHAR(50)
		
	DECLARE SysAccounts CURSOR LOCAL FAST_FORWARD FOR  (SELECT SysAdmin from #SysAdminAccount)
	OPEN SysAccounts
	FETCH NEXT FROM SysAccounts INTO @AdminAccounts
		WHILE @@FETCH_STATUS = 0
		BEGIN
			PRINT'								 SysAdmin Account - ' +@AdminAccounts
			FETCH NEXT FROM SysAccounts INTO @AdminAccounts
		END

	CLOSE SysAccounts
	DEALLOCATE SysAccounts
END

PRINT ' '
PRINT '					* Detected - ServerAdmin Members'
IF (SELECT	COUNT(*)	FROM	sys.server_principals r
	JOIN sys.server_role_members m  ON	r.principal_id = m.role_principal_id
	JOIN sys.server_principals p ON	p.principal_id = m.member_principal_id
	WHERE	(r.type ='R')and(r.name='serveradmin')) < 1

BEGIN 
	PRINT '							** No ServerAdmin Accounts Detected ** '
END

ELSE
BEGIN
	SELECT	 CONVERT (NVARCHAR(50),p.name) as 'ServerAdmins' INTO #SrvAdmin
	FROM sys.server_principals r
	JOIN sys.server_role_members m  ON	r.principal_id = m.role_principal_id
	JOIN sys.server_principals p ON	p.principal_id = m.member_principal_id
	WHERE (r.type ='R') AND (r.name='serveradmin')

	DECLARE @SrvAdmins VARCHAR(50)

	DECLARE SrvAccounts CURSOR LOCAL FAST_FORWARD FOR (SELECT ServerAdmins FROM #SrvAdmin)
	OPEN SrvAccounts
	FETCH NEXT FROM SrvAccounts INTO @SrvAdmins
		WHILE @@FETCH_STATUS = 0
		BEGIN
			PRINT'								 Server Admin Account - ' +@SrvAdmins
			FETCH NEXT FROM SrvAccounts INTO @SrvAdmins
		END

	CLOSE SrvAccounts
	DEALLOCATE SrvAccounts
		
	END
PRINT ' '

/*-- The checks for the following setting are to ensure SQL Server is running without dangerous setting. These setting should only be done if recommend
	  by Microsoft support or recommend to correct a performance issue
	  	
		affinity64 mask
		affinity I/O mask
		affinity64 I/O mask
		lightweight pooling
		priority boost
		max worker threads
*/

    SELECT [name], [description], [value_in_use] INTO #SQL_Server_Settings	
	FROM master.sys.configurations		
	where [name] = 'affinity64 mask' -- performance
	OR [name] = 'affinity I/O mask' -- performance
	OR [name] = 'affinity64 I/O mask' -- performance
	OR [name] = 'lightweight pooling' -- performance
	OR [name] = 'priority boost' -- performance
	OR [name] = 'max worker threads' -- performance
	OR [name] = 'ad hoc distributed queries'-- audit
	OR [name] = 'clr enabled'  -- audit
	OR [name] = 'Cross db ownership chaining' -- audit
	OR [name] = 'Database Mail XPs' -- audit
	OR [name] = 'Ole Automation Procedures' -- audit
	OR [name] = 'Remote access' -- audit
	OR [name] = 'Scan for startup procs' -- audit
	OR [name] = 'xp_cmdshell' -- audit
PRINT '  '
PRINT '-------------------------------------- Automated Checks/Tests Analysis --------------------------------------------------------- '
PRINT' '

CREATE TABLE #TrustedDB
(name VARCHAR (50), DBTrusted VARCHAR(50));

INSERT INTO #TrustedDB
EXEC ('SELECT sys.server_principals.name as Owner, sys.databases.name FROM sys.databases 
LEFT OUTER JOIN sys.server_principals ON sys.databases.owner_sid = sys.server_principals.sid
WHERE is_trustworthy_on = 1')

IF (SELECT COUNT(*) FROM #TrustedDB) > 1
BEGIN
	PRINT '	* Detected setting for TRUSTWORTHY databases --> Security Audit FAILED/WARNING  --> Read Recommendations! ***'
	PRINT ''
	SELECT '	', DBTrusted AS 'TRUSTWORTHY Database Name', name as 'Database Owner' FROM #TrustedDB 
	PRINT ''
	PRINT '	Reason: With a database set to TRUSTWORTHY, it will allow a user(s) to impersonate server level permissions. This setting can have harmful potential.'
	PRINT '			Because of the potential to use instance level security from inside of the database extreme care should be taken when granting access to one'
	PRINT '			of these databases. With the right access a user in a trusted database can take over the instance.'
	PRINT ''
	PRINT '			* If you restore or attach a database this setting is automatically turned off.'
	PRINT '			* MSDB is the only database with TRUSTWORTHY automatically set on and is required by the system. Altering this setting from its default value'
	PRINT '			  can result in unexpected behavior by SQL Server components that use the MSDB database'
	PRINT ''
	PRINT '			Leave this setting set to OFF to mitigate certain threats that may be present when a database is attached to the server and the following'
	PRINT '			conditions are true: The database contains malicious assemblies that have an EXTERNAL_ACCESS or UNSAFE permission setting'
	PRINT ''
	PRINT '			For any TRUSTWORTHY database detected, carefully check the permissions of the database owner and those of the users of the database.'
	PRINT '			If the TRUSTWORTHY setting is set to ON, and if the owner of the database is a member of a group that has administrative credentials, such as'
	PRINT '			the sysadmin group, the database owner may be able to create and to run unsafe assemblies that can compromise the instance of SQL Server.'
	PRINT ''
	PRINT '			Best practices for database ownership and trust include the following:'
	PRINT '				* Have distinct owners for databases. Not all databases should be owned by the system administrator.'
	PRINT '				* Limit the number of owners for each database.' 
	PRINT '				* Confer trust selectively.' 
	PRINT '				* Leave the Cross-Database Ownership Chaining setting set to OFF unless multiple databases are deployed at a single unit.' 
	PRINT '				* Migrate usage to selective trust instead of using the TRUSTWORTHY property.' 
	PRINT ''
	PRINT '	References the following site: 	https://support.microsoft.com/en-us/kb/2183687 '
	PRINT ''
	INSERT INTO #SASATFailed SELECT 'TRUSTWORTHY Databases'
END
 
ELSE
IF (SELECT DBTrusted FROM #TrustedDB) = 'msdb' 
BEGIN
	SET @TestResultCounter = @TestResultCounter + 1
	PRINT '	* Detected setting for TRUSTWORTHY databases --> Possible Dangerous Setting - Only MSDB is set to TRUSTWORTHY - PASSED'
	PRINT '		NOTE: MSDB is the only database with TRUSTWORTHY automatically set on and is required by the system.'
	PRINT ''
END


DECLARE  @Valuedescript NVARCHAR(100), @ValueName2 NVARCHAR (100), @ValueInUse NVARCHAR (100)

DECLARE DangerousSettings 
CURSOR FOR SELECT  [description] ,[name] ,CONVERT(NVARCHAR (100),[value_in_use]) FROM #SQL_Server_Settings	

OPEN DangerousSettings 
	FETCH NEXT FROM DangerousSettings INTO @Valuedescript, @ValueName2,@ValueInUse
	WHILE @@FETCH_STATUS = 0
	BEGIN
	IF @ValueInUse = 0
		BEGIN
	PRINT '	* Detected setting for '''+ @ValueName2 +'''  =  '+ @ValueInUse + ' --> Possible Dangerous Setting - PASSED'
	SET @TestResultCounter = @TestResultCounter + 1
		END
	ELSE
	BEGIN
		PRINT '	* Detected setting for ''' + @Valuedescript +''' --> *** FAILED/WARNING. Possible Dangerous Setting --> Is set to '+@ValueInUse + ' ***'
	
	IF @ValueName2 = 'max worker threads' 
	BEGIN
		PRINT '  '
		PRINT '	Max Work Threads setting my cause blocking and thread pool issues/errors.'
		PRINT '  '
		PRINT '	When all worker threads are active with long running queries, SQL Server may appear unresponsive until' 
		PRINT '	a worker thread completes and becomes available. Though not a defect, this can sometimes be undesirable.'
		PRINT '	If a process appears to be unresponsive and no new queries can be processed, then connect to SQL Server'
		PRINT '	using the dedicated administrator connection (DAC), and kill the process.' 
		PRINT '  '
		PRINT '	** Only use if requested by Microsoft Support ** The default value for this option in sp_configure is 0.'
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Max Work Threads'
	END

	IF @ValueName2 = 'priority boost' 
	BEGIN
		PRINT '  '
		PRINT '"	Boost SQL Server priority" setting will drain OS and network functions and causes issues/errors.' 
		PRINT '  '
		PRINT '	Raising the priority too high may drain resources from essential operating system and network functions, '
		PRINT '	resulting in problems shutting down SQL Server or using other operating system tasks on the server. '
		PRINT '  '
		PRINT '	** Only use if requested by Microsoft Support ** The default value for this option in sp_configure is 0.'
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Priority Boost'
	END

	IF @ValueName2 = 'lightweight pooling' 
	BEGIN
		PRINT ' '
		PRINT '"	Use Windows fibers (lightweight pooling)". By setting lightweight pooling to 1 causes SQL Server to switch to fiber mode scheduling. '
		PRINT '  '
		PRINT '	Common language runtime (CLR) execution is not supported under lightweight pooling. Disable one of two options: "clr enabled" or "lightweight pooling". '
		PRINT '	Features that rely upon CLR and that do not work properly in fiber mode include the hierarchy data type, replication, and Policy-Based Management.'
		PRINT '	CLR, replication and extended stored procedures will fail and/or not work.'
		PRINT '  '
		PRINT '	** Only use if requested by Microsoft Support ** The default value for this option in sp_configure is 0.'
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Lightweight Pooling'
	END
	
	IF @ValueName2 like 'affinity%' 
	BEGIN
		PRINT ' '
		PRINT '	I/O and processor affinity changes will cause strange issues/errors and is not necessary on and 64 bit server.'
		PRINT '  '
		PRINT '	Do not configure CPU affinity in the Windows operating system and also configure the affinity mask in SQL Server.'
		PRINT '	These settings are attempting to achieve the same result, and if the configurations are inconsistent, you may have'
		PRINT '	unpredictable results. SQL Server CPU affinity is best configured using the sp_configure option in SQL Server.'
		PRINT '	Using the GUI, under server properties select the "Automatically set processor affinity mask for all processors" and'
		PRINT '	select the "Automatically set I/O affinity mask for all processors". This will correct the issues.'
		PRINT '  '
		PRINT '	** Only use if requested by Microsoft Support **The default value for this option in sp_configure is 0.'
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'I/O and Processor Affinity'
	END

	IF @ValueName2 = 'ad hoc distributed queries' 
	BEGIN
		PRINT ''
		PRINT '	Reason: Enabling the use of ad hoc names means that any authenticated login to SQL Server can access the provider.'
		PRINT '			SQL Server administrators should enable this feature for providers that are safe to be accessed by any local login.'
		PRINT '			By default, SQL Server does not allow ad hoc distributed queries using OPENROWSET and OPENDATASOURCE'
		PRINT ' '
		PRINT '	Recommended changes:  '
		PRINT '  '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''Ad Hoc Distributed Queries'', 0; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 0; '
		PRINT '				RECONFIGURE;'
		PRINT '				GO '
		PRINT ' '
		PRINT '  This change will take effect immediately.'
		PRINT ' '
		PRINT '	References the following site: 	https://msdn.microsoft.com/en-us/library/ms187569(v=sql.120).aspx '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Ad Hoc Distributed queries'
	END

	IF @ValueName2 = 'clr enabled' 
	BEGIN
		PRINT ''
		PRINT '	Reason: Enabling the use of CLR assemblies can increase SQL Server attack surface and puts it at risk from malicious assemblies. '
		PRINT '			Use the clr enabled option to specify whether user assemblies can be run by SQL Server '
		PRINT' '
		PRINT '	Recommended changes:  '
		PRINT ''
		PRINT '				EXECUTE sp_configure ''clr enabled'', 0; '
		PRINT '				GO '
		PRINT'				RECONFIGURE;'  
		PRINT '				GO '
		PRINT ''
		PRINT '	Both value columns must show 0. Default Value: 0 (disabled). This change will take effect immediately. '
		PRINT''
		PRINT '	References the following site: 	https://msdn.microsoft.com/en-us/library/ms175193(v=sql.120).aspx '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'CLR Enabled'
	END

	IF @ValueName2 = 'Cross db ownership chaining' 
	BEGIN
		PRINT ''
		PRINT '	This server option allows you to control cross-database ownership chaining at the database level or to allow '
		PRINT '	cross-database ownership chaining for all databases'
		PRINT' '
		PRINT '	Recommended changes: '
 		PRINT ''
		PRINT '				EXECUTE sp_configure ''Cross db ownership chaining'', 0; ;'
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT ''
		PRINT '	Both value columns must show 0. Default Value: 0 (disabled) '
		PRINT ''
		PRINT '	References the following site: 	https://msdn.microsoft.com/en-us/library/ms188694(v=sql.120).aspx'
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Cross DB Ownership Chaining'
	END
	
	IF @ValueName2 = 'Database Mail XPs' 
	BEGIN
		PRINT ''
		PRINT '	Reason: Disabling Database Mail reduces the SQL Server surface, eliminates a DOS attack vector and helps prevent '
		PRINT '			data to be sent to non-trusted parties. Allows the creation and sending of email messages from SQL Server'
		PRINT '			to anyone and anywhere. '
		PRINT' '
		PRINT '	Recommended changes: '
		PRINT '  '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''Database Mail XPs'', 0; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 0;'
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT ''
		PRINT '	Both value columns must show 0. Default Value: 0 (disabled). This change will take effect immediately. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Database Mail XPs'
	END

	IF @ValueName2 = 'Ole Automation Procedures' 
	BEGIN
		PRINT ' '
		PRINT '	Reason: Enabling this option increases the SQL Server attack surface and allows users to execute functions in the '
		PRINT '			security context. Use the Ole Automation Procedures option to specify whether OLE Automation objects can be '
		PRINT '			instantiated within Transact-SQL batches '
		PRINT' '
		PRINT '	Recommended changes: '
		PRINT '  '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''Ole Automation Procedures'', 0; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 0; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT ''
		PRINT '	Both value columns must show 0. Default Value: 0 (disabled). This change will take effect immediately. '
		PRINT ''
		PRINT '	References the following site: 	https://msdn.microsoft.com/en-us/library/ms191188(v=sql.120).aspx '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'OLE Automation Procedures'
	END

	IF @ValueName2 = 'Remote access'
	BEGIN
		PRINT ''
		PRINT '	Reason: Could be used to launch a Denial-of-Service (DoS) attack on remote server(s). Controls the execution'
		PRINT '			of stored procedures from local and / or remote servers on which instances of SQL Server are running.'
		PRINT' '
		PRINT '	Recommended changes: '
		PRINT '  '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''Remote access'', 0; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 0;  '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT ''
		PRINT '	Both value columns must show 0. Default Value: 0 (disabled). This change will require a restart to take effect.  '
		PRINT ''
		PRINT '	References the following site: http://msdn.microsoft.com/en-us/library/ms187660(v=sql.105).aspx '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Remote Access'
	END

	IF @ValueName2 = 'Scan for startup procs'
	BEGIN
		PRINT ''
		PRINT '	Reason: Reduces the risk auto execution of malicious code. Option allows SQL Server to'
		PRINT '			automatically execute stored procedure(s) on SQL Server services startup / restart'
		PRINT' '
		PRINT '	Recommended changes: '
		PRINT '  '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''Scan for startup procs'', 0; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 0;  '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT ''
		PRINT '	Both value columns must show 0. Default Value: 0 (disabled). This change will require a restart to take effect. '
		PRINT ''
		PRINT '	References the following site: 	http://msdn.microsoft.com/en-us/library/ms179460(v=sql.105).aspx '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Startup Procedures'
	END

	IF @ValueName2 = 'xp_cmdshell' 
	BEGIN
		PRINT ''
		PRINT '	Reason: xp_cmdshell is commonly used by attackers to read or write data to/from the underlying Operating System of'
		PRINT '			a database server. This option allows SQL Server user to execute commands in the operating system and returns '
		PRINT '			with the SQL client'
		PRINT' '
		PRINT '	Recommended changes: '
		PRINT '  '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''xp_cmdshell'', 0; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 0; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT ''
		PRINT '	Both value columns must show 0. Default Value: 0 (disabled). This change will take effect immediately. '
		PRINT ''
		PRINT '	References the following site: https://msdn.microsoft.com/en-us/library/ms175046(v=sql.110).aspx'
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_cmdshell Enabled'
	END
 END
PRINT  ' '
FETCH NEXT FROM DangerousSettings INTO @Valuedescript, @ValueName2,@ValueInUse
END

CLOSE DangerousSettings
DEALLOCATE DangerousSettings

IF ((SELECT [is_disabled] FROM sys.server_principals WHERE sid = 0x01) = 0)
	BEGIN
		PRINT '	* Detected setting for ''sa'' account  --> Security Audit FAILED.  --> *** FAILED/WARNING. Possible Dangerous Setting --> Is set to ENABLE ***'
		PRINT ''
		PRINT '	Reason: Disabling this account reduces the risk of an attacker executing a brute\force attacks against SQL Server.'
		PRINT '			The sa account is generally known and has high permissions like sysadmin. It is bad security practice for'
		PRINT '			applications and/or scripts connect with the sa account. If this has been done, however,  disabling the account '
		PRINT '			will prevent applications and/or scripts from functioning properly. In this case you must leave the account enable. '
		PRINT '			It is recommend that other audit tools should be used to trace the usage/use of the ''sa'' account'
		PRINT ''
		PRINT '	Recommend changes:  Execute the following query to disable the ''sa'' account'
		PRINT ''
		PRINT '				ALTER LOGIN sa DISABLE; '
		PRINT ''
		PRINT '	By default the ''sa'' login account is enabled. '
		PRINT ''
		PRINT '	References the following site: https://msdn.microsoft.com/en-us/library/ms188786(v=sql.110).aspx'
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'SA Account Enabled'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''sa'' account is DISABLED --> Possible Dangerous Setting - PASSED'
		PRINT ' '
		SET @TestResultCounter = @TestResultCounter + 1;
    END

SET @RemoteAdminConnections = CONVERT(NVARCHAR(10), (SELECT VALUE FROM SYS.CONFIGURATIONS where Name like 'Remote admin connections%'))
IF (SELECT @RemoteAdminConnections) = 1
	BEGIN
		PRINT '	* Detected setting for ''Remote Admin Connections'' = 1 --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''Remote Admin Connections'' = 0 --> Security Audit FAILED --> Change this setting back to default! ***'
		PRINT' '
		PRINT '	Reason: The Dedicated Admin Connection (DAC) is a feature that allows connections to have direct access to system ' 
		PRINT '			tables which could be used to conduct malicious activities. This feature must be restricted for only local '
		PRINT '			administrators to reduce the risk. '
		PRINT' '
		PRINT '	Recommended changes: '
		PRINT '  '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''Remote admin connections'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 0; ' 
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT ''
		PRINT '	Both value columns must show 1 on clustered installations. Default Value: 0 (disabled). This change will take effect immediately. '
		PRINT ''
		PRINT '	References the following site:  https://msdn.microsoft.com/en-us/library/ms190468(v=sql.120).aspx'
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Remote Admin Connections'
	END

SET @DefaultTraceEnabled = CONVERT(NVARCHAR(1), (SELECT VALUE FROM SYS.CONFIGURATIONS where Name like 'default trace%'))
IF (SELECT @DefaultTraceEnabled) = 1
	BEGIN
		PRINT '	* Detected setting for ''Default Trace File Enabled'' = 1 --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''Default Trace File Enabled'' = 0 --> Security Audit FAILED   Default Trace is set to 1  --> Change this setting back to default! ***'
		PRINT''
		PRINT'	Reason: Default trace allows for the collection of valuable audit information and security-related activities on the server.' 
		PRINT'			Default trace files provide audit logging of database activity including account activities, login privilege '
		PRINT'			elevation and execution of DBCC commands. '
		PRINT' '
		PRINT '	Recommended changes: '
		PRINT '  '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''Default trace enabled'', 1; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT '				EXECUTE sp_configure ''show advanced options'', 0; '
		PRINT '				GO '
		PRINT '				RECONFIGURE; '
		PRINT '				GO '
		PRINT'' 
		PRINT'	Both value columns must show 1.Default Value: 1 (on). This change will take effect immediately. '
		PRINT ''
		PRINT'	References the following site: https://msdn.microsoft.com/en-us/library/ms175513(v=sql.120).aspx '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Default Trace File Enabled'
	END

SET @TRANSPORT = (SELECT net_transport FROM sys.dm_exec_connections WHERE session_id = @@SPID)

IF (@TRANSPORT = 'Named pipe')
BEGIN
	PRINT '	* Detected setting for ''Default SQL Port Number'' --> Connection made with '+@TRANSPORT+'. Manually check default port number if TCP/IP is enable'
	PRINT''
END
ELSE
BEGIN  
	IF (@StaticPortNumber = '1433')
		BEGIN
			PRINT '	* Detected setting for ''Default SQL Port Number'' --> Security Audit FAILED. Default SQL Port Number is set to '+@StaticPortNumber + ' --> Change setting! ***'
			PRINT ' '
			PRINT '	Reason: Using a non-default port helps protect SQL Server from attacks directed to the default port. '
			PRINT '			Changing the default port will force DAC (Default Administrator Connection) to listen on a random port. Also, firewall'
			PRINT '			will require configuration changes. Default SQL Server instance are assigned port of TCP: 1433 for TCP/IP communication.'
			PRINT '			Since TCP: 1433 is a widely known for SQL Server port, the port number should be changed. '
			PRINT '			By default, SQL Server instances listen on TCP port 1433 and named instances uses dynamic ports.' 
			PRINT ''
			PRINT '	References the following site:  https://msdn.microsoft.com/en-us/library/ms177440(v=sql.120).aspx'
			PRINT ''
			INSERT INTO #SASATFailed SELECT 'Default Port Number'
		END
	ELSE
	BEGIN
			PRINT '	* Detected setting for ''Default SQL Port Number'' --> '+@StaticPortNumber +' --> Security Audit PASSED'
			PRINT ' '
			SET @TestResultCounter = @TestResultCounter + 1
	END
END

SET @xp_dirtreeEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_dirtree') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_dirtreeEnabled  = 'PUBLIC'
	BEGIN
		PRINT '	* Detected setting for ''xp_dirtree''  --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT '	Reason: Ensuring this procedure is disabled will prevent an attacker from performing directory enumeration and'
		PRINT '			listing files and folders to read or write data to / from. This procedure is currently leveraged by '
		PRINT '			several automated SQL Injection tools. 	Any record returned is an indicator that the public role '
		PRINT '			maintains execute permission on the procedure. Results returns a set of the directory tree for '
		PRINT '			a given directory path. '
		PRINT' '
		PRINT '	Recommended changes: '
		PRINT '  '
		PRINT '	The following steps can be performed using SQL Server Management Studio: '
		PRINT '  '
		PRINT '  			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT '  			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT '  			Procedures\System Extended Stored Procedures '
		PRINT ' '			
		PRINT '  			2.	Locate xp_dirtree, right click and select Properties '
		PRINT ' '			
		PRINT '  			3.	Select the Permissions tab '
		PRINT ' '			
		PRINT '  			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the '
		PRINT '  			recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT ' '			
		PRINT ' 			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT ' '		
		PRINT ' 			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute permission'
		PRINT ' 			on the procedure and the listed remediation procedure should be followed. '
		PRINT' '
		PRINT' 	Or you can execute the following to revoke use by all general users on the SQL Server machine: '
		PRINT '  '
		PRINT '				REVOKE EXECUTE ON xp_dirtree TO PUBLIC;'
		PRINT '  '
		PRINT '	Note: Server logins within the sysadmin role will retain use of this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_dirtree Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_dirtree'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_fixeddrivesEnabled =(select  'PUBLIC'  from sys.database_permissions where major_id = 
OBJECT_ID('xp_fixeddrives') AND [type] = 'EX' AND grantee_principal_id = 0);

IF @xp_fixeddrivesEnabled = 'PUBLIC'
	BEGIN
		PRINT '	* Detected setting for ''xp_fixeddrives'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT '	Reason: When disabled, will prevent an attacker from viewing local available drives for '
		PRINT '			directory and / or file enumeration. Any record returned indicates the public role maintains '
		PRINT '			execute permission on the procedure. A list of all hard drives on the machine and the space' 
		PRINT '			free in megabytes for each drive are shown. '
		PRINT' '
		PRINT' 	Recommended changes: Revoke use by all general users on the SQL Server machine:'
		PRINT ' '
		PRINT '				REVOKE EXECUTE ON xp_fixeddrives TO PUBLIC;  '
		PRINT ' '
		PRINT '	Note: Server logins within the sysadmin role will retain use of this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_fixdrdrives Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_fixeddrives'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_enumgroupsEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_enumgroups') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_enumgroupsEnabled  = 'PUBLIC'
	BEGIN
		PRINT '	* Detected setting for ''xp_enumgroups'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT '	Reason: Disabling this procedure will limit the ability to view Windows groups present on the'
		PRINT '			SQL Server machine. Currently being used by automated SQL Injection tools. '
		PRINT '			Any record returned indicates the public role maintains execute permission on the procedure.'
		PRINT '			This procedure can provide a list of local Microsoft Windows groups and / or a list of global groups'
		PRINT '			that are defined in a specified Windows machine. '
		PRINT' '
		PRINT ' 			The following steps can be performed by using SQL Server Management Studio: '
		PRINT ' '
		PRINT ' 			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT ' 			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT ' 			Procedures\System Extended Stored Procedures '
		PRINT ' '			
		PRINT ' 			2.	Locate xp_enumgroups, right click and select Properties '
		PRINT ' '			
		PRINT ' 			3.	Select the Permissions tab '
		PRINT ' '			
		PRINT ' 			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the '
		PRINT ' 			recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT ' '			
		PRINT ' 			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT ' '			
		PRINT ' 			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute permission on the '
		PRINT ' 			procedure and the listed remediation procedure should be followed. '
		PRINT' '
		PRINT '	Recommended changes: Revoke use by all general users on the SQL Server machine: '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_enumgroups Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_enumgroups'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_servicecontrolEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_servicecontrol') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_servicecontrolEnabled  = 'PUBLIC'
	BEGIN
		PRINT '	* Detected setting for ''xp_servicecontrol'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT'	Reason: Can be used remotely by an attacker to shutdown Windows services used by Antivirus products and / or firewalls'
		PRINT'			Any record returned indicates the public role maintains execute permission on the procedure.'
		PRINT'			Can be used to start and / or stop windows services and SQL related services running on the SQL Server machine. '
		PRINT ' '		
		PRINT ' 			The following steps can be used by using SQL Server Management Studio: '
		PRINT ' '
		PRINT ' 			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT ' 			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT ' 			Procedures\System Extended Stored Procedures '
		PRINT ' '		
		PRINT ' 			2.	Locate xp_servicecontrol, right click and select Properties '
		PRINT ' '			
		PRINT ' 			3.	Select the Permissions tab '
		PRINT ' '			
		PRINT ' 			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the recommendation and '
		PRINT ' 			you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT ' '			
		PRINT ' 			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT '' 			
		PRINT ' 			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute permission on the procedure'
		PRINT ' 			and the listed remediation procedure should be followed.' 
		PRINT' '
		PRINT'	Recommended changes: '
		PRINT '  '
		PRINT '				REVOKE EXECUTE ON xp_servicecontrol TO PUBLIC;  '
		PRINT '  '
		PRINT '	Note: Server logins within the sysadmin role will retain use of this procedure '
		PRINT'	By default, the public role is given execute permissions to this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_servicecontrol Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_servicecontrol'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_subdirsEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_subdirs') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_subdirsEnabled  = 'PUBLIC'
	BEGIN
		PRINT '	* Detected setting for ''xp_subdirs'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT'	Reason: Disable to prevent an attacker from performing directory enumeration, '
		PRINT'			listing all subdirectories on the file system. The attacker could use this information to '
		PRINT'			determine where key OS and SQL Server files are located. Shows all subdirectories'
		PRINT'			with in a given folder or path. '
		PRINT'			Any record returned indicates the public role maintains execute permission on the procedure.'
		PRINT''
		PRINT'			The following steps can be used by using SQL Server Management Studio: '
		PRINT''
		PRINT'			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT'			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT'			Procedures\System Extended Stored Procedures '
		PRINT''			
		PRINT'			2.	Locate xp_subdirs, right click and select Properties '
		PRINT''			
		PRINT'			3.	Select the Permissions tab '
		PRINT''			
		PRINT'			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the'
		PRINT'			 recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT''			
		PRINT'			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT''			
		PRINT'			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute permission on the '
		PRINT'			procedure and the listed remediation procedure should be followed. '
		PRINT' '
		PRINT'	Recommended changes: Revoke use by all general users on the SQL Server machine: '
		PRINT '  '
		PRINT '				REVOKE EXECUTE ON xp_subdirs TO PUBLIC;  '
		PRINT '  '
		PRINT '	Note: Server logins within the sysadmin role will retain use of this procedure. '
		PRINT'	By default, the public role is not given execute permissions to this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_subdirs Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT 	'	* Detected setting for ''xp_subdirs'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_regaddmultistringEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_regaddmultistring') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_regaddmultistringEnabled  = 'PUBLIC'
	BEGIN
		PRINT '	* Detected setting for ''xp_regaddmultistring'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT' '
		PRINT'	Reason: Disabling this feature will prevent a SQL Server users from writing to the Windows registry through SQL Server. '
		PRINT'			Any record returned indicates the public role maintains execute permission on the procedure. '
		PRINT'			Adds multiple strings to the server''s registry. '
		PRINT' '
		PRINT'			The following steps can be used with SQL Server Management Studio: '
		PRINT' '
		PRINT'			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT'			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT'			Procedures\System Extended Stored Procedures '
		PRINT' '			
		PRINT'			2.	Locate xp_regaddmdmultistring, right click and select Properties '
		PRINT' '			
		PRINT'			3.	Select the Permissions tab '
		PRINT' '			
		PRINT'			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the '
		PRINT'			recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT' '			
		PRINT'			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT' '			
		PRINT'			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute permission on the '
		PRINT'			procedure and the listed remediation procedure should be followed. '
		PRINT' '
		PRINT'	Recommended changes: Revoke the use by all general users on the SQL Server:' 
		PRINT''
		PRINT '				REVOKE EXECUTE ON xp_regaddmultistring TO PUBLIC;  '
		PRINT''
		PRINT '	Note: Logins within the sysadmin role will retain use of this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_regaddmultistring Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_regaddmultistring'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_regdeletekeyEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_regdeletekey') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_regdeletekeyEnabled  = 'PUBLIC'
	BEGIN
		PRINT '	* Detected setting for ''xp_regdeletekey'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT'	Reason: Disabling this feature will prevent a SQL Server users from deleting values from the Windows registry through SQL Server. '
		PRINT'			Any record returned indicates the public role maintains execute permission on the procedure. '
		PRINT'			Ability to delete registry keys from the server''s registry.'
		PRINT' '
		PRINT'		The following steps can be used with SQL Server Management Studio: '
		PRINT' '
		PRINT' 			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT' 			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT' 			Procedures\System Extended Stored Procedures '
		PRINT' '		
		PRINT' 			2.	Locate xp_regdeletekey, right click and select Properties '
		PRINT' '		
		PRINT' 			3.	Select the Permissions tab '
		PRINT' '		
		PRINT' 			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the  '
		PRINT' 			recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT' '		
		PRINT' 			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT' '		
		PRINT' 			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute permission'
		PRINT' 			on the procedure and the listed remediation procedure should be followed. '
		PRINT' '
		PRINT'	Recommended changes: Revoke use by all general users on the SQL Server machine: '
		PRINT '  '
		PRINT '				REVOKE EXECUTE ON xp_regdeletekey TO PUBLIC; '
		PRINT '  '
		PRINT '	Note: Logins within the sysadmin role will retain use of this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_regdeletekey Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_regdeletekey'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_regdeletevalueEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_regdeletevalue') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_regdeletevalueEnabled  = 'PUBLIC'
	BEGIN
		PRINT '	* Detected setting for ''xp_regdeletevalue'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT'	Reason: Disabling this feature will prevent a SQL Server users from deleting values from the Windows registry through SQL Server. '
		PRINT'			Any record returned indicates the public role maintains execute permission on the procedure '
		PRINT'			Deletes values from the server''s registry.'
		PRINT''
		PRINT'			The following steps can be used with SQL Server Management Studio: '
		PRINT' '
		PRINT' 			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT'			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT'			Procedures\System Extended Stored Procedures '
		PRINT' '			
		PRINT'			2.	Locate xp_regdeletevalue, right click and select Properties '
		PRINT' '			
		PRINT'			3.	Select the Permissions tab '
		PRINT' '			
		PRINT'			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the'
		PRINT'			recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5' 
		PRINT' '			
		PRINT'			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT' '			
		PRINT'			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute permission '
		PRINT'			on the procedure and the listed remediation procedure should be followed. '
		PRINT' '
		PRINT'	Recommended changes: Revoke the use by all general users on the SQL Server machine:  '
		PRINT '  '
		PRINT ' 				REVOKE EXECUTE ON xp_regdeletevalue TO PUBLIC;  '
		PRINT '  '
		PRINT '	Note: Logins within the sysadmin role will retain use of this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_regdeletevalue Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_regdeletevalue'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_regenumvaluesEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_regenumvalues') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_regenumvaluesEnabled  = 'PUBLIC'	
	BEGIN
		PRINT '	* Detected setting for ''xp_regenumvalues'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT'	Reason: Disabling this feature will prevent a SQL Server user from enumerating and reading registry values. '
		PRINT'			Any record returned indicates the public role maintains execute permission on the procedure. '
		PRINT'			Enumerates and reads registry values from a provided registry path. '
		PRINT''
		PRINT'			The following steps can be used with SQL Server Management Studio: '
		PRINT' '
		PRINT'			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT'			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT'			Procedures\System Extended Stored Procedures '
		PRINT' '			
		PRINT'			2.	Locate xp_regenumvalues, right click and select Properties '
		PRINT' '			
		PRINT'			3.	Select the Permissions tab '
		PRINT' '			
		PRINT'			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the '
		PRINT'			recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT' '			
		PRINT'			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT' '			
		PRINT'			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute permission' 
		PRINT'			   on the procedure and the listed remediation procedure should be followed. '
		PRINT' '
		PRINT'	Recommended changes: Revoke use by all general users on the SQL Server machine: '
		PRINT''
		PRINT'				REVOKE EXECUTE ON xp_regenumvalues TO PUBLIC; '
		PRINT''
		PRINT'	Note: Logins within the sysadmin role will retain use of this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_regenumvalues Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_regenumvalues'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_regremovemultistringEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_regremovemultistring') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_regremovemultistringEnabled  = 'PUBLIC'	
	BEGIN
		PRINT '	* Detected setting for ''xp_regremovemultistring'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT''
		PRINT'	Reason: Disabling will prevent a SQL Server users from deleting batch values from the Windows registry via SQL Server. '
		PRINT'			Any record returned indicates the public role maintains execute permission on the procedure. '
		PRINT'			Removes multiple strings from the server''s registry. '
		PRINT ''
		PRINT'			The following steps can be used with SQL Server Management Studio: '
		PRINT ''		
		PRINT '			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT '			Databases\System Databases\master\Programmability\Extended Stored Procedures'
		PRINT '			\System Extended Stored Procedures '
		PRINT ''			
		PRINT '			2.	Locate xp_regremovemultistring, right click and select Properties '
		PRINT ''			
		PRINT '			3.	Select the Permissions tab '
		PRINT ''			
		PRINT '			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the '
		PRINT '			recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT ''			
		PRINT '			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT ''			
		PRINT '			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute permission '
		PRINT '			on the procedure and the listed remediation procedure should be followed. '
		PRINT''
		PRINT'	Recommended changes: Revoke the use by all general users on the SQL Server '
		PRINT''
		PRINT'				REVOKE EXECUTE ON xp_regremovemultistring TO PUBLIC;  '
		PRINT''
		PRINT'	Note: Server logins within the sysadmin role will retain use of this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_regremovemultistring Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_regremovemultistring'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_regwriteEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_regwrite') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_regwriteEnabled  = 'PUBLIC'	
	BEGIN
		PRINT '	* Detected setting for ''xp_regwrite'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT'	Reason: Disabling will prevent a SQL Server users from writing to the Windows registry via SQL Server. '
		PRINT'			Any record returned indicates the public role maintains execute permission on the procedure. '
		PRINT'			Description: Writes key values to the server''s registry. '
		PRINT ''
		PRINT'	The following steps can be used with SQL Server Management Studio: '
		PRINT ''
		PRINT '			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT '			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT '			Procedures\System Extended Stored Procedures '
		PRINT ''			
		PRINT '			2.	Locate xp_regwrite, right click and select Properties '
		PRINT ''			
		PRINT '			3.	Select the Permissions tab '
		PRINT ''			
		PRINT '			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with '
		PRINT '			the recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT ''			
		PRINT '			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT ''			
		PRINT '			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute '
		PRINT '			permission on the procedure and the listed remediation procedure should be followed. '
		PRINT''
		PRINT'	Recommended changes: Revoke use by all general users on the SQL Server machine: '
		PRINT''
		PRINT'				REVOKE EXECUTE ON xp_regwrite TO PUBLIC;  '
		PRINT''
		PRINT'	Note: Server logins within the sysadmin role will retain use of this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_regwrite Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_regwrite'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SET @xp_regreadEnabled = (select 'PUBLIC' from sys.database_permissions 
		where major_id = OBJECT_ID('xp_regread') AND [type] = 'EX' AND grantee_principal_id = 0 );

IF @xp_regreadEnabled  = 'PUBLIC'	
	BEGIN
		PRINT '	* Detected setting for ''xp_regread'' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT'	Reason: Disabling this feature will prevent a SQL Server users from enumerating'
		PRINT'			and reading registry values. This procedure is used by several automated SQL injection tools. '
		PRINT'			Any record returned indicates the public role maintains execute permission on the procedure. '
		PRINT'			Description: Reads key values from the server''s registry. '
		PRINT ' '
		PRINT'	The following steps can be used with SQL Server Management Studio: '
		PRINT ' '
		PRINT '			1.	In Object Explorer, navigate to the SQL Server instance and expand the path: '
		PRINT ' '
		PRINT '			Databases\System Databases\master\Programmability\Extended Stored '
		PRINT '			Procedures\System Extended Stored Procedures '
		PRINT ' '		
		PRINT '			2.	Locate xp_regread, right click and select Properties '
		PRINT ' '			
		PRINT '			3.	Select the Permissions tab '
		PRINT ' '			
		PRINT '			4.	If the ''public'' entry does not exist within the Users or Roles listing the server is in compliance with the '
		PRINT '			recommendation and you can halt further steps. If the ''public'' entry does exist proceed to step 5 '
		PRINT ' '			
		PRINT '			5.	Select the ''public'' entry within the Users or Roles listing '
		PRINT ' '			
		PRINT '			6.	If the Grant check box for the Execute permission is checked the Public role maintains Execute'
		PRINT '			permission on the procedure and the listed remediation procedure should be followed. '
		PRINT''
		PRINT'	Recommended changes: Revoke the use by all general users on the SQL Server: '
		PRINT''
		PRINT'				REVOKE EXECUTE ON xp_regread TO PUBLIC;  '
		PRINT''
		PRINT'	Note: Logins within the sysadmin role will retain use of this procedure. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'XP_regread Enabled for PUBLIC'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''xp_regwrite'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
		PRINT' '
	END

SELECT @AuditLvltxt = CASE 
	WHEN @AuditLevel = 0	THEN 'None'
	WHEN @AuditLevel = 1	THEN 'Successful logins only'
	WHEN @AuditLevel = 2	THEN 'Failed logins only'
	WHEN @AuditLevel = 3	THEN 'Both successful and failed logins'
	ELSE 'Unknown'
	END

IF @AuditLevel  <> 3
	BEGIN
		PRINT '	* Detected setting for ''Audit Level'' is set to: ' +@AuditLvltxt+ ' --> Security Audit FAILED  --> Apply Recommended changes! ***'
		PRINT' '
		PRINT '	Reason: Logging successful and failed logins provides key information that can be used to detect\confirm password '
		PRINT '			guessing attacks. Further, logging successful login attempts can be used to confirm server access during forensic ' 
		PRINT '			investigations. Set logs both successful and failed login SQL Server authentication attempts. '
		PRINT' '
		PRINT '	Recommended changes: Perform the following steps to change the audit level:'
		PRINT ''
		PRINT' 			1.	Open SQL Server Management Studio. '
		PRINT' 			2.	Right click the target instance and select Properties and navigate to the Security tab. '
		PRINT' 			3.	Select the option Both failed and successful logins under the "Login Auditing" section and click OK. '
		PRINT' 			4.	Restart the SQL Server instance.'  
		PRINT' '	
		PRINT'	By default, only failed login attempted are captured. '
		PRINT' '
		PRINT'	References: '
		PRINT'				1.	http://technet.microsoft.com/en-us/library/ms188470(v=sql.105).aspx '
		PRINT'				2.	http://technet.microsoft.com/en-us/library/ms188470(v=sql.100).aspx '
		PRINT''
		PRINT '	Note: A value of ''all''  indicates a server login auditing setting of ''Both failed and successful logins''. '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Audit Level Logging'
	END
ELSE
	BEGIN
		PRINT '	* Detected setting for ''Audit Level'' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1
	END

IF (SELECT CONVERT(char(30), SERVERPROPERTY('ISIntegratedSecurityOnly'))) = 0
	BEGIN
		SET @ISIntegratedSecurityOnly = 'SQL Authentication and Windows Authentication Mode '
		PRINT ' '
		PRINT '	* Detected setting for ''Server Authentication'' is set to '+@ISIntegratedSecurityOnly+'  --> Security Audit FAILED --> Apply Recommended changes! ***'
		PRINT ''
		PRINT '	Reason: Windows provides a better authentication mechanism than SQL Server authentication. '
		PRINT '			A config value of Windows NT Authentication indicates the Server Authentication property is set to '
		PRINT '			Windows Authentication mode. Use Windows Authentication to validate connections. '
		PRINT ' '
		PRINT '	Recommended changes: '
		PRINT ' '
		PRINT ' 	Perform the following steps: '
		PRINT ' 			1.	Open SQL Server Management Studio. '
		PRINT ' 			2.	Open the Object Explorer tab and connect to the target database instance. '
		PRINT ' 			3.	Right click the instance name and select Properties. '
		PRINT ' 			4.	Select the Security page from the left menu. '
		PRINT ' 			5.	Set the Server authentication setting to Windows Authentication mode. '
		PRINT ' '	
		PRINT '	Default Value: Windows Authentication Mode '
		PRINT ' '	
		PRINT '	References: '
		PRINT '				1.	http://msdn.microsoft.com/en-us/library/ms188470(v=sql.100).aspx '
		PRINT '				2.	http://msdn.microsoft.com/en-us/library/ms188470(v=sql.105).aspx '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Authentication Mode'
    END
ELSE
	BEGIN
		SET @ISIntegratedSecurityOnly = 'Windows Authentication Security Mode'
		PRINT ' '
		PRINT '	* Detected setting for ''Server Authentication'' is set to '+@ISIntegratedSecurityOnly+' --> Security Audit PASSED'
		SET @TestResultCounter = @TestResultCounter + 1;
    END
---------------------------------------------------------------------------------------------------------------------------------------------
PRINT ' '	
IF @InstanceName <>  'Default Instance'
	BEGIN 
		PRINT ' '	
		PRINT '------------------ SQL Server Instance * Detected - Manual Analysis Required --------------------------------------------- '
		PRINT ' '
		PRINT '		Set the ''Hide Instance'' option to ''Yes'' for Production SQL Server instances'
		PRINT' '
		PRINT'		The following steps can be performed with SQL Server Configuration Manager: '
		PRINT' '
		PRINT ' 			1.	In SQL Server Configuration Manager, expand SQL Server Network Configuration, '
		PRINT ' 			right-click Protocols for <server instance>, and then select Properties. '
		PRINT' '
		PRINT ' 			2.	On the Flags tab, in the Hide Instance box, select Yes, and then click OK to close the dialog box. '
		PRINT ' 			The change takes effect	 immediately for new connections. '
		PRINT' '
		PRINT '		Recommended changes: '
		PRINT ' 			1.	In SQL Server Configuration Manager, expand SQL Server Network Configuration, right-click'
		PRINT ' 			Protocols for <server instance>,  and then select Properties. '
		PRINT' '
		PRINT ' 			2.	On the Flags tab, in the Hide Instance box, select Yes, and then click OK to close the dialog box.'
		PRINT ' 			The change takes effect immediately for new connections. '
		PRINT ''
		PRINT '		SQL Server instances are show and not hidden by default. '
		PRINT ''
		PRINT '		References the following site: 	https://msdn.microsoft.com/en-us/library/ms179327(v=sql.120).aspx '
		PRINT ''
		INSERT INTO #SASATFailed SELECT 'Hide Instance Name'
	END

PRINT'------------------------------------ Automated Check/Test Summary Report -------------------------------------------------------'
PRINT ''
SET @ResultsPercentage = (@TestResultCounter / @TotalAutomatedTests)*100
PRINT '	Total number of automated checks/tests that have passed is '+(CONVERT(varchar(4),@TestResultCounter)) +' out of '+(CONVERT(varchar(4),@TotalAutomatedTests))+' checks/tests. Success rate of '+ (CONVERT(varchar(4),@ResultsPercentage))+'%'
PRINT ''
PRINT '							Summary of sections that have been marked as Failed/Warning'
PRINT ''
DECLARE @FailedName NVARCHAR(50)
DECLARE AuditRpt CURSOR LOCAL FAST_FORWARD FOR (SELECT AuditName FROM #SASATFailed)
OPEN AuditRpt
FETCH NEXT FROM AuditRpt INTO @FailedName
	WHILE @@FETCH_STATUS = 0
	BEGIN
		PRINT'										Area for review: - '+ @FailedName
		FETCH NEXT FROM AuditRpt INTO @FailedName
	END

CLOSE AuditRpt
DEALLOCATE AuditRpt
PRINT ''
PRINT'-------------------------------------------- End of SASAT Report ---------------------------------------------------------------'
PRINT ''

-- Performing clean up

IF OBJECT_ID('tempdb..#TrustedDB') IS NOT NULL
BEGIN
DROP TABLE #TrustedDB
END

IF OBJECT_ID('tempdb..#nodes') IS NOT NULL
BEGIN
DROP TABLE #nodes
END

IF OBJECT_ID('tempdb..#KERBINFO') IS NOT NULL
BEGIN
DROP TABLE #KERBINFO
END

IF OBJECT_ID('tempdb..#SysAdminAccount') IS NOT NULL
BEGIN
DROP TABLE #SysAdminAccount
END

IF OBJECT_ID('tempdb..#SrvAdmin') IS NOT NULL
BEGIN
DROP TABLE #SrvAdmin
END

IF OBJECT_ID('tempdb..#SQL_Server_Settings') IS NOT NULL
BEGIN
DROP TABLE #SQL_Server_Settings
END

IF OBJECT_ID('tempdb..#TraceStats') IS NOT NULL
BEGIN
DROP TABLE #TraceStats
END

IF OBJECT_ID('tempdb..#SASATFailed') IS NOT NULL
BEGIN
DROP TABLE #SASATFailed
END

GO

-- -- Un remark the following lines if you would like to show all config setting 
--PRINT ''
--PRINT '						SQL Server Configuration Settings for this server as per SP_CONFIGURE'
--PRINT ''
--PRINT ' 			When making changes to SQL Server configurations, some changes are immediate and some require a restart'
--PRINT ' 			of the SQL related services. Below shows current configurations and when the change(s) take effect.'
--PRINT ''
--SELECT Name as 'Configuration Name'
--, CONVERT (NVARCHAR(6),[VALUE]) as 'Configured Value'
--, CONVERT (NVARCHAR(6),[VALUE_IN_USE]) as 'Value in Used'
--, CASE (CONVERT (NVARCHAR(15),[is_dynamic]))
--	WHEN 0 THEN CAST('Service Restart Needed' as VARCHAR(25))
--	WHEN 1 THEN CAST('Change is Immediate' as VARCHAR(25))
--END  as '    Change Effect' 
--, CONVERT (NVARCHAR(80),[Description]) as 'Description'
--FROM SYS.CONFIGURATIONS
--GO

