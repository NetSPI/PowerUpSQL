-- Script: Get-Database.sql
-- Description: This will return viewable databases and some associated meta data.
--	Filename may not be returned if the current user is not a sysadmin.
--	If the "VIEW ANY DATABASE" privilege has been revoked from Public
--	then some databases may not be listed if the current user is not a sysadmin.
-- Reference: https://msdn.microsoft.com/en-us/library/ms178534.aspx
-- fix is_encrypted column - should only show on newer versions

SELECT a.database_id as [dbid],
	a.name,
	HAS_DBACCESS(a.name) as [has_dbaccess],
	SUSER_SNAME(a.owner_sid) as [db_owner],
	a.is_trustworthy_on,
	a.is_db_chaining_on,
	a.is_broker_enabled,
	a.is_encrypted,
	a.is_read_only,
	a.create_date,
	a.recovery_model_desc,
	b.filename 
FROM [sys].[databases] a
INNER JOIN [sys].[sysdatabases] b
	ON a.database_id = b.dbid
ORDER BY a.database_id