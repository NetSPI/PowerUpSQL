-- Script: Get-ServerLink.sql
-- Decription: Return a list of SQL Server links and their properties.
-- Reference: https://msdn.microsoft.com/en-us/library/ms178530.aspx
-- Note: Use open query or four part names to query links

SELECT a.server_id,
	a.name AS [DATABASE_LINK_NAME],
	CASE a.Server_id 
		WHEN 0 
		THEN 'Current'
		ELSE 'Remote'
		END AS [DATABASE_LINK_LOCATION],
	a.product,
	a.provider,
	a.catalog,
	'Local Login ' = CASE b.uses_self_credential
		WHEN 1 THEN 'Uses Self Credentials'
		ELSE c.name
		END,
	b.remote_name AS [REMOTE LOGIN NAME],
	a.is_rpc_out_enabled,
	a.is_data_access_enabled,
	a.modify_date
FROM [sys].[Servers] a
LEFT JOIN [sys].[linked_logins] b
	ON a.server_id = b.server_id
LEFT JOIN [sys].[server_principals] c
	ON c.principal_id = b.local_principal_id

-- Alternative Options

sp_linkedservers
select * from master..sysservers
select * from master.dbo.sysservers
select * from master.sys.servers
select * from FROM master.sys.sysxsrvs -- This is a system base table and can only be accessed via a dedicated administrator connection (DAC) with a sysadmin login.










