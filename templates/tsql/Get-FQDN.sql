-- Requires sysadmin

DECLARE @Domain NVARCHAR(100)
EXEC master.dbo.xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\CurrentControlSet\services\Tcpip\Parameters', N'Domain',@Domain OUTPUT
SELECT Cast(SERVERPROPERTY('MachineName') as nvarchar) + '.' + @Domain AS FQDN
