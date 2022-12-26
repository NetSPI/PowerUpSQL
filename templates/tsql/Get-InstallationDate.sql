-- Option 1: createdat FROM master.sys.syslogins 
-- $server.VersionMajor -ge 9
-- works on 2022, 2016, but not on 2014
-- Reference: https://www.dbrnd.com/2016/03/sql-server-script-to-find-installation-date-time-and-authentication-mode/
SELECT 
	createdate AS InstallationDate 
	,CASE SERVERPROPERTY('IsIntegratedSecurityOnly')   
		WHEN 1 THEN 'Windows Authentication'  
		WHEN 0 THEN 'Windows and SQL Server Authentication'  
	END AS AuthenticationMode
	,SERVERPROPERTY('servername') AS ServerName
FROM master.sys.syslogins 
WHERE name LIKE 'NT AUTHORITY\SYSTEM'

-- Option 2: create_date FROM sys.server_principals
-- $server.VersionMajor -ge 9
-- Reference: https://github.com/dataplat/dbatools/blob/6cae0dd18bda3ad8efd60404c2d05b402cc4a785/functions/Get-DbaInstanceInstallDate.ps1
/*
$sql = "SELECT create_date FROM sys.server_principals WHERE sid = 0x010100000000000512000000"
[DbaDateTime]$sqlInstallDate = $server.Query($sql, 'master', $true).create_date
*/

-- Option 3: schemadate FROM sysservers
--$server.VersionMajor -le 9
--Reference: https://github.com/dataplat/dbatools/blob/6cae0dd18bda3ad8efd60404c2d05b402cc4a785/functions/Get-DbaInstanceInstallDate.ps1
/*
$sql = "SELECT schemadate FROM sysservers"
[DbaDateTime]$sqlInstallDate = $server.Query($sql, 'master', $true).schemadate
*/
