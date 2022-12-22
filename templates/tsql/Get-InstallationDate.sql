-- requires sysadmin
-- works on 2022, 2016, but not on 2014
-- https://www.dbrnd.com/2016/03/sql-server-script-to-find-installation-date-time-and-authentication-mode/
SELECT 
	createdate AS InstallationDate 
	,CASE SERVERPROPERTY('IsIntegratedSecurityOnly')   
		WHEN 1 THEN 'Windows Authentication'  
		WHEN 0 THEN 'Windows and SQL Server Authentication'  
	END AS AuthenticationMode
	,SERVERPROPERTY('servername') AS ServerName
FROM master.sys.syslogins 
WHERE name LIKE 'NT AUTHORITY\SYSTEM'
