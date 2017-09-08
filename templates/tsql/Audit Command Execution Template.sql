/*
	Build Audit Policies to identify potential command execution
*/

-- Create and enable an audit
USE master 
CREATE SERVER AUDIT DerbyconAudit
TO APPLICATION_LOG 
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE) 
ALTER SERVER AUDIT DerbyconAudit
WITH (STATE = ON)

-- Server: Audit server configuration changes
CREATE SERVER AUDIT SPECIFICATION [Audit_Server_Configuration_Changes]
FOR SERVER AUDIT DerbyconAudit
ADD (AUDIT_CHANGE_GROUP), 		-- Audit Audit changes
ADD (SERVER_OPERATION_GROUP)  	-- Audit server changes
WITH (STATE = ON)

--  DATABASE: Audit common agent job activity
Use msdb
CREATE DATABASE AUDIT SPECIFICATION [Audit_Agent_Jobs]
FOR SERVER AUDIT [DerbyconAudit]
ADD (EXECUTE ON OBJECT::[dbo].[sp_delete_job] BY [dbo]),
ADD (EXECUTE ON OBJECT::[dbo].[sp_add_job] BY [dbo]),
ADD (EXECUTE ON OBJECT::[dbo].[sp_start_job] BY [dbo])
WITH (STATE = ON)

--  DATABASE: Audit potentially dangerous procedures
use master
CREATE DATABASE AUDIT SPECIFICATION [Audit_OSCMDEXEC]
FOR SERVER AUDIT [DerbyconAudit]
ADD (EXECUTE ON OBJECT::[dbo].[xp_cmdshell] BY [dbo]),					-- Audit xp_cmdshell execution
ADD (EXECUTE ON OBJECT::[dbo].[sp_addextendedproc] BY [dbo]),			-- Audit additional of custom extended stored procedures
ADD (EXECUTE ON OBJECT::[dbo].[sp_execute_external_script] BY [dbo]), 	-- Audit execution of external scripts such as R and Python
ADD (EXECUTE ON OBJECT::[dbo].[Sp_oacreate] BY [dbo])					-- Audit OLE Automation Procedure execution
WITH (STATE = ON)


/*
	View Audit Policies
*/

-- View audits
SELECT * FROM sys.dm_server_audit_status

-- View server specifications
SELECT audit_id, 
a.name as audit_name, 
s.name as server_specification_name, 
d.audit_action_name, 
s.is_state_enabled, 
d.is_group, 
d.audit_action_id, 
s.create_date, 
s.modify_date 
FROM sys.server_audits AS a 
JOIN sys.server_audit_specifications AS s 
ON a.audit_guid = s.audit_guid 
JOIN sys.server_audit_specification_details AS d 
ON s.server_specification_id = d.server_specification_id 

-- View database specifications
SELECT a.audit_id, 
a.name as audit_name, 
s.name as database_specification_name, 
d.audit_action_name, 
s.is_state_enabled, 
d.is_group, s.create_date, 
s.modify_date, 
d.audited_result 
FROM sys.server_audits AS a 
JOIN sys.database_audit_specifications AS s 
ON a.audit_guid = s.audit_guid 
JOIN sys.database_audit_specification_details AS d 
ON s.database_specification_id = d.database_specification_id 


/*
	Remove Audit Policies
*/

-- Remove Audit_Server_Configuration_Changes
use master
ALTER SERVER AUDIT SPECIFICATION [Audit_Server_Configuration_Changes]
WITH (STATE = OFF)
DROP SERVER AUDIT SPECIFICATION [Audit_Server_Configuration_Changes]

-- Remove Audit_OSCMDEXEC
USE master
ALTER DATABASE AUDIT SPECIFICATION [Audit_OSCMDEXEC]
WITH (STATE = OFF)
DROP DATABASE AUDIT SPECIFICATION [Audit_OSCMDEXEC]

-- Remove Audit_Agent_Jobs
USE msdb
ALTER DATABASE AUDIT SPECIFICATION [Audit_Agent_Jobs]
WITH (STATE = OFF)
DROP DATABASE AUDIT SPECIFICATION [Audit_Agent_Jobs]

-- Remove DerbyconAudit audit
ALTER SERVER AUDIT DerbyconAudit
WITH (STATE = OFF)
DROP SERVER AUDIT DerbyconAudit
