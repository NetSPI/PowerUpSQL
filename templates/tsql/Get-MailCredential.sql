-- Script: Get-MailCredential.sql
-- Requirements: Sysadmin or required SELECT privileges.
-- Description: Returns a row for SMTP credential.  Everything but the cleartext credential is shown.
-- Note: Tested on SQL Server 2008, 2012, 2014, 2016.

SELECT c.name as credential_name,  
c.credential_id,
ms.account_id,
ms.servertype,
ms.servername,
ms.port,
ms.username,
a.name,
a.display_name,
a.description,
a.email_address,
a.replyto_address,
ms.credential_id,
ms.use_default_credentials,
ms.enable_ssl,
ms.flags,
ms.last_mod_datetime,
ms.last_mod_user
FROM sys.credentials as c       
JOIN msdb.dbo.sysmail_server as ms        
ON c.credential_id = ms.credential_id   
JOIN msdb.dbo.sysmail_account as a
ON ms.account_id = a.account_id
WHERE ms.servertype like 'SMTP'
