-- Script: Get-MailCredential.sql
-- Requirements: Sysadmin or required SELECT privileges.
-- Description: Returns a row for SMTP credential.  Everything but the cleartext credential is shown.
-- Reference: https://msdn.microsoft.com/en-us/library/ms187404.aspx

SELECT name,  
c.credential_id,
ms.account_id,
ms.servertype,
ms.servername,
ms.port,
ms.username,
ms.credential_id,
ms.use_default_credentials,
ms.enable_ssl,
ms.flags,
ms.timeout,
ms.last_mod_datetime,
ms.last_mod_user
FROM sys.credentials as c       
JOIN msdb.dbo.sysmail_server as ms        
ON c.credential_id = ms.credential_id     
WHERE ms.servertype like 'SMTP'
