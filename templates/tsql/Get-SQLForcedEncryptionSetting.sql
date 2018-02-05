-- Script: Get-SQLForcedEncryptionSetting.sql
-- Description: Get the "Forced Encryption" setting for the current SQL Server instance
-- Author: Scott Sutherland, NetSPI 2018

DECLARE @ForcedEncryption INT
EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
N'ForceEncryption', @ForcedEncryption OUTPUT

SELECT @ForcedEncryption as ForcedEncryption
