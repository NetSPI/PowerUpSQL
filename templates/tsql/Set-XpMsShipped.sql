-- This outlines how to set the "is_ms_shipped" flag to one for custom stored procedures in SQL Server.
-- Note: The following has to be executed as a sysadmin

-- Create stored procedure
CREATE PROCEDURE sp_example
AS
BEGIN
SELECT @@Version
END

-- Check properties of proc
SELECT name,is_ms_shipped FROM sys.procedures WHERE name = 'sp_example'

-- Flag the procedure as a system object via a DAC connection via
-- Reference for incline DAC connection: https://github.com/NetSPI/PowerUpSQL/blob/master/templates/tsql/Get-DACQuery.sql

-- Note: This changes the proc to a system object, but doesn't change from the dbo to sys schema.
-- Source: https://raresql.com/tag/sp_ms_marksystemobject/

exec sys.sp_ms_marksystemobject sp_example

-- Check properties of proc
SELECT name,is_ms_shipped FROM sys.procedures WHERE name = 'sp_example'

--Note: To remove the flag the procedures need to be dropped and recreated.
