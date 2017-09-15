/*
  Script: Get-SQLStoredProcedureXP.sql
  Description: This will list the custom exteneded stored procedures for the current database.
  Author: Scott Sutherland, 2017
*/

SELECT * FROM sys.objects o 
INNER JOIN sys.syscomments s
ON o.object_id = s.id
WHERE o.type = 'x' 
