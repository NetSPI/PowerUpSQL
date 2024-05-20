-- Script: Get-Table.sql
-- Description: Returns a list of tables for the current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms186224.aspx

SELECT TABLE_CATALOG AS [DATABASE_NAME],
	TABLE_SCHEMA AS [SCHEMA_NAME],
	TABLE_NAME,
	CASE
		WHEN (SELECT CASE WHEN LEN(TABLE_NAME) - LEN(REPLACE(TABLE_NAME,'#','')) > 1 THEN 1 ELSE 0 END) = 1 THEN 'GlobalTempTable'
                WHEN TABLE_NAME LIKE '%[_]%' AND (SELECT CASE WHEN LEN(TABLE_NAME) - LEN(REPLACE(TABLE_NAME,'#','')) = 1 THEN 1 ELSE 0 END) = 1 THEN 'LocalTempTable'
                WHEN TABLE_NAME NOT LIKE '%[_]%' AND (SELECT CASE WHEN LEN(TABLE_NAME) - LEN(REPLACE(TABLE_NAME,'#','')) = 1 THEN 1 ELSE 0 END) = 1 THEN 'TableVariable'
                ELSE  TABLE_TYPE
        END AS Table_Type
FROM [INFORMATION_SCHEMA].[TABLES]
