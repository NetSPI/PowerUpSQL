-- Script: Get-TempTableColumns.sql
-- Author: Scott Sutherland
-- Description: Return a list of all temp table types.
-- Include table variables, local temp tables, and global temp tables.

SELECT 'tempdb' as 'Database_Name',
    SCHEMA_NAME(t1.schema_id) AS 'Schema_Name',
    t1.name AS 'Table_Name',
    t2.name AS 'Column_Name',
    t3.name AS 'Column_Type',
    CASE
        WHEN (SELECT CASE WHEN LEN(t1.name) - LEN(REPLACE(t1.name,'#','')) > 1 THEN 1 ELSE 0 END) = 1 THEN 'GlobalTempTable'
        WHEN t1.name LIKE '%[_]%' AND (SELECT CASE WHEN LEN(t1.name) - LEN(REPLACE(t1.name,'#','')) = 1 THEN 1 ELSE 0 END) = 1 THEN 'LocalTempTable'
        WHEN t1.name NOT LIKE '%[_]%' AND (SELECT CASE WHEN LEN(t1.name) - LEN(REPLACE(t1.name,'#','')) = 1 THEN 1 ELSE 0 END) = 1 THEN 'TableVariable'
        ELSE NULL
    END AS Table_Type,
    t1.is_ms_shipped,
    t1.is_published,
    t1.is_schema_published,
    t1.create_date,
    t1.modify_date
FROM [tempdb].[sys].[objects] AS t1
JOIN [tempdb].[sys].[columns] AS t2 ON t1.OBJECT_ID = t2.OBJECT_ID
JOIN sys.types AS t3 ON t2.system_type_id = t3.system_type_id
WHERE t1.name LIKE '#%'
