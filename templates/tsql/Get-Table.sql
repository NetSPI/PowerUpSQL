-- Script: Get-Table.sql
-- Description: Returns a list of tables for the current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms186224.aspx

SELECT 
    @@SERVERNAME AS [INSTANCE_NAME],
    t.TABLE_CATALOG AS [DATABASE_NAME],
    t.TABLE_SCHEMA AS [SCHEMA_NAME],
    t.TABLE_NAME,
    CASE
        WHEN (SELECT CASE WHEN LEN(t.TABLE_NAME) - LEN(REPLACE(t.TABLE_NAME,'#','')) > 1 THEN 1 ELSE 0 END) = 1 THEN 'GlobalTempTable'
        WHEN t.TABLE_NAME LIKE '%[_]%' AND (SELECT CASE WHEN LEN(t.TABLE_NAME) - LEN(REPLACE(t.TABLE_NAME,'#','')) = 1 THEN 1 ELSE 0 END) = 1 THEN 'LocalTempTable'
        WHEN t.TABLE_NAME NOT LIKE '%[_]%' AND (SELECT CASE WHEN LEN(t.TABLE_NAME) - LEN(REPLACE(t.TABLE_NAME,'#','')) = 1 THEN 1 ELSE 0 END) = 1 THEN 'TableVariable'
        ELSE t.TABLE_TYPE
    END AS Table_Type,
    st.is_ms_shipped,
    st.is_published,
    st.is_schema_published,
    st.create_date,
    st.modify_date AS modified_date
FROM [INFORMATION_SCHEMA].[TABLES] t
JOIN sys.tables st ON t.TABLE_NAME = st.name AND t.TABLE_SCHEMA = OBJECT_SCHEMA_NAME(st.object_id)
JOIN sys.objects s ON st.object_id = s.object_id
LEFT JOIN sys.extended_properties ep ON s.object_id = ep.major_id 
    AND ep.minor_id = 0 
ORDER BY t.TABLE_CATALOG, t.TABLE_SCHEMA, t.TABLE_NAME;
