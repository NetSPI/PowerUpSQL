-- List temp tables, columns, and column types
SELECT t1.name as 'tablename',t2.name as 'columnname',t3.name FROM tempdb.sys.objects AS t1
JOIN tempdb.sys.columns AS t2 ON t1.OBJECT_ID = t2.OBJECT_ID
JOIN sys.types AS t3 ON t2.system_type_id = t3.system_type_id
WHERE t1.name like '#%';
