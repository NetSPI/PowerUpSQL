/*
Script:
Get-SQLServerLinkHistory

Goal: 
Identify linked server usage by qurying the plan cache.

Potential Solution: 
You can modify the query below to identify openquery, openrowset and specific link name usage (would require appending names to query).  
However, I still need a solution for four part named references.

Requiremets:
Sysadmin or required SELECT privileges.

Known limitations:
 - If linked server is used via view/function it may not appear in your result set. In these instances you would have to search the 
   source code for link name references in functions/views, then search the plan cache for those function/views.
 - It will only include any sql that is in the plan cache.
 - The plan cache is cleared on restart.
 - SQL Server will clear out old plans from the cache once it's size limits are reached (can we check when it was last cleared?)
 
Source: 
https://dba.stackexchange.com/questions/5519/determine-last-usage-date-of-a-linked-server
*/

SELECT
    (SELECT TOP 1 SUBSTRING(s2.text,statement_start_offset / 2+1 , 
      ( (CASE WHEN statement_end_offset = -1 
         THEN (LEN(CONVERT(nvarchar(max),s2.text)) * 2) 
         ELSE statement_end_offset END)  - statement_start_offset) / 2+1)) 
        AS sql_statement,
    last_execution_time
FROM sys.dm_exec_query_stats AS s1 
    CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS s2 
WHERE s2.text like '%openquery%' or s2.text like '%openrowset)'
ORDER BY 
    s1.sql_handle, s1.statement_start_offset, s1.statement_end_offset
