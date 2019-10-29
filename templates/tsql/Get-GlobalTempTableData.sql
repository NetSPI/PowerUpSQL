-- Script: Get-GlobalTempTableData.sql
-- Author: Scott Sutherland

---------------------------------------
-- View All Global Temp Table Contents
---------------------------------------

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
	
	-- Select table contents
	DECLARE @myname varchar(max)
	SET @myname = 'SELECT * FROM [' + @mytempname + ']'
	EXEC(@myname)
	
	-- Next 
	FETCH NEXT FROM MY_CURSOR INTO @mytempname 
END
CLOSE MY_CURSOR
DEALLOCATE MY_CURSOR

---------------------------------------
-- View All Global Temp Table Contents 
-- Loop it
---------------------------------------

While 1=1
BEGIN
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

		-- Select table contents
		DECLARE @myname varchar(max)
		SET @myname = 'SELECT * FROM [' + @mytempname + ']'
		EXEC(@myname)

		-- Next record
		FETCH NEXT FROM MY_CURSOR INTO @mytempname 
	END
	CLOSE MY_CURSOR
	DEALLOCATE MY_CURSOR
END

