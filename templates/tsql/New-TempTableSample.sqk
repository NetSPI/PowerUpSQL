-- Create sample table variables and local/global temp tables

-- Create global temporary table
IF (OBJECT_ID('tempdb..##GlobalTempTbl') IS NULL)
CREATE TABLE ##GlobalTempTbl (Spy_id INT NOT NULL, SpyName text NOT NULL, RealName text NULL);

-- Insert records global temporary table
INSERT INTO ##GlobalTempTbl (Spy_id, SpyName, RealName) VALUES (1,'Black Widow','Scarlett Johansson')
INSERT INTO ##GlobalTempTbl (Spy_id, SpyName, RealName) VALUES (2,'Ethan Hunt','Tom Cruise')
INSERT INTO ##GlobalTempTbl (Spy_id, SpyName, RealName) VALUES (3,'Evelyn Salt','Angelina Jolie')
INSERT INTO ##GlobalTempTbl (Spy_id, SpyName, RealName) VALUES (4,'James Bond','Sean Connery')
GO

-- Query global temporary table
SELECT * 
FROM ##GlobalTempTbl
GO

-- Create local temporary table
IF (OBJECT_ID('tempdb..#LocalTempTbl') IS NULL)
CREATE TABLE #LocalTempTbl (Spy_id INT NOT NULL, SpyName text NOT NULL, RealName text NULL);
-- Insert records local temporary table
INSERT INTO #LocalTempTbl (Spy_id, SpyName, RealName) VALUES (1,'Black Widow','Scarlett Johansson')
INSERT INTO #LocalTempTbl (Spy_id, SpyName, RealName) VALUES (2,'Ethan Hunt','Tom Cruise')
INSERT INTO #LocalTempTbl (Spy_id, SpyName, RealName) VALUES (3,'Evelyn Salt','Angelina Jolie')
INSERT INTO #LocalTempTbl (Spy_id, SpyName, RealName) VALUES (4,'James Bond','Sean Connery')
GO
-- Query local temporary table
SELECT * 
FROM #LocalTempTbl
GO

-- Create table variable
If not Exists (SELECT name FROM tempdb.sys.objects WHERE name = 'table_variable')
DECLARE @table_variable TABLE (Spy_id INT NOT NULL, SpyName text NOT NULL, RealName text NULL);

-- Insert records into table variable
INSERT INTO @table_variable (Spy_id, SpyName, RealName) VALUES (1,'Black Widow','Scarlett Johansson')
INSERT INTO @table_variable (Spy_id, SpyName, RealName) VALUES (2,'Ethan Hunt','Tom Cruise')
INSERT INTO @table_variable (Spy_id, SpyName, RealName) VALUES (3,'Evelyn Salt','Angelina Jolie')
INSERT INTO @table_variable (Spy_id, SpyName, RealName) VALUES (4,'James Bond','Sean Connery')

-- Query table variable in same batch 
SELECT * 
FROM @table_variable
GO
