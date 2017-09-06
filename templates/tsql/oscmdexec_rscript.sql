-- Dependences: R runtime must be installed

-- Enable Show Advanced Options
sp_configure 'Show Advanced Options',1
RECONFIGURE
GO

-- Enable external scripts enabled, may require a service restart
sp_configure 'external scripts enabled',1
RECONFIGURE
GO

EXEC sp_execute_external_script
  @language=N'R',
  @script=N'OutputDataSet <- data.frame(system("cmd.exe /c dir",intern=T))'
  WITH RESULT SETS (([cmd_out] text));
GO
