@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'PowerUpSQL.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = 'dd1fe106-2226-4869-9363-44469e930a4a'

# Author of this module
Author = 'Scott Sutherland'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerShellSQL: An Offensive Toolkit for attacking SQL Server.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Functions to export from this module
FunctionsToExport = @(  
    'Create-SQLFile-XPDLL',
    'Get-SQLAuditDatabaseSpec',
    'Get-SQLAuditServerSpec',
    'Get-SQLColumn',        
    'Get-SQLColumnSampleData',                                                                                                                                   
	'Get-SQLColumnSampleDataThreaded',                                                                                                                                   
    'Get-SQLConnectionTest',
    'Get-SQLConnectionTestThreaded',
    'Get-SQLDatabase',                                                                                                                   
    'Get-SQLDatabasePriv', 
    'Get-SQLDatabaseRole', 
    'Get-SQLDatabaseRoleMember',                                                                                                                                 
    'Get-SQLDatabaseSchema',    
	'Get-SQLDatabaseThreaded',   
    'Get-SQLDatabaseUser', 
    'Get-SQLFuzzDatabaseName',                                                                                                                                   
    'Get-SQLFuzzDomainAccount',                                                                                                                                  
    'Get-SQLFuzzObjectName',
    'Get-SQLFuzzServerLogin'                                                                                                                                    
    'Get-SQLInstanceDomain',
    'Get-SQLInstanceFile',  
    'Get-SQLInstanceLocal', 
    'Get-SQLInstanceScanUDP',    
	'Get-SQLInstanceScanUDPThreaded',
    'Get-SQLQuery',         
    'Get-SQLQueryThreaded',
	'Get-SQLServerConfiguration',	
    'Get-SQLServerCredential',                                                                                                                                   
    'Get-SQLServerInfo',    
	'Get-SQLServerInfoThreaded',    
    'Get-SQLServerLink',    
    'Get-SQLServerLogin',   
    'Get-SQLServerPriv',    
    'Get-SQLServerRole',    
    'Get-SQLServerRoleMember',                                                                                                                                   
    'Get-SQLServiceAccount',
    'Get-SQLServiceLocal', 
    'Get-SQLSession',       
    'Get-SQLStoredProcedure', 
    'Get-SQLSysadminCheck', 
    'Get-SQLTable',         
    'Get-SQLTriggerDdl',    
    'Get-SQLTriggerDml',    
    'Get-SQLView',  
	'Invoke-SQLAudit',
	'Invoke-SQLAuditPrivCreateProcedure',	
	'Invoke-SQLAuditPrivDbChaining',
	'Invoke-SQLAuditPrivImpersonateLogin',
	'Invoke-SQLAuditPrivServerLink',
	'Invoke-SQLAuditPrivTrustworthy',
	'Invoke-SQLAuditPrivXpDirtree',
	'Invoke-SQLAuditPrivXpFileexit',
	'Invoke-SQLAuditRoleDbDdlAdmin',
	'Invoke-SQLAuditRoleDbOwner',
	'Invoke-SQLAuditSampleDataByColumn',
	'Invoke-SQLAuditWeakLoginPw',
	'Invoke-SQLDumpInfo',
	'Invoke-SQLEscalatePriv',
	'Invoke-SQLOSCmd'		
)

# List of all files packaged with this module
FileList = 'PowerUpSQL.psm1', 'PowerUpSQL.ps1', 'README.md'

}


