#requires -Version 1
@{
    ModuleToProcess   = 'PowerUpSQL.psm1'
    ModuleVersion     = '1.0.0.50'
    GUID              = 'dd1fe106-2226-4869-9363-44469e930a4a'
    Author            = 'Scott Sutherland'
    Copyright         = 'BSD 3-Clause'
    Description       = 'PowerUpSQL is an offensive toolkit designed for attacking SQL Server.  The PowerUpSQL module includes functions that support SQL Server discovery, auditing for common weak configurations, and privilege escalation on scale.  It is intended to be used during penetration tests and red team engagements. However, PowerUpSQL also includes many functions that could be used by administrators to inventory the SQL Servers on their ADS domain very quickly.  More information can be found at https://github.com/NetSPI/PowerUpSQL.'
    PowerShellVersion = '2.0'
    FunctionsToExport = @(  
        'Create-SQLFileXpDll', 
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
        'Get-SQLRecoverPwAutoLogon',
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
        'Get-SQLStoredProcedureSQLi',        
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
        'Invoke-SQLAuditSQLiExecuteAs',        
        'Invoke-SQLDumpInfo', 
        'Invoke-SQLEscalatePriv', 
        'Invoke-SQLOSCmd'		
    )
    FileList          = 'PowerUpSQL.psm1', 'PowerUpSQL.ps1', 'README.md'
}


