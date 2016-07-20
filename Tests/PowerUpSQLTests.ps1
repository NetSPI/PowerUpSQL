
Describe "Get-SQLDatabase" {
    It "Should return results for the local host" {
        if ( (Get-SQLDatabase | Measure-Object).count -lt 1) {
            Throw "Incorrect database results returned"
        }
    }
    It "Should accept -Instance argument" {
        if ( (Get-SQLDatabase -Instance $env:COMPUTERNAME | Measure-Object).count -lt 1) {
            Throw "Incorrect database results returned"
        }
    }
    It "Should accept -Username argument" {
        if ( (Get-SQLDatabase -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database results returned"
        }
    }
    It "Should accept -Password argument" {
        if ( (Get-SQLDatabase -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database results returned"
        }
    }
    It "Should accept -NoDefaults flag" {
        if ( (Get-SQLDatabase -Instance $env:COMPUTERNAME -NoDefaults | Measure-Object).count -lt 1) {
            Throw "Incorrect database results returned"
        }
    }
    It "Should accept -HasAccess flag" {
        if ( (Get-SQLDatabase -Instance $env:COMPUTERNAME -HasAccess | Measure-Object).count -lt 1) {
            Throw "Incorrect database results returned"
        }
    }
   It "Should accept -SysAdminOnly flag" {
        if ( (Get-SQLDatabase -Instance $env:COMPUTERNAME -SysAdminOnly | Measure-Object).count -lt 1) {
            Throw "Incorrect database results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( Get-SQLInstanceLocal | Get-SQLDatabase | Measure-Object).count -lt 1) {
            Throw "Incorrect database results returned"
        }
    }
}

Describe "Get-SQLDatabasePriv" {
    It "Should return results for the local host" {
        if ( (Get-SQLDatabasePriv | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
    It "Should accept -Instance argument" {
        if ( (Get-SQLDatabasePriv -Instance $env:COMPUTERNAME | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
    It "Should accept -Username argument" {
        if ( (Get-SQLDatabasePriv -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
    It "Should accept -Password argument" {
        if ( (Get-SQLDatabasePriv -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
    It "Should accept -DatabaseName argument" {
        if ( (Get-SQLDatabasePriv -Instance $env:COMPUTERNAME -DatabaseName master | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
    It "Should accept -PermissionName argument" {
        if ( (Get-SQLDatabasePriv -Instance $env:COMPUTERNAME -PermissionName "EXECUTE" | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
    It "Should accept -PermissionType argument" {
        if ( (Get-SQLDatabasePriv -Instance $env:COMPUTERNAME -PermissionType "OBJECT_OR_COLUMN" | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
    It "Should accept -PrincipalName argument" {
        if ( (Get-SQLDatabasePriv -Instance $env:COMPUTERNAME -PrincipalName "Public" | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
    It "Should accept -NoDefaults flag" {
        if ( (Get-SQLDatabasePriv -Instance $env:COMPUTERNAME -NoDefaults | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( Get-SQLInstanceLocal | Get-SQLDatabasePriv | Measure-Object).count -lt 1) {
            Throw "Incorrect database priv results returned"
        }
    }
}


Describe "Get-SQLDatabaseRole" {
    It "Should return results for the local host" {
        if ( (Get-SQLDatabaseRole | Measure-Object).count -lt 1) {
            Throw "Incorrect database role results returned"
        }
    }
    It "Should accept -Instance argument" {
        if ( (Get-SQLDatabaseRole -Instance $env:COMPUTERNAME | Measure-Object).count -lt 1) {
            Throw "Incorrect database role results returned"
        }
    }
    It "Should accept -Username argument" {
        if ( (Get-SQLDatabaseRole -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database role results returned"
        }
    }
    It "Should accept -Password argument" {
        if ( (Get-SQLDatabaseRole -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database role results returned"
        }
    }
    It "Should accept -DatabaseName argument" {
        if ( (Get-SQLDatabaseRole -Instance $env:COMPUTERNAME -DatabaseName master | Measure-Object).count -lt 1) {
            Throw "Incorrect database role results returned"
        }
    }
    It "Should accept -RolePrincipalName argument" {
        if ( (Get-SQLDatabaseRole -Instance $env:COMPUTERNAME -RolePrincipalName "db_owner" | Measure-Object).count -lt 1) {
            Throw "Incorrect database role results returned"
        }
    }
    It "Should accept -RoleOwner argument" {
        if ( (Get-SQLDatabaseRole -Instance $env:COMPUTERNAME -RoleOwner "sa" | Measure-Object).count -lt 1) {
            Throw "Incorrect database role results returned"
        }
    }
    It "Should accept -NoDefaults flag" {
        if ( (Get-SQLDatabaseRole -Instance $env:COMPUTERNAME -NoDefaults | Measure-Object).count -lt 1) {
            Throw "Incorrect database role results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( Get-SQLInstanceLocal | Get-SQLDatabaseRole | Measure-Object).count -lt 1) {
            Throw "Incorrect database role results returned"
        }
    }
}
