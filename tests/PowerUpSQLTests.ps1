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
    It "Should accept -DatabaseName argument" {
        if ( (Get-SQLDatabase -Instance $env:COMPUTERNAME -DatabaseName master | Measure-Object).count -lt 1) {
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


Describe "Get-SQLDatabaseRoleMember" {
    It "Should return results for the local host" {
        if ( (Get-SQLDatabaseRoleMember | Measure-Object).count -lt 1) {
            Throw "Incorrect database role member results returned"
        }
    }
    It "Should accept -Instance argument" {
        if ( (Get-SQLDatabaseRoleMember -Instance $env:COMPUTERNAME | Measure-Object).count -lt 1) {
            Throw "Incorrect database role member results returned"
        }
    }
    It "Should accept -Username argument" {
        if ( (Get-SQLDatabaseRoleMember -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database role member results returned"
        }
    }
    It "Should accept -Password argument" {
        if ( (Get-SQLDatabaseRoleMember -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database role member results returned"
        }
    }
    It "Should accept -DatabaseName argument" {
        if ( (Get-SQLDatabaseRoleMember -Instance $env:COMPUTERNAME -DatabaseName master | Measure-Object).count -lt 1) {
            Throw "Incorrect database role member results returned"
        }
    }
    It "Should accept -RolePrincipalName argument" {
        if ( (Get-SQLDatabaseRoleMember -Instance $env:COMPUTERNAME -RolePrincipalName "db_owner" | Measure-Object).count -lt 1) {
            Throw "Incorrect database role member results returned"
        }
    }
    It "Should accept -PrincipalName argument" {
        if ( (Get-SQLDatabaseRoleMember -Instance $env:COMPUTERNAME -PrincipalName "dbo" | Measure-Object).count -lt 1) {
            Throw "Incorrect database role member results returned"
        }
    }
    It "Should accept -NoDefaults flag" {
        if ( (Get-SQLDatabaseRoleMember -Instance $env:COMPUTERNAME -NoDefaults | Measure-Object).count -lt 1) {
            Throw "Incorrect database role member results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( Get-SQLInstanceLocal | Get-SQLDatabaseRoleMember | Measure-Object).count -lt 1) {
            Throw "Incorrect database role member results returned"
        }
    }
}


Describe "Get-SQLDatabaseSchema" {
    It "Should return results for the local host" {
        if ( (Get-SQLDatabaseSchema | Measure-Object).count -lt 1) {
            Throw "Incorrect database schema results returned"
        }
    }
    It "Should accept -Instance argument" {
        if ( (Get-SQLDatabaseSchema -Instance $env:COMPUTERNAME | Measure-Object).count -lt 1) {
            Throw "Incorrect database schema results returned"
        }
    }
    It "Should accept -Username argument" {
        if ( (Get-SQLDatabaseSchema -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database schema results returned"
        }
    }
    It "Should accept -Password argument" {
        if ( (Get-SQLDatabaseSchema -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database schema results returned"
        }
    }
    It "Should accept -DatabaseName argument" {
        if ( (Get-SQLDatabaseSchema -Instance $env:COMPUTERNAME -DatabaseName master | Measure-Object).count -lt 1) {
            Throw "Incorrect database schema results returned"
        }
    }
    It "Should accept -SchemaName argument" {
        if ( (Get-SQLDatabaseSchema -Instance $env:COMPUTERNAME -SchemaName "sys" | Measure-Object).count -lt 1) {
            Throw "Incorrect database schema results returned"
        }
    }

    It "Should accept -NoDefaults flag" {
        if ( (Get-SQLDatabaseSchema -Instance $env:COMPUTERNAME -NoDefaults | Measure-Object).count -lt 1) {
            Throw "Incorrect database schema results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( Get-SQLInstanceLocal | Get-SQLDatabaseSchema | Measure-Object).count -lt 1) {
            Throw "Incorrect database schema results returned"
        }
    }
}


Describe "Get-SQLDatabaseThreaded" {
    It "Should return results for the local host" {
        if ( (Get-SQLDatabaseThreaded | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
    It "Should accept -Instance argument" {
        if ( (Get-SQLDatabaseThreaded -Instance $env:COMPUTERNAME | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
    It "Should accept -Username argument" {
        if ( (Get-SQLDatabaseThreaded -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
    It "Should accept -Password argument" {
        if ( (Get-SQLDatabaseThreaded -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
    It "Should accept -DatabaseName argument" {
        if ( (Get-SQLDatabaseThreaded -Instance $env:COMPUTERNAME -DatabaseName master | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
    It "Should accept -NoDefaults flag" {
        if ( (Get-SQLDatabaseThreaded -Instance $env:COMPUTERNAME -NoDefaults | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
    It "Should accept -HasAccess flag" {
        if ( (Get-SQLDatabaseThreaded -Instance $env:COMPUTERNAME -HasAccess | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
   It "Should accept -SysAdminOnly flag" {
        if ( (Get-SQLDatabaseThreaded -Instance $env:COMPUTERNAME -SysAdminOnly | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
    It "Should accept -Threads argument" {
        if ( (Get-SQLDatabaseThreaded -Instance $env:COMPUTERNAME -Threads 2 | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( Get-SQLInstanceLocal | Get-SQLDatabaseThreaded | Measure-Object).count -lt 1) {
            Throw "Incorrect threaded database results returned"
        }
    }
}


Describe "Get-SQLDatabaseUser" {
    It "Should return results for the local host" {
        if ( (Get-SQLDatabaseUser | Measure-Object).count -lt 1) {
            Throw "Incorrect database user results returned"
        }
    }
    It "Should accept -Instance argument" {
        if ( (Get-SQLDatabaseUser -Instance $env:COMPUTERNAME | Measure-Object).count -lt 1) {
            Throw "Incorrect database user results returned"
        }
    }
    It "Should accept -Username argument" {
        if ( (Get-SQLDatabaseUser -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database user results returned"
        }
    }
    It "Should accept -Password argument" {
        if ( (Get-SQLDatabaseUser -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect database user results returned"
        }
    }
    It "Should accept -DatabaseName argument" {
        if ( (Get-SQLDatabaseUser -Instance $env:COMPUTERNAME -DatabaseName "master" | Measure-Object).count -lt 1) {
            Throw "Incorrect database user results returned"
        }
    }
    It "Should accept -DatabaseUser argument" {
        if ( (Get-SQLDatabaseUser -Instance $env:COMPUTERNAME -DatabaseUser "dbo" | Measure-Object).count -lt 1) {
            Throw "Incorrect database user results returned"
        }
    }
    It "Should accept -PrincipalName argument" {
        if ( (Get-SQLDatabaseUser -Instance $env:COMPUTERNAME -PrincipalName "sa" | Measure-Object).count -lt 1) {
            Throw "Incorrect database user results returned"
        }
    }
    It "Should accept -NoDefaults flag" {
        if ( (Get-SQLDatabaseUser -Instance $env:COMPUTERNAME -NoDefaults | Measure-Object).count -lt 1) {
            Throw "Incorrect database user results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( Get-SQLInstanceLocal | Get-SQLDatabaseUser | Measure-Object).count -lt 1) {
            Throw "Incorrect database user results returned"
        }
    }
}


Describe "Get-SQLConnectionTest" {
    It "Should return results for the local host" {
        if ( (Get-SQLConnectionTest | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept -Instance argument" {
        if ( (Get-SQLConnectionTest -Instance $env:COMPUTERNAME | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept -Username argument" {
        if ( (Get-SQLConnectionTest -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept -Password argument" {
        if ( (Get-SQLConnectionTest -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept -TimeOut argument" {
        if ( (Get-SQLConnectionTest -Instance $env:COMPUTERNAME -TimeOut 5 | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
   It "Should accept -DAC flag" {
        if ( (Get-SQLConnectionTest -Instance $env:COMPUTERNAME -DAC| Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( Get-SQLInstanceLocal | Get-SQLConnectionTest | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
}


Describe "Get-SQLConnectionTestThreaded" {
    It "Should return results for the local host" {
        if ( (Get-SQLConnectionTestThreaded | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept -Instance argument" {
        if ( (Get-SQLConnectionTestThreaded -Instance $env:COMPUTERNAME | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept -Username argument" {
        if ( (Get-SQLConnectionTestThreaded -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept -Password argument" {
        if ( (Get-SQLConnectionTestThreaded -Instance $env:COMPUTERNAME -Username test -Password test | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept -TimeOut argument" {
        if ( (Get-SQLConnectionTestThreaded -Instance $env:COMPUTERNAME -TimeOut 5 | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept -Threads argument" {
        if ( (Get-SQLConnectionTestThreaded -Instance $env:COMPUTERNAME -Threads 5 | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
   It "Should accept -DAC flag" {
        if ( (Get-SQLConnectionTestThreaded -Instance $env:COMPUTERNAME -DAC| Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( Get-SQLInstanceLocal | Get-SQLConnectionTestThreaded | Measure-Object).count -lt 1) {
            Throw "Incorrect connection test results returned"
        }
    }
}
