Function Get-SQLCrawl{
    <#
    .SYNOPSIS
    Get-SQLCrawl attempts to enumerate and follow MSSQL database links.
    .DESCRIPTION
    Get-SQLCrawl attempts to enumerate and follow MSSQL database links. The function enumerates database names, versions, and links,
    and then enumerates the MSSQL user and the privileges that the link path has.
    .EXAMPLE
    Get-SQLCrawl -Instance "servername\instancename" -ByLinkPath
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

        $Server = New-Object PSObject -Property @{ Name=""; Version=""; Links=@(); Path=@(); User=""; Sysadmin=""; CustomQuery=""}

        $List += $Server
        $SqlInfoTable = New-Object System.Data.DataTable
    }
    
    Process
    {
        $i=1
        while($i){
            $i--
            foreach($Server in $List){
                if($Server.Name -eq "") {
                    $List = (Get-SQLServerLink -list $List -server $Server -query $Query)
                    $i++

                    # Verbose output
                    $myname = $server.name
                    $myLinkPath = $server.path                   
                    $myPath = $myLinkPath -join ' -> '                 
                    $mylinks = $server.links
                    $mysysadmin = $server.sysadmin
                    $myuser = $server.user
                    $myLinkCount = $mylinks.count
                 
                    write-verbose "--------------------------------"
                    Write-Verbose " Server: $myname"
                    write-verbose "--------------------------------"
                    write-verbose " - Link Path to server: $myPath"                    
                    write-verbose " - Link Login: $myuser"                                   
                    write-verbose " - Link IsSysAdmin: $mysysadmin"
                    write-verbose " - Link Count: $myLinkCount"                    
                    write-verbose " - Links on this server:$mylinks"
                }   
            } 
        }

        if($Export){
            $LinkList = New-Object System.Data.Datatable
            [void]$LinkList.Columns.Add("Name")
            [void]$LinkList.Columns.Add("Version")
            [void]$LinkList.Columns.Add("Path")
            [void]$LinkList.Columns.Add("Links")
            [void]$LinkList.Columns.Add("User")
            [void]$LinkList.Columns.Add("Sysadmin")
            [void]$LinkList.Columns.Add("CustomQuery")

            foreach($Server in $List){
                [void]$LinkList.Rows.Add($Server.name,$Server.version,$Server.path -join " -> ", $Server.links -join ",", $Server.user, $Server.Sysadmin, $Server.CustomQuery -join ",")
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

Function Get-SQLServerLink{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="List of server objects identified during the crawling")]
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
        $SqlInfoTable = Get-SqlQuery -instance $Instance -Query ((Get-SQLLinkQuery -path $Server.Path -sql $SqlInfoQuery)) -Timeout $Timeout -Username $UserName -Password $Password -Credential $Credential
        if($SqlInfoTable.Servername -ne $null){
            $Server.Name = $SqlInfoTable.Servername
            $Server.Version = [System.String]::Join("",(($SqlInfoTable.Version)[10..25]))
            $Server.Sysadmin = $sqlInfoTable.role
            $Server.User = $sqlInfoTable.linkuser
            
            if($List.Count -eq 1) { $Server.Path += ,$sqlInfoTable.servername }

            $SqlInfoTable = Get-SqlQuery -instance $Instance -Query ((Get-SQLLinkQuery -path $Server.Path -sql $SqlLinksQuery)) -Timeout $Timeout -Username $UserName -Password $Password -Credential $Credential
            $Server.Links = [array]$SqlInfoTable.srvname

            if($Query -ne ""){
                if($Query -like '*xp_cmdshell*'){
                    $Query =  $Query + " WITH RESULT SETS ((output VARCHAR(8000)))"
                }
                if($Query -like '*xp_dirtree*'){
                    $Query = $Query + "  WITH RESULT SETS ((output VARCHAR(8000), depth int))"
                }
                $SqlInfoTable = Get-SqlQuery -instance $Instance -Query ((Get-SQLLinkQuery -path $Server.Path -sql $Query)) -Timeout $Timeout -Username $UserName -Password $Password -Credential $Credential
                if($Query -like '*WITH RESULT SETS*'){
                    $Server.CustomQuery = $SqlInfoTable.output
                } else {
                    $Server.CustomQuery = $SqlInfoTable
                }
            }

            if(($Server.Path | Sort-Object | Get-Unique).Count -eq ($Server.Path).Count){
                foreach($Link in $Server.Links){
                    $Linkpath = $Server.Path + $Link
                    $List += ,(New-Object PSObject -Property @{ Name=""; Version=""; Links=@(); Path=$Linkpath; User=""; Sysadmin=""; CustomQuery="" })
                }
            }
        } else {
            $Server.Name = "Broken Link"
        }
        return $List
    }
}

Function Get-SQLLinkQuery{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="SQL link path to crawl")]
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
        (Get-SQLLinkQuery -path $Path[1..($Path.Length-1)] -sql $Sql -ticks ($Ticks+1))+"'"*[Math]::pow(2,$Ticks)+")")
    }
}

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
                    #Write-Verbose -Message "$Instance : Connection Success."
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
                    #Write-Verbose -Message "$Instance : Connection Failed."
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

        # Check for username and password
        if($Username -and $Password)
        {
            # Setup connection string with SQL Server credentials
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=$TimeOut"
        }
        else
        {
            # Get connecting user
            $UserDomain = [Environment]::UserDomainName
            $Username = [Environment]::UserName
            $ConnectionectUser = "$UserDomain\$Username"

            # Status user
            Write-Debug -Message "Attempting to authenticate to $DacConn$Instance as current Windows user ($ConnectionectUser)..."

            # Setup connection string with trusted connection
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=1"

            <#
                    # Check for provided credential
                    if ($Credential){
                    $Username = $credential.Username
                    $Password = $Credential.GetNetworkCredential().Password
                    # Setup connection string with SQL Server credentials
                    $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=$TimeOut"
                    }
            #>
        }

        # Return the connection object
        return $Connection
    }

    End
    {
    }
}


# Example commands
#Get-SQLCrawl -instance "SQLSERVER1\Instance1" -Query "select name from master..sysdatabases"
#Get-SQLCrawl -instance "SQLSERVER1\Instance1" -Query "select name from master..sysdatabases" | select name,version,path,links,user,sysadmin,customquery | format-table
#Get-SQLCrawl -instance "SQLSERVER1\Instance1" -Query "select name from master..sysdatabases" | where name -ne "Broken Link" | select name,version,path,links,user,sysadmin,customquery | format-table
#Get-SQLCrawl -instance "SQLSERVER1\Instance1" -Query "exec master..xp_cmdshell 'whoami'" | format-table
#Get-SQLCrawl -instance "SQLSERVER1\Instance1" -Query "exec xp_dirtree 'c:\temp'" -Export | format-table
#Get-SQLCrawl -instance "SQLSERVER1\Instance1" -Query "select name from master..sysdatabases" -Export | where name -ne "broken link" | sort name |  Format-Table
