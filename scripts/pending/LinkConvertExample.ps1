$output = Get-SQLServerLinkCrawl -Verbose -Username sa -Password 'SuperSecretPassword!' -Instance 'MSSQLSRV04.demo.local\SQLSERVER2014' 
$CsvResults = $output  | 
foreach {
    [string]$StringLinkPath = ""
    $Path = $_.path 
    $PathCount = $Path.count - 1       
    $LinkSrc = $Path[$PathCount - 1]
    $LinkDes = $Path[$PathCount]
    $LinkUser = $_.user
    $LinkDesSysadmin = $_.Sysadmin
    $Instance = $_.instance 
    $LinkDesVersion = $_.Version
    $Path |
    foreach {
        if ( $StringLinkPath -eq ""){
            [string]$StringLinkPath = "$_" 
        }else{
            [string]$StringLinkPath = "$StringLinkPath -> $_"         
        }
    }
    $Object = New-Object PSObject        
    $Object | add-member Noteproperty LinkSrc          $LinkSrc
    $Object | add-member Noteproperty LinkName         $LinkDes
    $Object | add-member Noteproperty LinkInstance     $Instance     
    $Object | add-member Noteproperty LinkUser         $LinkUser
    $Object | add-member Noteproperty LinkSysadmin     $LinkDesSysadmin        
    $Object | add-member Noteproperty LinkVersion      $LinkDesVersion 
    $Object | add-member Noteproperty LinkHops         $PathCount 
    $Object | add-member Noteproperty LinkPath         $StringLinkPath
    $Object 
} 
$CsvResults  | export-csv -NoTypeInformation SQL-Server-Links.csv
