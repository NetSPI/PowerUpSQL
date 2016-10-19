
## ![alt tag](https://github.com/NetSPI/PowerUpSQL/blob/master/images/powerupsql-large.png)
[![licence badge]][licence]
[![stars badge]][stars]
[![forks badge]][forks]
[![issues badge]][issues]

[licence badge]:https://img.shields.io/badge/license-New%20BSD-blue.svg
[stars badge]:https://img.shields.io/github/stars/NetSPI/PowerUpSQL.svg
[forks badge]:https://img.shields.io/github/forks/NetSPI/PowerUpSQL.svg
[issues badge]:https://img.shields.io/github/issues/NetSPI/PowerUpSQL.svg

[licence]:https://github.com/NetSPI/PowerUpSQL/blob/master/LICENSE
[stars]:https://github.com/NetSPI/PowerUpSQL/stargazers
[forks]:https://github.com/NetSPI/PowerUpSQL/network
[issues]:https://github.com/NetSPI/PowerUpSQL/issues

###PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server
The PowerUpSQL module includes functions that support SQL Server discovery, auditing for common weak configurations, and privilege escalation on scale.  It is intended to be used during internal penetration tests and red team engagements. However, PowerUpSQL also includes many functions that could be used by administrators to quickly inventory the SQL Servers in their ADS domain.

PowerUpSQL was designed with six objectives in mind:
* Easy Server Discovery: Discovery functions can be used to blindly identify local, domain, and non-domain SQL Server instances on scale.
* Easy Server Auditing: The Invoke-SQLAudit function can be used to audit for common high impact vulnerabilities and weak configurations using the current login's privileges.  Also, Invoke-SQLDumpInfo can be used to quickly inventory databases, privileges, and other information.
* Easy Server Exploitation: The Invoke-SQLEscalatePriv function attempts to obtain sysadmin privileges using identified vulnerabilities. 
* Scalability: Multi-threading is supported on core functions so they can be executed against many SQL Servers quickly.
* Flexibility: PowerUpSQL functions support the PowerShell pipeline so they can be used together, and with other scripts.
* Portability: Default .net libraries are used and there are no dependencies on SQLPS or the SMO libraries. Functions have also been designed so they can be run independently. As a result, it's easy to use on any Windows system with PowerShell v2 installed.


### Module Information
* Author: Scott Sutherland (@_nullbind), NetSPI - 2016
* Major Contributors: Antti Rantasaari and Eric Gruber (@egru)
* Contributors: Alexander Leary, @leoloobeek, and @ktaranov
* License: BSD 3-Clause
* Required Dependencies: None
 
For setup instructions, function overviews, and common usage information check out the PowerUpSQL wiki: https://github.com/NetSPI/PowerUpSQL/wiki

### Hacking SQL Server on Scale with PowerShell Presentation
* DerbyCon 6.0 Slides: http://www.slideshare.net/nullbind/derbycon2016-hacking-sql-server-on-scale-with-powershell
* DerbyCon 6.0 Videos: https://www.youtube.com/watch?v=xLbPztByc8M
* 2016 PASS Oct. Webinar Video: https://youtu.be/npoORzfP7rw
