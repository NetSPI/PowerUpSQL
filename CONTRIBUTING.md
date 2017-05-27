# Contributing to the PowerUpSQL

Thank you for taking an interest in PowerUpSQL! We're excited that you'd like to contribute. How would you like to help?

* [I'd like to report a bug or request an enhancement](#how-to-report-bugs-or-request-enhancements)
* [How to Write or Update Documentation](#how-to-write-or-update-documentation)

## How to Report Bugs or Request Enhancements
Check out the [Github issues list]. Search for what you're interested in - there may already be an issue for it. Make sure to search through closed issues, too, because we may have declined things that aren't a good fit for PowerUpSQL.

If you can't find a similar issue, go ahead and open your own. Include as much detail as you can - what you're seeing now, and what you'd like to see.

When requesting new checks, keep in mind that we want to focus on:

* Bug fixes
* Vulnerability checks that can result in privilege escalation
* Post exploitation checks
* Performance improvements

Now head on over to the [Github issues list] and get started.

## Script Style Guide
We love good ideas! So if you have one for PowerUpSQL we want to work with you on it!  
However, we have a few guidlines below. If you have questions or comments please feel free to reach out to us! 
* Functions must follow the verb-noun agreement.  
* Functions must use the PowerUpSQL naming style. Examples: Get-SQLXXX, Invoke-SQLXXX, CreateSQLXXX
* Functions must accept the "Instance" parameter on the pipeline for targeting specific databases.
* Function output must include the "ComputerName" and "Instance" fields so they can be used with other functions.
* Function output must be a psobject, datatable, or other custom object. 
* Do not use write-output/write-host when possible. 
* Do use write-verbose when trying to provide more context to the user or troubleshooting.
* Please include a help section for all functions with command examples.
* Please do not use hardcoded paths.


### Attribution
This Code of Conduct is adapted from the [Contributor Covenant][homepage], version 1.4, available at [http://contributor-covenant.org/version/1/4][version]

[homepage]: http://contributor-covenant.org
[version]: http://contributor-covenant.org/version/1/4/
[Github issues list]:https://github.com/NetSPI/PowerUpSQL/issues
