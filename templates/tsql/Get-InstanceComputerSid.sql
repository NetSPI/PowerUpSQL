-- The following command will recover the SID for the current computer account if it's assocaited with a Active Directory domain.
-- https://www.netspi.com/blog/technical/network-penetration-testing/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/
-- Tested and works on: SQL Server 2012,2014,2016
-- Currently failes on SQL Server 2008
SELECT SUSER_SID(concat(DEFAULT_DOMAIN(),'\',cast(SERVERPROPERTY('MachineName') as varchar(max)),'$'))
