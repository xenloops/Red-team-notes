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


