# Domain Reconnaissance

Once you have elevated access to a workstation on the domain, do some recon to see where else the creds can be used. Note that performing domain recon in a high priv process is not required, and in some cases (e.g. SYSTEM) can be detrimental.

## PowerView 

[PowerView](https://github.com/PowerShellMafia/PowerSploit) is a tool for domain enumeration. A strength is the queries return PS objects which can be piped to other cmdlets. Set up in PS: ```powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1```.

* ```powershell Get-Domain``` returns the current domain or the domain specified with ```-Domain```
* ```powershell Get-DomainController | select Forest, Name, OSVersion | fl``` returns the domain controllers for the current or specified domain
* ```powershell Get-ForestDomain``` returns all domains for the current forest or the forest specified by ```-Forest```
* ```powershell Get-DomainPolicyData | select -expand SystemAccess``` returns the default domain [controller] policy for the current domain or a specified domain/domain controller. Use to find e.g. domain password policy.
* ```powershell Get-DomainUser -Identity <user> -Properties DisplayName, MemberOf | fl``` returns all/specific user(s).
  * ```-Properties``` to return specific properties
  * ```-Identity``` to return a specific user
* ```powershell Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName``` returns all computers or specific computer objects
* ```powershell Get-DomainOU -Properties Name | sort -Property Name``` returns all organization units (OUs) or specific OU objects
* ```powershell Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName``` returns all domain groups or specific domain group objects
* ```powershell Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName``` returns members of a specific domain group
* ```powershell Get-DomainGPO -Properties DisplayName | sort -Property DisplayName``` returns all GPOs or specific GPO objects.
  * ```-ComputerIdentity``` enumerates all GPOs that are applied to a particular machine
* ```powershell Get-DomainGPOLocalGroup | select GPODisplayName, GroupName``` returns all GPOs that modify local group membership through Restricted Groups or Group Policy Preferences (then manually find which OUs, and by extension which computers, these GPOs apply to)
* ```powershell Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl``` enumerates machines where a specific domain user/group is a member of a specific local group (useful for finding where domain groups have local admin access, which is a more automated way to perform the manual cross-referencing above)
* ```powershell Get-DomainTrust``` returns all domain trusts for the current or specified domain

## SharpView

[SharpView](https://github.com/tevora-threat/SharpView) is a port of PowerView but doesn't have the same piping ability as PS.

## ADSearch

[ADSearch](https://github.com/tomcarver16/ADSearch) has fewer built-ins than PowerView and SharpView, but can specify custom LDAP searches, which can be used to identify entries in the directory that match a given criteria.

* ```execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=user"``` searches for all objects whose category is "user" (i.e. domain users)
* ```execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins))"``` limits the search results to domain groups which end in the word "admins" (can be made more complex with AND, OR and NOT conditions)
* ```execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member``` returns all attributes using ```--full``` or specific attributes with ```--attributes```; output to json with ```--json```
* 




