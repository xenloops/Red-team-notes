# Host Reconnaissance

After exploiting a host, pause and examine the host environment. Look for AV/EDR, policies, logging, etc. Everything learned should shape the attacks going forward. Best practice is to know several methods and tools in case a go-to favorite is watched for.

List running processes on a system using ```ps```. Running as a standard user won't show architecture, session, and user information for processes that the current user does not own. Interesting processes  include:
* Sysmon64
* MsMpEng
* elastic-endpoint
* elastic-agent

## Seatbelt

[Seatbelt](https://github.com/GhostPack/Seatbelt) collects data on a host, e.g. OS info, AV, AppLocker, LAPS, PowerShell logging, audit policies, .NET versions, and firewall rules. PS: ```execute-assembly .\Seatbelt.exe -group=system```

## Domain Categorization

Domain names can be categorized into buckets that are routinely blocked by vendors. This can be remedied by getting a domain in an unfiltered category or requesting a change on the domain (e.g. through sites like [Bluecoat](https://sitereview.bluecoat.com) and using tools like [Chameleon](https://github.com/mdsecactivebreach/Chameleon)).

## HTTPS Offloading

Some orgs use a proxy to decrypt incoming HTTPS traffic to inspect the plaintext HTTP. Use tools like [Covenant](https://github.com/cobbr/Covenant) for certificate pinning to avoid this.

## Content Filtering / AV Scanning

Some prgs scanincoming traffic for known malicious content or block the ingress/egress of file types such as .exe, .dll, and .ps1.

## Authentication

Orgs can use basic auth with a local database, Radius, or AD before access to the proxy. AD integration is common and provides SSO via NTLM, Kerberos and LDAP. This often excludes computer accounts, which means HTTP/S beacons running as local SYSTEM accounts won't work.

## Capturing data from client

* Screenshots: Take screenshots of the user’s desktop using a beacon command:
  * ```printscreen```: single screenshot via PrintScr
  * ```screenshot```: single screenshot
  * ```screenwatch```: periodic screenshots of desktop
* Keylogger: Capture user keystrokes in the beacon: ```keylogger```. CS: View > Keystrokes to see what's typed. Kill the keylogger using ```jobs``` then ```jobkill <PID>```.
* Clipboard: The beacon ```clipboard``` command grabs only text copied to the user's clipboard.
* User sessions ...



