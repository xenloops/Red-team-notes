# Command & Control

## Starting the Team Server

1. Log into Attacker Desktop
2. Right-click on Terminal icon in the taskbar
3. Select Team Server (SSH)
4. (Opt) tmux session
5. ```cd cobaltstrike```
6. ```sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile```
7. Once SHA of teamserver appears, run Cobalt Strike client from the taskbar
8. Connect (confirm fingerprint first time)

## Listener Management

Use nickelviper.com for stager, which points to 10.10.5.50

* Egress listeners (Cobalt Strike > Listeners) - allow Beacon to communicate outside of the target network to team server
  * HTTP - allows Beacon to send and receive C2 messages over HTTP GET and/or POST requests (check with ```sudo ss -lntp```)
  * DNS - C2 messages over several lookup/response types like A, AAAA and TXT. TXT used by default (holds the most amount of data). Use pics.nickelviper.com for stager. (Check with ```dig @ns1.nickelviper.com test.pics.nickelviper.com +short```; should give 0.0.0.0.)
  * P2P - chain multiple Beacons together in parent/child relationships to reduce overall host traffic or to allow beacons on hosts unable to egress data out of network. Link child Beacon to an egress HTTP/DNS Beacon, and traffic from the child is sent to the parent, which sends to the team server.
    * SMB - starts a new named pipe server and listens for an incoming connection. This pipe is available both locally and remotely. (Use a name that will blend with existing pipes -- ```PS C:\> ls \\.\pipe\``` shows them.)
    * Raw TCP - binds and listens on the specified port number.

Create all listeners:
| name | payload | host | port | beacons | profile |
|--|--|--|--|--|--|
| dns | windows/beacon_dns/reverse_dns_txt | pics.nickelviper.com | 53 | pics.nickelviper.com | default |
| http | windows/beacon_dns/reverse_http | nickelviper.com | 80 | nickelviper.com | default |
| smb | windows/beacon_bind_pipe | | TSVCPIPE-abcd... | | |
| tcp | windows/beacon_bind_tcp | | 4444 | 0.0.0.0 | |
| tcp-loc | windows/beacon_bind_tcp | | 4444 | 127.0.0.1 | |

## Generating Payloads

Use Payloads menu to generate different kinds of payloads:
| | | |
|--|--|--|
| HTML App | .hta file delivered through browser via social engineering | x86, only for egress listeners |
| MS Office Macro | VBA that can be dropped into a macro-enabled MS Word or Excel file | x86/x64, only for egress listeners |
| Stager Payload Generator | Payload stager in C, C#, PowerShell, Python, VBA, etc.; for custom payloads/exploits | x86/x64, only for egress listeners |
| Stageless Payload Generator | Stageless payloads rather than stagers. Can specify an exit function (process/thread) | Also for P2P listeners |
| Windows Stager Payload | Pre-compiled stager as an EXE, Service EXE, or DLL. | |
| Windows Stageless Payload | Pre-compiled stageless payload as an EXE, Service EXE, DLL, shellcode, or PowerShell | P2P listeners |
| Windows Stageless Generate All Payloads | Every stageless payload variant for every listener | x86/x64 |

Save payloads to C:\Payloads (Defender has an exception for that directory).

## Interacting with Beacon

1. Launch a beacon on the Attacker Desktop
2. Change beacon's sleep cycle if desired, e.g. ```sleep 5``` (_but watch how noisy it can get -- not a prob in lab network_)
3. Confirm beacon in Wireshark; filter for http, look for GET request with 200 response (use Follow > HTTP Stream) -- how traffic appears can be customised in the Malleable C2 profile
4. Check control by using some commands, like ```pwd```, ```dir```, ```whoami```, etc.
5. DNS beacons do not automatically send metadata; use ```checkin``` command

## Pivot Listeners
## Running as a Service
