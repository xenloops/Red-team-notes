# Host Privilege Escalation

Not always needed, but helps in lateral movement and doing high-priv naughty things. It should only be sought if it provides a means of reaching a goal, not something done for ego or cred. Some capabilities that can be done:

* Dumping creds with Mimikatz
* Sneaky persistence
* Manipulating host configuration (e.g. firewall)

Common entrypoints include software misconfigurations and missing patches. [SharpUp](https://github.com/GhostPack/SharpUp) can enumerate these.

## Windows Services

Just a startup application run by the OS. How to see:

* Open services.msc
* Command line: ```sc query```
* PS: ```Get-Service | fl```

Properties to look for:

* Binary Path
* Startup Type
* Service Status
* Log On As - highly-privileged services make escalation easy (need to restart service to apply -- sometimes need to wait until machine is restarted)
* Dependants/Dependencies

Remember to restore the service configuration once you are done.

## Unquoted Service Paths

The path to the service binary is not wrapped in quotes. Under specific conditions it can lead to an elevation of privilege.

From beacon: ```run wmic service get name, pathname```
If see something unquoted like ```VulnService1    C:\Program Files\Vulnerable Services\Service 1.exe```, vulnerable places to drop a binary (which would run before the real exe) would be:
1. C:\**Program.exe**
2. C:\Program Files\**Vulnerable.exe**
3. C:\Program Files\Vulnerable Services\**Service.exe**

Check for permission to write to those directories from beacon: ```powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl```

Or just use SharpUp: ```execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath```

Payloads that work here are the ones with ```svc``` in the name to be service binaries. Recommend using TCP beacons bound to localhost only for privilege escalations. The new beacon does not appear in the UI automatically, but should see the port used in the TCP listener is listening on 127.0.0.1. Then ```connect localhost <port>``` to link to beacon. To restore the service, simply delete Service.exe and restart the service.

## 
