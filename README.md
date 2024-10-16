# CRTO_notes

Notes jotted down while taking the Certified Red Team Ops training.

## Miscellany before you get started

* Bidirectional copy/paste between host and lab machines is enabled. Doesn't work using Firefox as of v128.3.1esr (Linux). Ideas:
  * Try another browser
  * Copy, then on Guacamole press Ctrl+Shift+Alt -> Then copy from that box -> Press Ctrl+Shift+Alt again to close that box and paste where you want it to be pasted
* Snapshots are not available on the lab machines. They won't really help since they only save the hard drive state and not the running state. The storage state of the lab VMs are preserved when you shut down.  All of your listeners will still be there the next time you power it back up.


## Common tools

* [Cobalt Strike](https://www.cobaltstrike.com) (Manual: [HTML](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm#) [PDF](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt_cobalt-strike_userguide.pdf)) - platform for adversary simulations and red team operations; what most of the course is based on training to use
* [Red Team Guides](https://redteam.guide/docs/guides)


## Outline

How to do it.

1. Connect to attacker machine
2. Set up beacon listeners (and save them)
3. Generate payloads
4. 
