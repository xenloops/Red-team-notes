# Password Cracking Tips & Tricks

Passwords are (supposed to be) stored in non-clear ways, notably hashed. Several generic password cracking methods deal with non-NTLM hashes. Note that the lab VMs are not good for cracking hashes, a processor-intensive function.

## Tools

* [hashcat](https://hashcat.net/hashcat)
* [John the Ripper](https://www.openwall.com/john)


## Wordlist / Dictionary Attacks

Easiest method. Looks up hashes of common passwords from the wordlist. Many wordlists exist in the public domain:

* rockyou
* [SecLists repo](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

Basic use: ```hashcat -a 0 -m 1000 ntlm.txt rockyou.txt``` (use ```hashcat --help``` to see options). But if the password is one character off from one in the wordlist, this won't find it.

## Wordlist + Rules

Rules extend a wordlist. The [hashcat wiki](https://hashcat.net/wiki/doku.php?id=rule_based_attack) contains info on writing custom rules. Examples:

* Change a char's case
* Pre/appending characters

To append a character, use ```$x``` -- so to append "2020", use ```$2$0$2$0``` and add the rule as a text file: ```hashcat -a 0 -m 1000 ntlm.txt rockyou.txt -r rules\add-year.rule```

## Masks: mode -a 3

If there are assumptions that can be made about the password (e.g. length, what can appear in certain positions), masking is useful. In hashcat, ```-a 3``` specifies a mask atttack.

```hashcat --help``` shows the charsets:
```
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff
```

Example: ```hashcat -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d``` to catch something like "Password1"

Can combine masks, e.g. ```hashcat -a 3 -m 1000 ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1``` to catch something like "Password!"

For masks of different lengths, create a mask file, e.g.:
```
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
```

To specifiy static strings in the password: 
```
Booger?d
Booger?d?d
Booger?d?d?d
Booger?d?d?d?d
```

and use it like: ```hashcat -a 3 -m 1000 ntlm.txt example.hcmask```

## Combinator: mode -a 1

Combines words from different lists into every permutation. ```hashcat -a 1 -m 1000 ntlm.txt list1.txt list2.txt -j $- -k $!``` catches "purple-monkey!" if purple and monkey are in list1 and list2 respectively. (But on Linux shells need to quote $s.)

## Hybrid: modes -a 6, 7

Mode 6: Specify wordlist and mask; the mask is pre/appended to the words within the list: ```hashcat -a 6 -m 1000 ntlm.txt list.txt ?d?d?d?d``` catches "Password5555".

Mode 7: Just the reverse: ```hashcat -a 7 -m 1000 ntlm.txt ?d?d?d?d list.txt``` catches "5555Password".

## Key-walk Passwords

[kwprocessor](https://github.com/hashcat/kwprocessor) generates key-walk passwords based on adjacent keys. kwprocessor has three main components:

* Base characters - the alphabet of the target language.
* Keymaps - the keyboard layout.
* Routes - the directions to walk in.

Many examples in the basechars, keymaps and routes directory in the kwprocessor download. Example: ```kwp64 basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o keywalk.txt```

De-duplicate the list before using for best efficiency. This wordlist can then be used like any other dictionary in hashcat.

