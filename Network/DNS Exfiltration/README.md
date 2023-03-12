DNS can be used to exfiltrate data, for example to bypass firewalls.

* [iodine](https://github.com/yarrick/iodine)

    Can be identifed by the presence of the "Aaahhh-Drink-mal-ein-Jägermeister" or "La flûte naïve française est retirée à Crête".<br>
    Can be decipherd with [this script](../Tools/iodine/exploit.py)<br>
    [Hack.lu CTF WU](http://blog.stalkr.net/2010/10/hacklu-ctf-challenge-9-bottle-writeup.html)

* [DNScat2](https://github.com/iagox86/dnscat2)

    Can be identified when [file signatures](../../Scanning/File%20Scanning/README.md) are present in the DNS queries.
    Data can be extracted with [this script](../Tools/dnscat2/exploit.py) and fies can be extracted with [binwalk](../../Scanning/File%20Scanning/README.md).


