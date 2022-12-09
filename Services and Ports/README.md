Assigned port numbers by IANA can be found at [IANA Port Numbers](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml). But other services can also run on these ports.




FTP - File Transfer Protocol - 21/tcp
-------------------------------------

Transfer files between a client and server.
The anonymous credentials are anonymous:anonymous.

Connect to a server
```bash
ftp <ip> <port>  
```

Enumerate anonymous logins
```bash
nmap -v -p 21 --script=ftp-anon.nse <ip>
```


SSH - Secure Shell - 22/tcp
---------------------------

Securely connect to a remote server.

Connect to a server
```bash
ssh <user>@<ip> -p <port>
```

Local port forwarding
```bash
ssh -L <local_port>:<remote_host>:<remote_port> <user>@<ip> 
```

Transfer files
```bash
scp <file> <user>@<ip>:<path> # Local to remote
scp <user>@<ip>:<path> <file> # Remote to local
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

See [Web](../Web/README.md) for more information.


POP3 - Post Office Protocol - 110/all
-------------------------------------

POP3 is used to retrieve emails from a server.


SMB - Samba - 445/tcp
---------------------

* [`smbmap`](https://github.com/ShawnDEvans/smbmap)

	`smbmap` tells you permissions and access, which `smbclient` does _not_ do!

	To try and list shares as the anonymous user **DO THIS** (this doesn't always work for some weird reason)

```
smbmap -H 10.10.10.125 -u anonymous
```

Or you can attempt just:

```
smbmap -H 10.10.10.125
```

And you can specify a domain like so:

```
smbmap -H 10.10.10.125 -u anonymous -d HTB.LOCAL
```

Worth trying `localhost` as a domain, if that gets "NO_LOGON_SERVERS"

```
smbmap -H 10.10.10.125 -u anonymous -d localhost
```

* `enum4linux`


```
enum4linux 10.10.10.125
```

* `smbclient`

	**NOTE: DEPENDING ON THE VERSION OF SMBCLIENT YOU ARE USING, you may need to SPECIFY the use of S<B version 1 or SMB version 2. You can dp this with `-m SMB2`. Older versions of SMBclient (latest being 4.10 at the time of writing) use SMB1 _by default_.**

	You can use `smbclient` to look through files shared with SMB. To _list_ available shares:

```
smbclient -m SMB2 -N -L //10.10.10.125/
```

Once you find a share you want to/can access, you can connect to shares by using the name following the locator:

```
smbclient -m SMB2 -N //10.10.10.125/Reports
```

You will see a `smb: \>` prompt, and you can use `ls` and `get` to retrieve files or even `put` if you need to place files there.

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





