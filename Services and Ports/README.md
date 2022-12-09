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


SMB - Samba - 445/all
---------------------

Samba is a free and open-source implementation of the SMB/CIFS network protocol. It allows file and printer sharing between Linux and Windows machines.

A smb server can have multiple **shares** (~partition) with their own permissions. They can be listed with `smbmap` or `enum4linux` and accessed with `smbclient`.

* [`smbmap`](https://github.com/ShawnDEvans/smbmap)

	Emumerate SMB shares and their permissions.


List shares as anonymous user:
```
smbmap -H <ip> -u anonymous
```

Logged in as a user:
```
smbmap -H 10.10.10.125 -u <user> -p <password>
```

List recursively everything on the server.
```
smbmap -H 10.10.10.125 -u <user> -p <password> -r
```

The `-d` option specifies a domain. For exemple with the `localhost` domain (useful when NO_LOGON_SERVERS is returned)
```
smbmap -H 10.10.10.125 -u <user> -d localhost
```

* `enum4linux`

	Enumerate SMB shares and their permissions.

```
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





