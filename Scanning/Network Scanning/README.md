* [`nmap`](https://nmap.org/)

    `nmap` is a utility for network discovery.

Classic scan
```	
nmap -sC -sV -O 192.168.0.0/24
```

SYN scan : Only send SYN (faster but no service detection)
```
nmap -sS 192.168.0.0/24
```

* [`traceroute`](https://en.wikipedia.org/wiki/Traceroute)

    See the path packets take to reach a host.