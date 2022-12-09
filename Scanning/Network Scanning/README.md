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

* [Nmap scripts](https://nmap.org/nsedoc/scripts/)
  
  `nmap` has a lot of scripts that can be used to scan for specific vulnerabilities. They are called with the `--script` option.

Run all dns scripts
```
nmap -sV --script dns-* <ip>
```

* [`traceroute`](https://en.wikipedia.org/wiki/Traceroute)

    See the path packets take to reach a host.