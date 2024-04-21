# Nmap

## TCP

Scan for open TCP ports:
```bash
nmap -Pn -p- -oN tcp_all.nmap 192.168.226.87
```
Results:
```bash
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Enumerate services:
```bash
nmap -Pn -p 22,80 -sV -sC -oN tcp_services.nmap 192.168.226.87
```

## UDP

Scan for open UDP ports:
```bash
sudo nmap -Pn -sU -oN udp_default.nmap 192.168.226.87
```
Results:
```bash

```

# HTTP

Nikto:
```bash
nikto -host http://192.168.226.87 -usecookies
```
Output:
![[Pasted image 20240421114136.png]]
=> /cgi-bin/test/test.cgi