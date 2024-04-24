# Nmap

## TCP

Scan for open TCP ports:
```bash
nmap -Pn -p- -oN tcp_all.nmap 192.168.228.212
```
Results:
```bash
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Enumerate services:
```bash
nmap -Pn -p 22,80 -sV -sC -oN tcp_services.nmap 192.168.228.212
```

## UDP

Scan for open UDP ports:
```bash
sudo nmap -Pn -sU -oN udp_default.nmap 192.168.228.212
```
Results:
```bash
PORT      STATE  SERVICE VERSION
20309/udp closed unknown
```

# HTTP

dir brute-forcing:
![[Pasted image 20240424144349.png]]
/secret/evil.php is an empty file

robots.txt
![[Pasted image 20240424145909.png]]

Server reflects Host header in response:
![[Pasted image 20240424151654.png]]
=> not exploitable

Nikto scan:
![[Pasted image 20240424160249.png]]