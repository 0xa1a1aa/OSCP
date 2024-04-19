# Nmap

## TCP

Scan for open TCP ports:
```bash
nmap -Pn -p- -oN tcp_all.nmap <ip>
```
Results:
```bash

```

Enumerate services:
```bash
nmap -Pn -p  -sV -sC -oN tcp_services.nmap <ip>
```

## UDP

Scan for open UDP ports:
```bash
sudo nmap -Pn -sU -oN udp_default.nmap <ip>
```
Results:
```bash

```