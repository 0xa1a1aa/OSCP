# Nmap

## TCP

Scan for open TCP ports:
```bash
sudo nmap -Pn -p- -T4 -oN tcp_ports.nmap <ip>
```
Results:
```bash

```

Enumerate services:
```bash
sudo nmap -v -Pn -p $(cat tcp_ports.nmap | grep -Eo '([0-9]{1,5})/tcp' | awk -F '/' '{print $1}' | paste -sd ',') -sV -sC -oA tcp_services <ip>
```
Results:
```bash

```

## UDP

Scan for open UDP ports:
```bash
sudo nmap -Pn -sU -oN udp_default.nmap <ip>
```
Results:
```bash

```