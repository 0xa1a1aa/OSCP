# Nmap

## TCP

Scan for open TCP ports:
```bash
sudo nmap -Pn -p- -T4 -oN tcp_all.nmap 192.168.131.136
```
Results:
```bash
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
389/tcp  open  ldap
443/tcp  open  https
5667/tcp open  unknown
```

Enumerate services:
```bash
sudo nmap -v -Pn -p $(cat tcp_all.nmap | grep -Eo '([0-9]{1,5})/tcp' | awk -F '/' '{print $1}' | paste -sd ',') -sV -sC -oA tcp_services 192.168.131.136
```
Results:
```bash
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b8:8c:40:f6:5f:2a:8b:f7:92:a8:81:4b:bb:59:6d:02 (RSA)
|   256 e7:bb:11:c1:2e:cd:39:91:68:4e:aa:01:f6:de:e6:19 (ECDSA)
|_  256 0f:8e:28:a7:b7:1d:60:bf:a6:2b:dd:a3:6d:d1:4e:a4 (ED25519)
25/tcp   open  smtp       Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-08T17:59:00
| Not valid after:  2030-09-06T17:59:00
| MD5:   e067:1ea3:92c2:ec73:cb21:de0e:73df:cb66
|_SHA-1: e39c:c9b6:c35b:b608:3dd0:cd25:e60f:cb61:6551:da77
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 8E1494DD4BFF0FC523A2E2A15ED59D84
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Nagios XI
|_http-server-header: Apache/2.4.18 (Ubuntu)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=192.168.1.6/organizationName=Nagios Enterprises/stateOrProvinceName=Minnesota/countryName=US
| Issuer: commonName=192.168.1.6/organizationName=Nagios Enterprises/stateOrProvinceName=Minnesota/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-09-08T18:28:08
| Not valid after:  2030-09-06T18:28:08
| MD5:   20f0:951f:8eff:1b69:ef3f:1b1e:fb4c:361f
|_SHA-1: cc40:0ad7:60cf:4959:1c92:d9ab:0f06:106c:18f6:6661
|_http-title: Nagios XI
5667/tcp open  tcpwrapped
```

## UDP

Scan for open UDP ports:
```bash
sudo nmap -Pn -sU -oN udp_default.nmap 192.168.131.136
```
Results:
```bash
All 1000 scanned ports on 192.168.131.136 are in ignored states.
```