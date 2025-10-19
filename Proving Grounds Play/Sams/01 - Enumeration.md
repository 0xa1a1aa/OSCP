# Nmap

Scan for open ports:
```bash
IP=192.168.229.248
nmap -Pn -p- -oN tcp_all.nmap $IP
```
Results:
```bash
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
445/tcp  open  microsoft-ds
3306/tcp open  mysql
7680/tcp open  pando-pub
```

Enumerate services:
```bash
sudo nmap -v -Pn -p $(cat tcp_ports.nmap | grep -Eo '([0-9]{1,5})/tcp' | awk -F '/' '{print $1}' | paste -sd ',') -sV -sC -oA tcp_services $IP
```
Results:
```bash
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/7.3.29)
|_http-title: Sam Elliot | Web Designer
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/7.3.29
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
443/tcp  open  ssl/http      Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/7.3.29)
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/7.3.29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-title: Sam Elliot | Web Designer
445/tcp  open  microsoft-ds?
3306/tcp open  mysql         MariaDB 10.3.24 or later (unauthorized)
7680/tcp open  pando-pub?
```

# HTTP/80,443

```
Server: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/7.3.29
```
CVE-2021-40438: not vulnerable

Username?
```
Sam Elliot
```

gobuster
```bash
gobuster dir -u http://192.168.229.248/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -f                                                                                             1 ↵
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.229.248/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 305]
/assets/              (Status: 200) [Size: 1608]
/webalizer/           (Status: 403) [Size: 424]
/phpmyadmin/          (Status: 403) [Size: 424]
/testing/             (Status: 200) [Size: 70]
/icons/               (Status: 200) [Size: 74798]
/examples/            (Status: 503) [Size: 405]
/vendor/              (Status: 200) [Size: 1199]
/licenses/            (Status: 403) [Size: 424]
/server-status/       (Status: 403) [Size: 424]
/con/                 (Status: 403) [Size: 305]
/aux/                 (Status: 403) [Size: 305]
/error_log/          (Status: 403) [Size: 305]
/prn/                 (Status: 403) [Size: 305]
/server-info/         (Status: 403) [Size: 424]
Progress: 26583 / 26583 (100.00%)
```

To further directory brute-force _/testing/_ we need to use ffuf to filter invalid responses, as gobuster has no option to filter responses by a string:
```bash
ffuf -u http://192.168.229.248/testing/FUZZ/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -fr "There is no website configured at this address"

# install                 [Status: 200, Size: 86195, Words: 29371, Lines: 1236, 
```

URI `/testing/install`:
![[Pasted image 20251018224144.png]]
From the Changelog looks like version 2.2.6

```bash
searchsploit schlix 2.2.6
# Schlix CMS 2.2.6-6 - 'title' Persistent Cross-Site Scripting (Authenticated)      | multiple/webapps/49837.txt
# Schlix CMS 2.2.6-6 - Arbitary File Upload (Authenticated)                         | multiple/webapps/49897.txt
# Schlix CMS 2.2.6-6 - Remote Code Execution (Authenticated)                        | multiple/webapps/49838.txt
```

LUL offsec Lab is broken, there should be a /testing/admin url....

# SMB/445

```bash
smbclient -N -L \\\\192.168.229.248\\

# session setup failed: NT_STATUS_ACCESS_DENIED
```

```bash
enum4linux-ng -A 192.168.229.248

# NetBIOS computer name: SAMS-PC

# [+] After merging OS information we have the following result:
# OS: Windows 10, Windows Server 2019, Windows Server 2016                       # OS version: '10.0'
# OS release: '2004'
# OS build: '19041'
```

# MySQL/3306

```bash
mysql -h 192.168.229.248 --user=anonymous

# ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.184' is not allowed to connect to this MariaDB server
```