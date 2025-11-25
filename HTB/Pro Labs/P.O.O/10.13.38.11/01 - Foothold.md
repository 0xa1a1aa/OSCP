# Nmap

```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.2056.00; RTM+
|_ssl-date: 2025-11-23T20:14:52+00:00; +3s from scanner time.
| ms-sql-ntlm-info: 
|   10.13.38.11:1433: 
|     Target_Name: POO
|     NetBIOS_Domain_Name: POO
|     NetBIOS_Computer_Name: COMPATIBILITY
|     DNS_Domain_Name: intranet.poo
|     DNS_Computer_Name: COMPATIBILITY.intranet.poo
|     DNS_Tree_Name: intranet.poo
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-23T03:06:02
| Not valid after:  2055-11-23T03:06:02
| MD5:   2cc3:fccd:d5c8:dbf5:c2da:c964:0fb6:6523
|_SHA-1: b2ab:67b4:d4ce:25e7:54d6:add2:3ce8:0694:9f5c:c26a
| ms-sql-info: 
|   10.13.38.11:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM+
|       number: 14.00.2056.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: true
|_    TCP port: 1433
```
=> AD domain: `intranet.poo`
=> DNS Host name: `compatibility.intranet.poo`

UDP:
```bash
sudo nmap -v -Pn -sU -T4 -oN udp_ports.nmap compatibility.intranet.poo
```
=> no open ports

---
# HTTP / 80

DNS Name from Nmap MSSQL entry. Add to `/etc/hosts`:
```
10.13.38.11 compatibility.intranet.poo
```

Default IIS webpage:
```
http://compatibility.intranet.poo/
```

## Dir brute

Feroxbuster:
```bash
feroxbuster -u http://compatibility.intranet.poo/ -o feroxbuster_p80.txt
```
=> 401: `/admin`

Basic auth `/admin` :
![[Pasted image 20251123212212.png]]

Brute force Basic Auth:
```bash
hydra -I -e nsr -l admin -P /usr/share/wordlists/rockyou.txt "http-get://compatibility.intranet.poo/admin:A=BASIC:F=401"
```
=> nothing (tried users: "poo", "admin", "administrator")


Gobuster quick sweep:
```bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://compatibility.intranet.poo/ -f
# /ADMIN/               (Status: 401) [Size: 1293]
# /Admin/               (Status: 401) [Size: 1293]
# /admin/               (Status: 401) [Size: 1293]
# /dev/                 (Status: 403) [Size: 1233]
# /images/              (Status: 403) [Size: 1233]
# /Images/              (Status: 403) [Size: 1233]
# /js/                  (Status: 403) [Size: 1233]
# /meta-inf/            (Status: 403) [Size: 1233]
# /META-INF/            (Status: 403) [Size: 1233]
# /plugins/             (Status: 403) [Size: 1233]
# /templates/           (Status: 403) [Size: 1233]
# /themes/              (Status: 403) [Size: 1233]
# /Themes/              (Status: 403) [Size: 1233]
# /uploads/             (Status: 403) [Size: 1233]
# /widgets/             (Status: 403) [Size: 1233]
```

## VHost fuzzing

```bash
ffuf -H "Host: FUZZ.intranet.poo" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.13.38.11 -fs 703

ffuf -H "Host: FUZZ" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.13.38.11 -fs 703
```
=> nothing

## Nikto

```bash
nikto --url http://compatibility.intranet.poo/
```

Results:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.13.38.11
+ Target Hostname:    compatibility.intranet.poo
+ Target Port:        80
+ Start Time:         2025-11-23 23:01:21 (GMT1)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ /.DS_Store: Apache on Mac OSX will serve the .DS_Store file, which contains sensitive information. Configure Apache to ignore this file or upgrade to a newer version. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-1446
+ 7825 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2025-11-23 23:10:48 (GMT1) (567 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
=> File: `/.DS_Store`

---
# MSSQL / 1433

```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 -oN mssql_p1433.nmap compatibility.intranet.poo
```
=> nothing new

Default creds:
```bash
# Try default creds
impacket-mssqlclient sa@compatibility.intranet.poo
# Password123
```
=> Nope

Brute force:
```bash
hydra -I -e nsr -l sa -P /usr/share/wordlists/rockyou.txt compatibility.intranet.poo mssql -t2 -vv
```
=> had to abort, its to slow..