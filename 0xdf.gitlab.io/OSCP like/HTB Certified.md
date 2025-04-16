https://0xdf.gitlab.io/2025/03/15/htb-certified.html#
Windows
“assume-breach”: creds for a low priv user given
# Methodology

Initial Foothold:
- Nmap
- identified AD domains: `dc01.certified.htb`, `certified.htb` (add to `/etc/hosts`)
- Check if creds work for SMB: `netexec smb certified.htb -u judith.mader -p judith09` => do work
- Check if creds work for WinRM: `netexec winrm certified.htb -u judith.mader -p judith09` => do not work
- Check SMB shares: `netexec smb dc01.certified.htb --shares` (only standard shares, nothing interesting)
- Use bloodhound (collector: https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce)
- mark "judith.mader" (initial user supplied) as owned
- check "Outbound Object Control" => `WriteOwner` On the Management group
- Management group has`GenericWrite` over the Management_SVC user
- Management_SVC user has `GenericAll` over the CA_Operator user
- “PathFinding” at the top right: enter judith.mader to CA_Operator, it shows the full path
- check for vulnerable certificate templates (Active Directory Certificate Services) with certipy => none
- Use bloodhound suggestions to "modify owner" and set `judith.mader` as the owner of  the Management group
- Use bloodhound suggestions: add rights to "add member" for the Management group
- add judith.mader to the Management group
- get TGT and NT-hash for the management_svc via shadow credentials (certipy)
- check SMB and WinRM access to the machine with the NT-Hash => access granted
- get a shell as "management_svc" user: `evil-winrm -i certified.htb -u management_svc -H <NT-hash>`

PrivEsc:
- check for other users: `ls C:\Users`
- from bloodhound above: management_svc user has `GenericAll` over the CA_Operator user => Shadow Credential again to get the NTLM hash: `certipy shadow auto -username management_svc@certified.htb -hashes :<NT-hash> -account ca_operator -target certified.htb -dc-ip <DC-ip>`
- exploit ESC9