**Initial foothold:**
1) AD enum: Kerberoasting -> SPN NTLM hash cracked
2) Used cracked creds to connect to internal machine MSSQL
3) MSSQL command exec to reverse shell

**PrivEsc:**
1) SeImpersonatePrivilege -> PrintSpoofer Exploit -> Reverse Shell as SYSTEM
2) Mimikatz: Domain Admin creds -> GG