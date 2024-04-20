co# Nmap

## TCP

Scan for open TCP ports:
```bash
nmap -Pn -p- -oN tcp_all.nmap 192.168.227.132
```
Results:
```bash
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Enumerate services:
```bash
nmap -Pn -p 22,80 -sV -sC -oN tcp_services.nmap 192.168.227.132
```

## UDP

Scan for open UDP ports:
```bash
nmap -Pn -sU -oN udp_default.nmap 192.168.227.132
```
Results:
No open ports

# HTTP

Gobuster dir brute:
```bash
gobuster dir -u http://192.168.227.132 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
```

![[Pasted image 20240418131650.png]]

/phpmyadmin:
![[Pasted image 20240418131628.png]]
=> PMA_VERSION: 4.6.6deb5
- no known exploits
- default username and password for phpMyAdmin **'root'⁢ and 'password'** dont work

Ffuf password brute force:
```bash
ffuf -request phpmyadmin_login.req -request-proto http -w /usr/share/wordlists/rockyou.txt -fr 'Access denied'
```
=> doesnt work CSRF

Hydra brute force login:
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.227.132 http-post-form "/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1&target=index.php&lang=en&collation_connection=utf8mb4_unicode_ci&token=da22ee837de8b2af0a7b63e080f1ca93:F=Access denied"
```
=> doesnt work CSRF

Nikto:
```bash
nikto -host 192.168.227.132 -usecookies
```
=> nothing interesting

Brute-force login with my script :)
```bash
python3 ~/tools/brute_forge/brute_forge.py -u http://192.168.227.132/phpmyadmin/index.php -l root -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/best110.txt -r phpmyadmin_login.req -t 'token:"(.*?)"' --proxy "http://127.0.0.1:8080" -f "Access denied"
```
=> nothing found

Well-known URIs => nothing found