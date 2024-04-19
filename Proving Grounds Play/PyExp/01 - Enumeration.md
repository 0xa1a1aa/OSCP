# Nmap

Scan for open ports:
```bash
nmap -Pn -p- -oN tcp_all.nmap 192.168.206.118
```
Results:
```bash
PORT     STATE SERVICE
1337/tcp open  waste
3306/tcp open  mysql
```

Enumerate services:
```bash
nmap -Pn -p 1337,3306 -sV -sC -oN tcp_services.nmap 192.168.206.118
```

# MySQL

**Version**: MySQL 5.5.5-10.3.23-MariaDB-0+deb10u1 (protocol 10)

## Brute-force password

Hydra user "root":
![[Pasted image 20240417140728.png]]
=> pw: prettywoman

## Connect to DB

```bash
mysql --host=192.168.206.118 --user=root --password=prettywoman
```

Status:
![[Pasted image 20240417141755.png]]

## Show databases

Show databases and tables:
![[Pasted image 20240417142640.png]]
=> database "data" with table "fernet"

Dump table "fernet":
![[Pasted image 20240417142822.png]]

**cred:**
gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys=

**keyy:**
UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0=