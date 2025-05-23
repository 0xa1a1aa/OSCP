Nmap: TCP 22,80

Gobuster:
```
/build => Forbidden
/login
/robots.txt
/mailing
/storage => Forbidden
/up
/upload
/vendor => Forbidden
```

/mailing => gives a error message with some infos
```
PHP 8.2.28 — Laravel 11.30.0
Symfony
=> Only POST request allowed
```

/up
```
http://environment.htb/up/


## Application up

HTTP request received. Response successfully rendered in 32ms.
```

/upload
```
=> Only POST request allowed
```

Searching for vulnerabilities for Laravel 11.30:
- CVE-2024-52301

https://github.com/Nyamort/CVE-2024-52301 explains the vulnerability:
```
http://environment.htb/?--env=local
```
=> Footer changes from
```
environment.htb © 2025 | Production v1.1

to

environment.htb © 2025 | Local v1.1
```

Exploit?
```
https://github.com/nanwinata/CVE-2024-52301/blob/main/exploit.sh
```
=> nope

TODO: Try to set `APP_KEY` via vulnerability and PHP insecure deserialization of session cookie for RCE?