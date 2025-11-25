**Initial foothold:**
1) Robots.txt => /wordpress/
2) Wordpress login: `admin:admin`
3) Edit 404.php page and add PHP reverse shell code
4) Access 404.php to spawn a shell

**PrivEsc:**
1) Upload and execute LinPEAS => found MySQL creds
2) Login to MySQL and dump wordpress user creds
3) Cracked Hashes with crackstation
4) SSH login with cracked password
5) User has sudo all privs => Get root shell via `su`