**Initial foothold:**
1)  Directory brute-forcing => wordpress site
2) wpscan: Wordpress Plugin RCE exploit available
3) shell as www-data

**PrivEsc:**
1) 2 users: user1 has ssh private key file we can read. => access as user1
2) user1 can sudo a command as user2 => access as user2
3) user2 can sudo a (non-existing) script as root. Create script and spawn root shell