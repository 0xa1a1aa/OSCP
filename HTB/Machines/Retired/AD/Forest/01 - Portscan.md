# Nmap

## TCP

```bash
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-12-03 10:12:15Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49682/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
52776/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-12-03T02:13:08-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2025-12-03T10:13:04
|_  start_date: 2025-12-03T10:06:24
|_clock-skew: mean: 2h47m39s, deviation: 4h37m11s, median: 7m37s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

## UDP

```bash
PORT      STATE         SERVICE
53/udp    open          domain
88/udp    open          kerberos-sec
123/udp   open          ntp
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
389/udp   open|filtered ldap
464/udp   open|filtered kpasswd5
500/udp   open|filtered isakmp
989/udp   open|filtered ftps-data
1025/udp  open|filtered blackjack
1761/udp  open|filtered cft-0
2161/udp  open|filtered apc-2161
4500/udp  open|filtered nat-t-ike
5353/udp  open|filtered zeroconf
5355/udp  open|filtered llmnr
17605/udp open|filtered unknown
17629/udp open|filtered unknown
17673/udp open|filtered unknown
19482/udp open|filtered unknown
20129/udp open|filtered unknown
26966/udp open|filtered unknown
41524/udp open|filtered unknown
48455/udp open|filtered unknown
49161/udp open|filtered unknown
54711/udp open|filtered unknown
54807/udp open|filtered unknown
54925/udp open|filtered unknown
55043/udp open|filtered unknown
55544/udp open|filtered unknown
55587/udp open|filtered unknown
56141/udp open|filtered unknown
```