Nmap:
```
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r-- 1 ftp ftp             44 Jan 08  2021 flag.txt
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
111/tcp   open  rpcbind      2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   172.16.1.5:1433: 
|     Target_Name: DANTE-SQL01
|     NetBIOS_Domain_Name: DANTE-SQL01
|     NetBIOS_Computer_Name: DANTE-SQL01
|     DNS_Domain_Name: DANTE-SQL01
|     DNS_Computer_Name: DANTE-SQL01
|_    Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-25T03:29:27
| Not valid after:  2055-11-25T03:29:27
| MD5:   07b9:4829:ac2f:cc17:5460:0429:710a:8494
|_SHA-1: 573a:21ec:bcf9:2332:a604:2bd0:0d45:5da0:1b6f:9e63
| ms-sql-info: 
|   172.16.1.5:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-11-25T22:41:03+00:00; +44s from scanner time.
2049/tcp  open  nlockmgr     1-4 (RPC #100021)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49673/tcp open  ms-sql-s     Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   172.16.1.5:49673: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49673
| ms-sql-ntlm-info: 
|   172.16.1.5:49673: 
|     Target_Name: DANTE-SQL01
|     NetBIOS_Domain_Name: DANTE-SQL01
|     NetBIOS_Computer_Name: DANTE-SQL01
|     DNS_Domain_Name: DANTE-SQL01
|     DNS_Computer_Name: DANTE-SQL01
|_    Product_Version: 10.0.14393
|_ssl-date: 2025-11-25T22:41:03+00:00; +44s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-25T03:29:27
| Not valid after:  2055-11-25T03:29:27
| MD5:   07b9:4829:ac2f:cc17:5460:0429:710a:8494
|_SHA-1: 573a:21ec:bcf9:2332:a604:2bd0:0d45:5da0:1b6f:9e63
49678/tcp open  msrpc        Microsoft Windows RPC
49679/tcp open  msrpc        Microsoft Windows RPC
49680/tcp open  msrpc        Microsoft Windows RPC
```

# FTP

Flag: FTP login with `anonymous:anonymous`:
```bash
proxychains ftp anonymous@172.16.1.5
# anonymous

get flag.txt
# DANTE{Ther3s_M0r3_to_pwn_so_k33p_searching!}
```

# NFS

Any exported NFS shares?
```bash
showmount -e 172.16.1.5
# Export list for 172.16.1.5:
```
=> nope

# MSSQL 

Brute force default creds (https://raw.githubusercontent.com/gauravnarwani97/MsSQL-default-credentials/refs/heads/master/default_db_credentials1.txt).

MSSQL Port 1433:
```bash
while IFS= read -r creds; do
	echo "==============================="
	echo "Creds: $creds"
	proxychains impacket-mssqlclient $creds@172.16.1.5
done < default_db_credentials1.txt | tee mssql_p1433.brute.txt
```
=> nothing

MSSQL Port 49673:
```bash
while IFS= read -r creds; do
	echo "==============================="
	echo "Creds: $creds"
	proxychains impacket-mssqlclient $creds@172.16.1.5 -port 49673
done < default_db_credentials1.txt | tee mssql_p49673.brute.txt
```
=> nothing


# RPC

Enumerate RPC services:
```bash
impacket-rpcdump 172.16.1.5 | tee rpc_services.txt
```

Enumerate OP nums of services:

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49664]' -uuid D95AFE70-A6D5-4259-822E-2C84DA1DDB0D -brute-opnums

# Protocol: [MS-RSP]: Remote Shutdown Protocol
# Provider: wininit.exe
# UUID: D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0
# Opnums 0-64: rpc_s_access_denied
```

```bash
impacket-rpcmap 'ncacn_np:172.16.1.5[\PIPE\InitShutdown]' -uuid 76F226C3-EC14-4325-8A99-6A46348418AF -brute-opnums

# [-] Protocol failed: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```

```bash
impacket-rpcmap 'ncacn_np:172.16.1.5[\pipe\LSM_API_service]' -uuid 9B008953-F195-4BF9-BDE0-4471971E58ED -brute-opnums

# [-] Protocol failed: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49665]' -uuid D09BDEB5-6171-4A34-BFE2-06FA82652568 -brute-opnums

# Procotol: N/A
# Provider: N/A
# UUID: D09BDEB5-6171-4A34-BFE2-06FA82652568 v1.0
# Opnums 0-64: rpc_s_access_denied
```

```bash
impacket-rpcmap 'ncacn_np:172.16.1.5[\pipe\LSM_API_service]' -uuid 697DCDA9-3BA9-4EB2-9247-E11F1901B0D2 -brute-opnums

# [-] Protocol failed: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```

Skipping `ncacn_np` bindings since they require SMB creds...

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49665]' -uuid A500D4C6-0DD1-4543-BC0C-D5F93486EAF8 -brute-opnums

# Procotol: N/A
# Provider: N/A
# UUID: A500D4C6-0DD1-4543-BC0C-D5F93486EAF8 v1.0
# Opnums 0-64: rpc_s_access_denied
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49665]' -uuid 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D6 -brute-opnums

# Procotol: N/A
# Provider: dhcpcsvc6.dll
# UUID: 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D6 v1.0
# Opnums 0-64: rpc_s_access_denied
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49665]' -uuid 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D5 -brute-opnums

# Procotol: N/A
# Provider: dhcpcsvc.dll
# UUID: 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D5 v1.0
# Opnums 0-64: rpc_s_access_denied
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49665]' -uuid F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C -brute-opnums

# Protocol: [MS-EVEN6]: EventLog Remoting Protocol
# Provider: wevtsvc.dll
# UUID: F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C v1.0
# Opnums 0-64: rpc_s_access_denied
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49677]' -uuid C49A5A70-8A7F-4E70-BA16-1E8F1F193EF1 -brute-opnums

# [-] Protocol failed: Could not connect: [Errno 111] Connection refused
```
=> FW blocking?

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49677]' -uuid C36BE077-E14B-4FE9-8ABC-E856EF4F048B -brute-opnums

# [-] Protocol failed: Could not connect: [Errno 111] Connection refused
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49677]' -uuid 2E6035B2-E8F1-41A7-A044-656B439C4C34 -brute-opnums

# [-] Protocol failed: Could not connect: [Errno 111] Connection refused
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49677]' -uuid 552D076A-CB29-4E44-8B6A-D15E59E2C0AF -brute-opnums 

# [-] Protocol failed: Could not connect: [Errno 111] Connection refused
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49677]' -uuid 0D3C7F20-1C8D-4654-A1B3-51563B298BDA -brute-opnums

# [-] Protocol failed: Could not connect: [Errno 111] Connection refused
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49677]' -uuid A398E520-D59A-4BDD-AA7A-3C1E0303A511 -brute-opnums 

# [-] Protocol failed: Could not connect: [Errno 111] Connection refused
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49677]' -uuid B18FBAB6-56F8-4702-84E0-41053293A869 -brute-opnums

# [-] Protocol failed: Could not connect: [Errno 111] Connection refused
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49677]' -uuid 3A9EF155-691D-4449-8D05-09AD57031823 -brute-opnums 

# [-] Protocol failed: Could not connect: [Errno 111] Connection refused
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49677]' -uuid 86D35949-83C9-4044-B424-DB363231FD0C -brute-opnums

# [-] Protocol failed: Could not connect: [Errno 111] Connection refused
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49666]' -uuid 76F03F96-CDFD-44FC-A22C-64950A001209 -brute-opnums

# [*] Tested 1 UUID(s)
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49666]' -uuid 4A452661-8290-4B36-8FBE-7F4093A94978 -brute-opnums

# [*] Tested 1 UUID(s)
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49666]' -uuid AE33069B-A2A8-46EE-A235-DDFD339BE281 -brute-opnums

# [*] Tested 1 UUID(s)
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49666]' -uuid 0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1 -brute-opnums

# [*] Tested 1 UUID(s)
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49666]' -uuid 12345678-1234-ABCD-EF00-0123456789AB -brute-opnums

# [*] Tested 1 UUID(s)
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49680]' -uuid 12345778-1234-ABCD-EF00-0123456789AC -brute-opnums

# Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol
# Provider: samsrv.dll
# UUID: 12345778-1234-ABCD-EF00-0123456789AC v1.0
# Opnums 0-64: rpc_s_access_denied

# [*] Tested 1 UUID(s)
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49678]' -uuid 6B5BDD1E-528C-422C-AF8C-A4079BE4FE48 -brute-opnums

# Protocol: [MS-FASP]: Firewall and Advanced Security Protocol
# Provider: FwRemoteSvr.dll
# UUID: 6B5BDD1E-528C-422C-AF8C-A4079BE4FE48 v1.0
# Opnums 0-64: rpc_s_access_denied

# [*] Tested 1 UUID(s)
```

```bash
impacket-rpcmap 'ncacn_ip_tcp:172.16.1.5[49679]' -uuid 367ABB81-9844-35F1-AD32-98F038001003 -brute-opnums

# [*] Tested 1 UUID(s)
```

Gave up... come back later