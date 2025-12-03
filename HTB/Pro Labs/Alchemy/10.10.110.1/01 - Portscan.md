# Nmap

## TCP

```bash
22/tcp  open  ssh      OpenSSH 9.4 (protocol 2.0)
443/tcp open  ssl/http nginx
| ssl-cert: Subject: commonName=pfSense-646b882d43d57/organizationName=pfSense webConfigurator Self-Signed Certificate
| Subject Alternative Name: DNS:pfSense-646b882d43d57
| Issuer: commonName=pfSense-646b882d43d57/organizationName=pfSense webConfigurator Self-Signed Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-22T15:20:13
| Not valid after:  2024-06-23T15:20:13
| MD5:   7c6e:3748:c644:e528:8196:4921:d7e5:b016
|_SHA-1: da89:813a:b794:d147:01c0:1e50:cbc2:8746:117f:831b
|_http-title: pfSense - Login
```

## UDP

```bash

```