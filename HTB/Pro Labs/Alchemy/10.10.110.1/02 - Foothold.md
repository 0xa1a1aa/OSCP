# HTTP / 443

pfsense login portal:
![[Pasted image 20251201133518.png]]

Default creds:
`admin:pfsense`

=> Default creds dont work 

## Dir brute

```bash
feroxbuster -u https://10.10.110.1/ --insecure -o p443.ferox
```
=> aborted

## nikto

```bash
nikto --url https://10.10.110.1/                                                                                                                                                                                                    1 ↵
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.110.1
+ Target Hostname:    10.10.110.1
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /O=pfSense webConfigurator Self-Signed Certificate/CN=pfSense-646b882d43d57
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /O=pfSense webConfigurator Self-Signed Certificate/CN=pfSense-646b882d43d57
+ Start Time:         2025-12-01 13:51:20 (GMT1)
---------------------------------------------------------------------------
+ Server: nginx
+ /EEARbDju.pwd: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: The Content-Encoding header is set to "deflate" which may mean that the server is vulnerable to the BREACH attack. See: http://breachattack.com/
+ Hostname '10.10.110.1' does not match certificate's names: pfSense-646b882d43d57. See: https://cwe.mitre.org/data/definitions/297.html
+ /xmlrpc.php: xmlrpc.php was found.
+ /help.php: A help file was found.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8074 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2025-12-01 14:14:23 (GMT1) (1383 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## `/xmlrpc.php`

https://github.com/chadillac/pfsense_xmlrpc_backdoor

## `/help.php`

this is just the login site?