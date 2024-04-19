Create a python3 script *fernet.py* to decrypt the credentials from the DB:
```python
from cryptography.fernet import Fernet

key = b"UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0="
cipher = Fernet(key)

ciphertext = "gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys="
plaintext = cipher.decrypt(ciphertext).decode('utf-8')

print(plaintext)
```

Output:
```bash
python3 fernet.py 
lucy:wJ9`"Lemdv9[FEw-
```

We can use these creds to login to SSH:
![[Pasted image 20240417144657.png]]

Get user flag:
![[Pasted image 20240417144744.png]]

