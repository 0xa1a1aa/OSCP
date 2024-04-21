**Initial foothold:**
1) HTTP directory brute-forcing
2) Upload PHP reverse-shell

**PrivEsc:**
1) Enumerate users (/etc/passwd)
2) Search for "password" keywords in files
3) Found password for MySQL database
4) Password reused for one of the enumerated users
5) That user was allowed to run sudo w/o password