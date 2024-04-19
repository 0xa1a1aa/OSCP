Check sudo privs:
![[Pasted image 20240417145347.png]]

However, lucy is not allowed to run python2 with sudo:
![[Pasted image 20240417145910.png]]

But we can run *exp.py*:
![[Pasted image 20240417150031.png]]

Providing `import pty; pty.spawn("/bin/sh")` as input we spawn a privileged shell:
![[Pasted image 20240417150230.png]]

Get root flag:
![[Pasted image 20240417150506.png]]