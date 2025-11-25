**Initial foothold:**
1) Robots.txt => reveals URI for blog website
2) Blog uses WordPress => wpscan vulnerable plugins => LFI exploit
3) Use LFI exploit to read local usernames
4) Brute force SSH with usernames (hydra -e nsr)

**PrivEsc:**
1) LinPEAS - Search credentials: `/home/JKanode/.bash_history:sshpass -p JZQuyIN5 peter@localhost`
2) SSH with creds => user can run all cmds as sudo w/o password 