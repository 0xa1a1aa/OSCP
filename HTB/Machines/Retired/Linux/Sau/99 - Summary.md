**Initial foothold:**
1) Webapp SSRF => access Website on localhost
2) RCE exploit on localhost website => gain shell

**PrivEsc:**
1) Sudo command, invoke pager (less) => start bash => root shell