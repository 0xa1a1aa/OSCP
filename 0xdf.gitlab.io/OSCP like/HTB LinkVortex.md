https://0xdf.gitlab.io/2025/04/12/htb-linkvortex.html#
Linux

# Methodology

Initial Foothold:
- Nmap
- Subdomain enumeration
- Nmap again on subdomains
- => robots.txt, Git repo
- Known CMS
- Analyze HTTP response headers
- Clone Git repo (git-dumper)
- `git status` shows 2 changed files. one is a config file, the other one contains a password
- Password and guessed email `admin@linkvortex.htb` can be used to login to the CMS
- Arbitrary file read exploit available for this CMS version
- Use exploit to read config file (found above) => contains SSH credentials

PrivEsc:
- `sudo -l`: allowed to run a cleanup script with sudo without password
- manual exploit the script (by setting an env variable when running it) to get cmd execution
- get a root shell (cmd = bash)