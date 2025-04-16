https://0xdf.gitlab.io/2024/10/19/htb-editorial.html
Linux

# Methodology

Initial Foothold:
- Nmap
- Port 80 website
- File upload has SSRF vulnerability
- Brute-Force request all local ports on 127.0.0.1 => port 5000 has api
- API endpoint reveals user creds

PrivEsc:
- no sudo privs `sudo -l`
- no interesting groups `id`
- 2 users: `/etc/passwd` or home folder
- hidden GIT directory in home folder
- git commits show the creds for the other user: `git status`, `git log --oneline`, `git diff 1e84a03 b73481b`
- SSH into the box as the other user "prod"
- "prod" user can run a python script as root `sudo -l`
- Check version of python git library: `pip freeze | grep -i git`
- Search for known vuln => CVE-2022-24439
- exploit to get root shell