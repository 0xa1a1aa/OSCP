# VM01

**Initial foothold:**
1. Given credentials

**PrivEsc:**
1. Add and execute action "reverse shell" via the "Application Manager" service => SYSTEM
2. Mimikatz => era\apache credentials (username, password)
3. Alternative: `C:\Users\Administrator\AppData\Local\Microsoft\"Remote Desktop Connection Manager"\RDCMan.settings` contains also the credentials for apache

# VM02

**Initial foothold:**
1) era\apache (from VM01)

**PrivEsc:**
1. administrator password in file: `C:\xampp\tmp\sess_4ratl05q4mpc92ib7bga2imgr9`
2. or local port 1337 is a listening SYSTEM SHELL
3. Port forward 3306
4. Access it via kali with user `root` w/o pw. It contains  the credentials for the user `charlotte`
5. Password spray `charlotte`'s credentials

# DC

**Initial foothold:**
1. Evil-winrm as charlotte

**PrivEsc:**
1. SeImpersonatePrivileges => PrintSpoofer exploit