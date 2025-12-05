**Initial foothold:**
1) SMB enum => Found .NET binary
2) Disassemble .NET binary with VSCode ILspy extension => LDAP credentials
3) LDAP enumerate users => user password in "info" attribute 

**PrivEsc:**
1) User is part of group which has "GenericAll" permissions on the DC computer
2) RBCD attack => Get SYSTEM shell on DC