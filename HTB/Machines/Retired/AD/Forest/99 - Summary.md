**Initial foothold:**
1) LDAP queries allowed w/o AD user creds
2) AS-REP Roasting => User creds

**PrivEsc:**
1) BloodHound with User creds
2) User is member of the group "Account Operators", which has GenericAll on the group "Exchange Windows Permissions", which in return has WriteDacl on the Domain
3) => Create new user for "Exchange Windows Permissions"
4) Add DCSync permissions to the new user via PowerView
5) Dump all credentials of the domain via the new user