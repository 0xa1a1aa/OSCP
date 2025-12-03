# HTTP / 80

```
http://10.10.110.21/
```

![[Pasted image 20251201135915.png]]

## Enum

Usernames:
```bash
# New member (bartender)
Jim

# Owner? "My hippie mate Sef"
Sef
```

Email format:
```
masterclass@sogard.htb
```

Git? (Possibly a hint for port 3000):
```
Insight of this new codebase, a new Git platform is being added if you would like access to it. Please email gitaccess@alchemy.htb
```

## Dir brute

```bash
feroxbuster -u http://10.10.110.21/ --insecure -o p80.ferox
```

```bash
cat p80.ferox| grep "http://10.10.110.21" | awk -F " " '{print $1 " " $6}'

500 http://10.10.110.21/admin
200 http://10.10.110.21/assets/images/content/booze/menu-icon2.png
200 http://10.10.110.21/assets/images/content/booze/author.png
200 http://10.10.110.21/assets/js/gmaps/init.js
200 http://10.10.110.21/assets/form/js/form.js
200 http://10.10.110.21/assets/js/age-ver.js
200 http://10.10.110.21/contact
200 http://10.10.110.21/assets/images/content/booze/watch-icon.png
200 http://10.10.110.21/assets/css/booze.css
200 http://10.10.110.21/assets/images/content/booze/menu-icon1.png
200 http://10.10.110.21/assets/images/content/booze/menu-icon2-colored.png
200 http://10.10.110.21/blog/2
200 http://10.10.110.21/assets/js/jquery.gray.min.js
200 http://10.10.110.21/login
200 http://10.10.110.21/assets/images/content/booze/blog2.jpg
200 http://10.10.110.21/assets/css/font-awesome.min.css
200 http://10.10.110.21/assets/images/content/booze/menu-icon1-colored.png
200 http://10.10.110.21/assets/js/main.js
200 http://10.10.110.21/assets/js/respond.min.js
200 http://10.10.110.21/assets/images/content/booze/icon-office-pin.png
200 http://10.10.110.21/masterclass
200 http://10.10.110.21/blog/3
200 http://10.10.110.21/assets/images/content/booze/scroller.png
200 http://10.10.110.21/events
200 http://10.10.110.21/assets/js/html5shiv.min.js
200 http://10.10.110.21/assets/js/es5-shim.min.js
200 http://10.10.110.21/assets/images/content/booze/blog3.jpg
200 http://10.10.110.21/store
200 http://10.10.110.21/assets/images/content/booze/blog1.jpg
200 http://10.10.110.21/blog/1
200 http://10.10.110.21/assets/js/gmaps/gmap3.min.js
200 http://10.10.110.21/assets/images/content/booze/main-picture2.jpg
200 http://10.10.110.21/assets/images/content/booze/big-intro.png
200 http://10.10.110.21/assets/images/content/booze/logo.png
200 http://10.10.110.21/assets/images/content/booze/drinks.jpg
200 http://10.10.110.21/menu
200 http://10.10.110.21/assets/images/content/booze/slide1.jpg
200 http://10.10.110.21/assets/css/bootstrap.min.css
200 http://10.10.110.21/assets/images/content/booze/logo-footer.png
200 http://10.10.110.21/assets/css/style.css
200 http://10.10.110.21/assets/images/1886667.jpg
200 http://10.10.110.21/status
200 http://10.10.110.21/assets/js/booze.min.js
200 http://10.10.110.21/
200 http://10.10.110.21/assets/images/content/booze/parallax.png
200 http://10.10.110.21/assets/images/content/booze/parallax2.png
```

## `/login`: employee login

Interesting parameter `ldapuri`:
```http
POST /login HTTP/1.1
Host: 10.10.110.21

username=Jim&password=Jim&ldapuri=ldap%3A%2F%2F172.16.0.2%3A389&email_subject=Login+Form
```

---
# HTTP / 3000

```
http://10.10.110.21:3000/
```

![[Pasted image 20251201135844.png]]

## Dir brute

```bash
feroxbuster -u http://10.10.110.21:3000/ --insecure -o p3000.ferox
```

```bash
cat p3000.ferox| grep "http://10.10.110.21" | awk -F " " '{print $1 " " $6}'

302 http://10.10.110.21:3000/admin
302 http://10.10.110.21:3000/js
302 http://10.10.110.21:3000/img
302 http://10.10.110.21:3000/css
302 http://10.10.110.21:3000/plugins
200 http://10.10.110.21:3000/js/libs/emojify-1.1.0.min.js
200 http://10.10.110.21:3000/js/libs/jquery.are-you-sure.js
200 http://10.10.110.21:3000/assets/octicons-4.3.0/octicons.min.css
200 http://10.10.110.21:3000/assets/librejs/librejs.html
200 http://10.10.110.21:3000/js/libs/clipboard-2.0.4.min.js
404 http://10.10.110.21:3000/assets/font-awesome-4.6.3/css/
200 http://10.10.110.21:3000/explore/repos
302 http://10.10.110.21:3000/explore/
200 http://10.10.110.21:3000/user/login
200 http://10.10.110.21:3000/img/gogs-hero.png
200 http://10.10.110.21:3000/assets/font-awesome-4.6.3/css/font-awesome.min.css
302 http://10.10.110.21:3000/assets
200 http://10.10.110.21:3000/img/favicon.png
200 http://10.10.110.21:3000/css/gogs.min.css
200 http://10.10.110.21:3000/js/gogs.js
200 http://10.10.110.21:3000/js/jquery-3.6.0.min.js
404 http://10.10.110.21:3000/css/css/themes
302 http://10.10.110.21:3000/css/themes
200 http://10.10.110.21:3000/js/semantic-2.4.2.min.js
200 http://10.10.110.21:3000/css/semantic-2.4.2.min.css
200 http://10.10.110.21:3000/
302 http://10.10.110.21:3000/avatars
200 http://10.10.110.21:3000/debug/pprof
200 http://10.10.110.21:3000/debug/profile
200 http://10.10.110.21:3000/debug
302 http://10.10.110.21:3000/js/libs
302 http://10.10.110.21:3000/css/themes/default
302 http://10.10.110.21:3000/css/themes/settings
302 http://10.10.110.21:3000/css/themes/default/assets
200 http://10.10.110.21:3000/debug/
302 http://10.10.110.21:3000/js/libs/settings
200 http://10.10.110.21:3000/avatars/1
200 http://10.10.110.21:3000/avatars/2
200 http://10.10.110.21:3000/avatars/3
302 http://10.10.110.21:3000/issues
200 http://10.10.110.21:3000/avatars/4
302 http://10.10.110.21:3000/explore
200 http://10.10.110.21:3000/healthcheck
302 http://10.10.110.21:3000/img/emoji
302 http://10.10.110.21:3000/img/emoji/settings
```

## `/admin`

![[Pasted image 20251201144704.png]]

Users:
![[Pasted image 20251201144818.png]]
- calde
- calde_ldap
- aepike


MSF RCE module:
```bash
msf > search gogs

# exploit/multi/http/gogs_git_hooks_rce   2020-10-07       excellent  Yes    Gogs Git Hooks 
```
