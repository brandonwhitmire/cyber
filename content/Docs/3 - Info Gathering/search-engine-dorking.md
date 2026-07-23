+++
title = "Search Engine Dorking"
+++

- https://www.exploit-db.com/google-hacking-database
- Cached Website: https://web.archive.org/

```bash
site:
inurl:
filetype:
intitle:
intext:
inbody:
cache:
link:
related:
info:
define:
numrange:
allintext:
allinurl:
allintitle:

# Operators
AND
OR
NOT
*
..
" "
-
+

### EXAMPLES
# Find Emails
inurl:<DOMAIN> intext:"@<DOMAIN>"

# Finding Login Pages:
site:<DOMAIN> inurl:login
site:<DOMAIN> (inurl:login OR inurl:admin)

# Identifying Exposed Files:
site:<DOMAIN> filetype:pdf
site:<DOMAIN> (filetype:xls OR filetype:docx)
inurl:<DOMAIN> filetype:pdf  # !!! careful this one can show malicious site hosting cached files !!!

# Uncovering Configuration Files:
site:<DOMAIN> inurl:config.php

# (searches for extensions commonly used for configuration files)
site:<DOMAIN> (ext:conf OR ext:cnf)

# Locating Database Backups:
site:<DOMAIN> inurl:backup
site:<DOMAIN> filetype:sql
```
