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
# Finding Login Pages:
site:example.com inurl:login
site:example.com (inurl:login OR inurl:admin)
# Identifying Exposed Files:
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:docx)
# Uncovering Configuration Files:
site:example.com inurl:config.php
# (searches for extensions commonly used for configuration files)
site:example.com (ext:conf OR ext:cnf)
# Locating Database Backups:
site:example.com inurl:backup
site:example.com filetype:sql
```
