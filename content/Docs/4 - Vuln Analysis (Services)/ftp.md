+++
title = "FTP"
+++

- `TCP 20`: data transfer
    - Active: Client->Server
    - Passive: Server->Client
- `TCP 21`: control channel
- Server Config: `/etc/vsftpd.conf`
    - http://vsftpd.beasts.org/vsftpd_conf.html
- DISALLOWED FTP users: `/etc/ftpusers`

- Commands: https://web.archive.org/web/20230326204635/https://www.smartfile.com/blog/the-ultimate-ftp-commands-list/
- Server Return Codes: https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes

**TFTP has no auth and uses only UDP.

{{% details "Dangerous Settings" %}}

| **Setting**                    | **Description**                                                                    |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| `anonymous_enable=YES`         | Allowing anonymous login?                                                          |
| `anon_upload_enable=YES`       | Allowing anonymous to upload files?                                                |
| `anon_mkdir_write_enable=YES`  | Allowing anonymous to create new directories?                                      |
| `no_anon_password=YES`         | Do not ask anonymous for password?                                                 |
| `anon_root=/home/username/ftp` | Directory for anonymous.                                                           |
| `write_enable=YES`             | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |
{{% /details %}}

```bash
# Connect to FTP server in passive mode with anonymous login
# Username: anonymous
# Password: (no password required)
ftp -p -a <TARGET>
ftp -p ftp://<USER>:<PASS>@<TARGET>

# Turn off passive mode
passive

# List files and directories
ls -la
ls -laR

# Read file
get <FILENAME> -
# Download file
get <FILENAME>
# Upload file
put <FILENAME>
# Download ALL files
mkdir ftp_files
wget -m --no-passive-ftp ftp://anonymous:anonymous@<TARGET>

# Execute local commands (outside of session)
!<COMMAND>
```
