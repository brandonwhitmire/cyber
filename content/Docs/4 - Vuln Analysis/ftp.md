+++
title = "🌐 FTP: TCP 20/21"
+++

- `TCP 20`: data transfer
    - Active: Client->Server
    - Passive: Server->Client
- `TCP 21`: control channel
- `UDP 69`: TFTP (simple boots or routers)
- Server Config: `/etc/vsftpd.conf`
    - http://vsftpd.beasts.org/vsftpd_conf.html
- DISALLOWED FTP users: `/etc/ftpusers`

- Commands: https://web.archive.org/web/20230326204635/https://www.smartfile.com/blog/the-ultimate-ftp-commands-list/
- Server Return Codes: https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes

```bash
sudo apt install -y lftp
# Download ALL files (anonymous)
mkdir -p ~/my_data/ftp_files && cd ~/my_data/ftp_files
lftp -e "set ssl:verify-certificate no;set ftp:list-options -a; mirror -c; bye" ftp://anonymous:anonymous@<TARGET>
```

```bash
# Normal login
lftp ftp://<USER>:<PASS>@<TARGET>
set ftp:passive-mode off

# Execute local commands (outside of session)
!<COMMAND>

# List files and directories
ls -la
ls -laR

# Read file
get <FILENAME> -
# Download file
get <FILENAME>
# Upload file
put <FILENAME>
# Download all files
mirror .
```