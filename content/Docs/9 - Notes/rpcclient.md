+++
title = "rpcclient"
+++

- https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
- https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf

All session commands can run non-interactively with `-c "command"` for piping/redirecting:

```bash
rpcclient -U '<USER>%<PASSWORD>' <TARGET> -c "enumdomusers" > users.txt
```

## Connecting

```bash
# Null session
rpcclient -U "" -N <TARGET>

# Authenticated
rpcclient -U '<USER>%<PASSWORD>' <TARGET>
```

## Enumeration

### Users and Groups

```bash
# Interactive session commands
enumdomusers                    # all domain users
enumalsgroups domain            # domain groups
enumalsgroups builtin           # local system groups
queryuser <RID>                 # user info by RID
lookupnames <USERNAME>          # resolve username to SID
enumprivs                       # privileges assigned to current user

# Non-interactive: user list pipeline
rpcclient -U '<USER>%<PASSWORD>' -c 'enumdomusers;quit' <TARGET> | tee rpcclient_log
grep -o 'user:\[[^]]*\]' rpcclient_log | cut -d '[' -f2 | cut -d ']' -f1 > domain_users.txt
```

### Domain and Shares

```bash
srvinfo                         # server info and OS version
enumdomains                     # all domains
querydominfo                    # domain, server, user info
netshareenumall                 # list all shares
netsharegetinfo <SHARE>         # share details
```

## Password Policy

```bash
getdompwinfo                    # domain-wide password policy
getusrdompwinfo <RID>           # password settings for a specific user RID
querydominfo                    # also includes basic policy summary
```

## Modify

### Force Change Password

Requires `ForceChangePassword` or `ForceChangePassword` ACL on the target user or Domain Admin rights:

```bash
rpcclient -U '<DOMAIN>/<USER>%<PASSWORD>' <DC_IP> -c 'setuserinfo2 <USER_TO_CHANGE> 23 <NEW_PASSWORD>'
```

### Change Password

Must know old password

```bash
rpcclient -U '<USER>%<PASSWORD>' <TARGET> -c "chgpasswd3 <USERNAME> '<OLDPASS>' '<NEWPASS>'"
```

### Create User

Create new user and set its password

```bash
rpcclient -U '<USER>%<PASSWORD>' <TARGET> -c "createdomuser <USERNAME>"
rpcclient -U '<USER>%<PASSWORD>' <TARGET> -c "setuserinfo2 <USERNAME> 24 '<PASSWORD>'"
```

### Add User to Group

```bash
net rpc group addmem "<TO_GROUP>" "<USER_TO_ADD>" -U "<DOMAIN>/<USER>%<PASSWORD>" -S <DC>
```

### Create Share

```bash
rpcclient -U '<USER>%<PASSWORD>' <TARGET> -c 'netshareadd "C:\Windows" "Windows" 10 "Windows Share"'
```
