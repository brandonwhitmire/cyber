+++
title = "SMB/CIFS"
+++

- `TCP 135`: RPC Endpoint Mapper (EPM)
- `UDP 137, UDP 138, TPC 139`: legacy (CIFS/SMB1)
- `TCP 445`: RPC/(SMB2/3)
- Shares:
    - `C$` (drive)
    - `ADMIN$` (Windows drive)
    - `IPC$` (RPC)
    - `PRINT$`

{{% details "Dangerous Settings" %}}

|**Setting**|**Description**|
|---|---|
|`browseable = yes`|Allow listing available shares in the current share?|
|`read only = no`|Forbid the creation and modification of files?|
|`writable = yes`|Allow users to create and modify files?|
|`guest ok = yes`|Allow connecting to the service without using a password?|
|`enable privileges = yes`|Honor privileges assigned to specific SID?|
|`create mask = 0777`|What permissions must be assigned to the newly created files?|
|`directory mask = 0777`|What permissions must be assigned to the newly created directories?|
|`logon script = script.sh`|What script needs to be executed on the user's login?|
|`magic script = script.sh`|Which script should be executed when the script gets closed?|
|`magic output = script.out`|Where the output of the magic script needs to be stored?|
{{% /details %}}

```bash
# ANON: List available SMB shares
smbclient -U "" -N --list //<TARGET>/
smbclient -U "guest" -N --list //<TARGET>/

# ANON: Connect to an SMB share
smbclient -U "" -N //<TARGET>/<SHARE>
smbclient -U "guest" -N //<TARGET>/<SHARE>

# Connect to SMB share
smbclient --user=<DOMAIN>/<USERNAME> --password='<PASSWORD>' //<TARGET>/<SHARE>
ls  # List files
more  # read file
get <FILE>  # Download file
recurse  # Toggle directory recursion
# Download recursion
recurse on
prompt off
mget *
# Execute local commands (outside of session)
!<COMMAND>

---

# https://www.netexec.wiki/getting-started/selecting-and-using-a-protocol
# badPwdCount: https://learn.microsoft.com/en-us/windows/win32/adschema/a-badpwdcount
# User and Groups
netexec smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --users
netexec smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --groups

# List shares
netexec smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --shares

# Recursively list files
smbmap -r --depth 3 -r <SHARE> -u <USERNAME> -p <PASSWORD> -H <IP>
# Directories only
smbmap -R <SHARE> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> -H <IP> --dir-only

---

# https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf
# https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html

# RPC
rpcclient -U '<USER>%<PASSWORD' <TARGET>
querydominfo	# Provides domain, server, and user info
enumdomusers  # Enumerates all domain users
srvinfo	 # Server information
enumdomains	 # Enumerate all domains
netshareenumall	 # Enumerates available shares
netsharegetinfo <SHARE>	 # Info about a specific share
queryuser <RID>  # User info

---

# TODO: move these to a more appropriate/relevant section

# Brute-Forcing RIDs via RPC
for i in $(seq 500 1100);do rpcclient -N -U "" <TARGET> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

# Same with other tools
samrdump.py <TARGET>
smbmap -H <TARGET>
```

## enum4linux-ng

enum4linux-ng uses various protocols for enumeration that are outside of the scope here, but for knowledge of the services:

| Tool      | Ports                                             |
| --------- | ------------------------------------------------- |
| nmblookup | 137/UDP                                           |
| nbtstat   | 137/UDP                                           |
| net       | 139/TCP, 135/TCP, TCP and UDP 135 and 49152-65535 |
| rpcclient | 135/TCP                                           |
| smbclient | 445/TCP                                           |

```
# Enumeration SMB/NetBIOS
enum4linux-ng -oA enum4linux-ng-log -A <TARGET>
```
