+++
title = "04 - Check - SMB Enumeration"
+++

### Unauthenticated Enumeration

1. [ ] Attempt **null/anonymous session** (no creds) and list available shares
    - [SMB Anonymous Access & Share Listing]({{% ref "smb-cifs-rpc.md" %}})
    - [Enumerate Shares with NetExec]({{% ref "netexec.md#shares-enumeration" %}})

2. [ ] Run comprehensive unauthenticated enumeration (users, groups, OS info, password policy)
    - [Null Session Enumeration (nxc)]({{% ref "netexec.md#basic-enumeration" %}})

3. [ ] Check SMB security posture -- determine if signing is required
    - Signing disabled on a host = relay candidate; add to relay target list

### Share Content Inspection

4. [ ] Browse accessible shares for sensitive content
    - [SMB Share Access]({{% ref "smb-cifs-rpc.md" %}})
    - Look for scripts, backups, config files, and hardcoded credentials

### NTLM Relay Attack

5. [ ] Generate relay target list (hosts without SMB signing)
    - `nxc smb <SUBNET>/24 --gen-relay-list relay-targets.txt`
    - Empty output: signing enforced everywhere -- stop here
    - Targets found: continue to relay setup

6. [ ] Set up relay infrastructure
    - [Responder -- Active / Relay Mode]({{% ref "protocol-poisoners.md" %}})
    - Disable SMB and HTTP in `Responder.conf` before running
    - Run `impacket-ntlmrelayx` pointed at relay targets alongside Responder

7. [ ] Choose relay action based on target service
    - **SMB exec:** shell/command execution on relay target
    - **LDAP (RBCD or Shadow Credentials):** delegate access or add key credential
    - **HTTP/CA (ADCS ESC8):** [relay to certificate authority for a machine certificate -> NT hash]({{% ref "active-directory.md#adcs-attack-reference" %}})
