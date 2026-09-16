+++
title = "09 - Check - Active Directory"
+++

# **SYNC CLOCK DC**

![[active-directory#Sync Clock]]

1. [ ] **RUN [BLOODHOUND]({{% ref "bloodhound.md" %}})** and mark everything owned
    - Run both **SharpHound** and **RustHound**
    - **REPEAT** for each new domain user for new paths

---

### Enumeration - WITHOUT Creds

#### User Identification

1. [ ] Grab all users by an [SMB Null Session against the DC with netexec]({{% ref "netexec.md#basic-enumeration" %}})

2. [ ] Attempt an [anonymous LDAP search against the domain controller to grab all users]({{% ref "netexec.md#anonymous-ldap-search" %}})

3. [ ] Try [RID Brute-forcing]({{% ref "netexec.md#basic-enumeration" %}}) for discovering users with SID/RID brute forcing.

4. [ ] Brute-force [usernames with wordlists via AS-REP Roasting]({{% ref "netexec.md#asreproast" %}})

### Exploitation

1. [ ] Kerberos attack chain in order:

- **[ASREPRoasting]({{% ref "netexec.md#asreproast" %}}) (w/o creds)**: only need usernames. Users with `DONT_REQ_PREAUTH` hand you a crackable TGT hash
- **[ASREPRoasting (credentialed)]({{% ref "netexec.md#asreproast" %}}) again (w/ creds)**: authenticated enum finds accounts anonymous enum misses.
- **[NetExec Kerberoast]({{% ref "netexec.md#kerberoast" %}}) (Linux) or [Rubeus]({{% ref "active-directory.md" %}}) (Windows) (w/ creds)**: any domain user can request TGS tickets for SPNs

2. [ ] Check for passwords in GPO:
- [Group Policy Preferences (GPP) Passwords]({{% ref "netexec.md#gpp_password-and-gpp_autologin" %}}) in SYSVOL
- GPO from DC for passwords with [Group3r]({{% ref "active-directory.md#group3r-group-policy" %}})

3. [ ] [Abuse any over-permissive ACL entries to gain control of more users and move laterally.]({{% ref "active-directory-acl.md#access-control-list-acl" %}})

4. [ ] Check [BloodHound]({{% ref "bloodhound.md" %}}) for [CanRDP]({{% ref "bloodhound.md#canrdp" %}}), [CanPSRemote]({{% ref "bloodhound.md#canpsremote" %}}), or [SQLAdmin]({{% ref "bloodhound.md#sqladmin" %}}) abilities to move laterally. Abuse these rights and look for sensitive info on the new machines

5. [ ] Use obtained NTLM hashes or Kerberos tickets to move laterally.
    - [Pass the Hash (PtH)]({{% ref "pass-the-hash.md" %}})
    - [Pass the Ticket (PtT)]({{% ref "active-directory.md#pass-the-ticket-ptt" %}})
    - [OverPass the Hash / Pass the Key]({{% ref "active-directory.md#pass-the-key-ptk-overpass-the-hash-oth" %}})

6. [ ] Check for common vulnerabilities and misconfigurations to escalate privileges or move laterally:
    - [Scan the DC: Zerologon, NoPac, PrintNightmare, EternalBlue, and coercion (PetitPotam/DFSCoerce/ShadowCoerce/Printerbug)]({{% ref "netexec.md#dc-vulnerability-scanning" %}})
    - [Exchange group permissions]({{% ref "active-directory-acl.md#exchange-privilege-escalation" %}})
    - [Check for DONT_REQ_PREAUTH field and AS-REP Roast any discovered users]({{% ref "netexec.md#asreproast" %}})
    - Check for GPOs that we have write access over (can be checked with [BloodHound]({{% ref "bloodhound.md" %}}))

7. [ ] Pillage for credentials and sensitive information across hosts and shares.
    - [Look for passwords in AD user description fields]({{% ref "active-directory-acl.md#user-attributes-mining" %}})
    - [Check for PASSWD_NOTREQD accounts -- test for weak or blank passwords]({{% ref "active-directory-acl.md#user-attributes-mining" %}})
    - Search accessible SMB shares with [Snaffler]({{% ref "finding-creds.md#snaffler" %}}) or [LaZagne]({{% ref "finding-creds.md#lazange" %}})

#### Attacking AD Trusts (Parent Domain)

1. [ ] Discover any current domain trusts with other domains using `Get-ADTrust`, `Get-DomainTrust` ([PowerView]({{% ref "powerview.md#domain-trust-enumeration" %}})), or [BloodHound]({{% ref "bloodhound.md" %}}).

2. [ ] From a Windows or Linux machine with Domain Admin privileges, attempt an [ExtraSIDs attack]({{% ref "active-directory.md#abusing-access-between-domain-trusts" %}}) to create an Enterprise Admin user in the parent domain.

3. [ ] [Domain Trusts Overview]({{% ref "active-directory.md" %}})

4. [ ] Child -> Parents Attacks
    - [Child -> Parent Attacks - Windows]({{% ref "active-directory.md" %}})
    - [Child -> Parent Attacks - Linux]({{% ref "active-directory.md" %}})

#### Attacking AD Trusts (Cross Forest)

1. [ ] Discover any current domain trusts with other domains using `Get-ADTrust`, `Get-DomainTrust` ([PowerView]({{% ref "powerview.md#domain-trust-enumeration" %}})), or [BloodHound]({{% ref "bloodhound.md" %}}).

2. [ ] Attempt [cross-forest Kerberoasting]({{% ref "netexec.md#kerberoast" %}}).

3. [ ] If admin accounts share names across domains and one is compromised, try reused credentials.

4. [ ] Check for SIDHistory abuse from domain migration

5. [ ] Cross-Forest Attacks
    - [Cross-Forest Trust Abuse - Windows]({{% ref "active-directory.md" %}})
    - [Cross-Forest Trust Abuse - Linux]({{% ref "active-directory.md" %}})
