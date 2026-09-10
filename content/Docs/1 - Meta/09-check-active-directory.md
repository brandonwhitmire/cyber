+++
title = "09 - Check - Active Directory"
+++

# **SYNC CLOCK DC**

{{< embed-section page="Docs/7 - Lateral Movement/active-directory" header="sync-clock" expanded=true >}}

1. [ ] **RUN [BLOODHOUND]({{% ref "bloodhound.md" %}})** and mark everything owned
    - Run both **SharpHound** and **RustHound**
    - **REPEAT** for each new domain user for new paths

---

### Enumeration - WITHOUT Creds

#### User Identification

1. [ ] Grab all users by an [SMB Null Session against the DC with netexec]({{% ref "netexec.md#enumerate-users" %}})

2. [ ] Attempt an [anonymous LDAP search against the domain controller to grab all users]({{% ref "netexec.md#anonymous-ldap-search" %}})

3. [ ] Try [RID Brute-forcing]({{% ref "netexec.md#enumerate-users" %}}) for discovering users with SID/RID brute forcing.

4. [ ] Brute-force [usernames with wordlists via AS-REP Roasting]({{% ref "netexec.md#asreproast" %}})

### Enumeration - WITH Creds Enumeration

#### Host Identification

1. [ ] Use [ldapdomaindump]({{% ref "active-directory.md#ad-enumeration" %}}) to identify all domain-joined computers.

2. [ ] Enumerate accessible [shares on servers with NetExec]({{% ref "netexec.md#shares-enumeration" %}})

#### User Identification

1. [ ] Gather the [domain password policy using the discovered credentials]({{% ref "netexec.md#basic-enumeration" %}})

2. [ ] Use the discovered credentials and a tool like [NetExec]({{% ref "netexec.md" %}}) to get all users, groups, and logged-on users against the server you have credentials for (ultimate goal is DC)

3. [ ] Gather a list of `Domain Admins` or privileged users using the following tools via [BloodHound]({{% ref "bloodhound.md#analysis-and-queries" %}})

#### On Foothold Enumeration

1. [ ] [Dump any credentials with Mimikatz]({{% ref "mimikatz-post-exploit.md" %}})

2. [ ] Look at owned users for abusable [ACL entries]({{% ref "active-directory.md" %}}) (`ForceChangePassword`, `AddMember`, `GenericAll`, etc.). Easiest to do in [BloodHound]({{% ref "bloodhound.md#enumerating-acls-of-user" %}})

3. [ ] Check GPO from DC for passwords with [Group3r]({{% ref "active-directory.md#group3r-group-policy" %}})

### Exploitation

1. [ ] Kerberos attack chain in order:
        - **[ASREPRoasting]({{% ref "netexec.md#asreproast" %}}) (w/o creds)**: only need usernames. Users with `DONT_REQ_PREAUTH` hand you a crackable TGT hash
        - **[ASREPRoasting (credentialed)]({{% ref "netexec.md#asreproast" %}}) again (w/ creds)**: authenticated enum finds accounts anonymous enum misses.
        - **[NetExec Kerberoast]({{% ref "netexec.md#kerberoast" %}}) (Linux) or [Rubeus]({{% ref "active-directory.md" %}}) (Windows) (w/ creds)**: any domain user can request TGS tickets for SPNs

2. [ ] Check for [Group Policy Preferences (GPP) Passwords]({{% ref "netexec.md#gpp_password" %}}) in SYSVOL

3. [ ] [Abuse any over-permissive ACL entries to gain control of more users and move laterally.]({{% ref "active-directory.md#access-control-list-acl" %}})

4. [ ] Check [BloodHound]({{% ref "bloodhound.md" %}}) for [CanRDP]({{% ref "bloodhound.md#canrdp" %}}), [CanPSRemote]({{% ref "bloodhound.md#canpsremote" %}}), or [SQLAdmin]({{% ref "bloodhound.md#sqladmin" %}}) abilities to move laterally. Abuse these rights and look for sensitive info on the new machines

5. [ ] Use obtained NTLM hashes or Kerberos tickets to move laterally.
    - [Pass the Hash (PtH)]({{% ref "pass-the-hash.md" %}})
    - [Pass the Ticket (PtT)]({{% ref "active-directory.md#pass-the-ticket-ptt" %}})
    - [OverPass the Hash / Pass the Key]({{% ref "active-directory.md#pass-the-key-ptk-overpass-the-hash-oth" %}})

6. [ ] Check for common vulnerabilities and misconfigurations to escalate privileges or move laterally:
    - [Zerologon (CVE-2020-1472)]({{% ref "active-directory.md#zerologon-cve-2020-1472" %}})
    - [NoPac (SAMAccountName Spoofing)]({{% ref "active-directory.md#nopac-samaccountname-spoofing" %}})
    - [PetitPotam (NTLM Coercion)]({{% ref "active-directory.md#petitpotam-ntlm-coercion" %}})
    - [DFSCoerce (NTLM Coercion)]({{% ref "active-directory.md#dfscoerce-ntlm-coercion" %}})
    - [ShadowCoerce (NTLM Coercion)]({{% ref "active-directory.md#shadowcoerce-ntlm-coercion" %}})
    - [EternalBlue (MS17-010)]({{% ref "active-directory.md#eternalblue-ms17-010" %}})
    - [PrintNightmare]({{% ref "privilege-escalation-windows.md#roguepotato-godpotato-printspoofer-printnightmare" %}})
    - [Exchange group permissions]({{% ref "active-directory.md#exchange-privilege-escalation" %}})
    - [MS-RPRN Printer bug]({{% ref "active-directory.md#printer-bug-enumeration-spooler-service" %}})
    - Sniff for LDAP credentials
    - Enumerate DNS records for interesting servers
    - [Check for DONT_REQ_PREAUTH field and AS-REP Roast any discovered users]({{% ref "netexec.md#asreproast" %}})
    - Check for GPOs that we have write access over (can be checked with [BloodHound]({{% ref "bloodhound.md" %}}))
    - Resource Based Constrained Delegation, Constrained Delegation, Unconstrained Delegation

7. [ ] Pillage for credentials and sensitive information across hosts and shares.
    - [Look for passwords in AD user description fields]({{% ref "active-directory.md#user-attributes-mining" %}})
    - [Check for PASSWD_NOTREQD accounts -- test for weak or blank passwords]({{% ref "active-directory.md#user-attributes-mining" %}})
    - Search accessible SMB shares with [Snaffler]({{% ref "finding-creds.md#snaffler" %}}) or [LaZagne]({{% ref "finding-creds.md#lazange" %}})

#### Attacking AD Trusts (Parent Domain)

1. [ ] Discover any current domain trusts with other domains using `Get-ADTrust`, `Get-DomainTrust` ([PowerView]({{% ref "powerview.md#domain-trust-enumeration" %}})), or [BloodHound]({{% ref "bloodhound.md" %}}).

2. [ ] From a Windows or Linux machine with Domain Admin privileges, attempt an [ExtraSIDs attack]({{% ref "active-directory.md#abusing-access-between-domain-trusts" %}}) to create an Enterprise Admin user in the parent domain.

3. [ ] [Domain Trusts Overview]({{% ref "active-directory.md" %}})

4. [ ] Child -> Parents Attacks
    - [Child -> Parent Attacks - Windows]({{% ref "active-directory.md" %}})
    - [ ] [Child -> Parent Attacks - Linux]({{% ref "active-directory.md" %}})

#### Attacking AD Trusts (Cross Forest)

1. [ ] Discover any current domain trusts with other domains using `Get-ADTrust`, `Get-DomainTrust` ([PowerView]({{% ref "powerview.md#domain-trust-enumeration" %}})), or [BloodHound]({{% ref "bloodhound.md" %}}).

2. [ ] Attempt [cross-forest Kerberoasting]({{% ref "netexec.md#kerberoast" %}}).

3. [ ] If admin accounts share names across domains and one is compromised, try reused credentials.

4. [ ] Check for SIDHistory abuse from domain migration

5. [ ] Cross-Forest Attacks
    - [Cross-Forest Trust Abuse - Windows]({{% ref "active-directory.md" %}})
    - [Cross-Forest Trust Abuse - Linux]({{% ref "active-directory.md" %}})
