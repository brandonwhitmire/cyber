+++
title = "09 - Check - Active Directory"
+++

# **SYNC CLOCK DC**

{{< embed-section page="Docs/7 - Lateral Movement/active-directory" header="sync-clock" expanded=true >}}

1. [ ] **RUN [BLOODHOUND]({{% ref "bloodhound.md" %}})** and mark everything owned -- This is the holy grail.
    - Run both **SharpHound** and **RustHound** since they are not exhaustive

---

### Uncredentialed (Initial) Enumeration

#### Host Identification

1. [ ] Start Wireshark or [Responder in Analyze mode]({{% ref "protocol-poisoners.md" %}}) to listen for Layer 2 (ARP, MDNS, NBNS) traffic, discover IP addresses and hostnames, and to discover IP addresses and hostnames.

2. [ ] Perform an [`fping` ICMP sweep]({{% ref "scanning.md#ping-sweep" %}}) to find all hosts on your subnet that respond to an ICMP echo request.

#### User Identification

1. [ ] Create a document for all discovered users.

2. [ ] Grab all users by an [SMB Null Session against the DC with netexec]({{% ref "netexec.md#enumerate-users" %}})

3. [ ] Attempt an [anonymous LDAP search against the domain controller to grab all users]({{% ref "netexec.md#anonymous-ldap-search" %}})

4. [ ] Try [RID Brute-forcing]({{% ref "netexec.md#enumerate-users" %}}) for discovering users with SID/RID brute forcing.

5. [ ] Brute-force [usernames with wordlists via AS-REP Roasting]({{% ref "netexec.md#asreproast" %}})

#### Get User Foothold

1. [ ] Start [Responder/Inveigh]({{% ref "protocol-poisoners.md" %}}) on network interface to listen for NTLM users and hashes. Attempt to crack with Hashcat/John.

2. [ ] Attempt a [password spray]({{% ref "03-check-password-attacks.md" %}}) against all discovered users.

---

### Credentialed Enumeration

#### Host Identification

1. [ ] Use [ldapdomaindump]({{% ref "active-directory.md#ad-enumeration" %}}) to identify all domain-joined computers.

2. [ ] Enumerate accessible [shares on servers with NetExec]({{% ref "netexec.md#shares-enumeration" %}}), PowerView, or Snaffler.

#### User Identification

1. [ ] Gather the [domain password policy using the discovered credentials]({{% ref "netexec.md#basic-enumeration" %}})

2. [ ] Use the discovered credentials and a tool like [NetExec]({{% ref "netexec.md" %}}) to get all users, groups, and logged-on users against the server you have credentials for (ultimate goal is DC).

3. [ ] Gather a list of `Domain Admins` or privileged users using the following tools:
    - [Windapsearch]({{% ref "active-directory.md#ad-enumeration" %}})
    - [PowerView]({{% ref "powerview.md#user-and-group-enumeration" %}})
    - [BloodHound]({{% ref "bloodhound.md#analysis-and-queries" %}})

#### On Foothold Enumeration

1. [ ] Enumerate security controls in place ([Defender]({{% ref "security-products.md#windows-defender" %}}), [AppLocker]({{% ref "security-products.md#applocker" %}}), [PowerShell Constraints]({{% ref "security-products.md#powershell" %}}), [LAPS]({{% ref "security-products.md#local-administrator-password-solution-laps" %}})).

2. [ ] [Dump any credentials with Mimikatz]({{% ref "mimikatz-post-exploit.md" %}}) or Rubeus.

3. [ ] Look for kerberoastable accounts through [NetExec]({{% ref "netexec.md#kerberoast" %}}), [BloodHound]({{% ref "bloodhound.md#analysis-and-queries" %}}), [PowerView]({{% ref "powerview.md#kerberoastable-account-enumeration" %}}), or `GetUserSPNs.py`.

4. [ ] Look at owned users for abusable ACL entries (`ForceChangePassword`, `AddMember`, `GenericAll`, etc.). Easiest to do in [BloodHound]({{% ref "bloodhound.md#enumerating-acls-of-user" %}}).
    - [ACL Enumeration]({{% ref "active-directory.md" %}})

#### Pivoting

1. [ ] Run [sshuttle, chisel, ligolo-ng]({{% ref "lateral-movement.md" %}}) for Windows on the Windows pivot host.
    - [(If needed) ensure proxy is setup]({{% ref "lateral-movement.md#step-0-pre-requisites" %}})

2. [ ] Check AGAIN [BloodHound]({{% ref "bloodhound.md" %}}) for `CanRDP`, `CanPSRemote`, or `SQLAdmin` abilities to move laterally onto other machines.

---

### Exploitation

1. [ ] Kerberos attack chain -- run in order, each step unlocks the next:
    1. [ ] **AS-REP roast (w/o creds)** -- only need usernames. Users with `DONT_REQ_PREAUTH` hand you a crackable TGT hash.
        - [ASREPRoasting]({{% ref "netexec.md#asreproast" %}})
        - Crack with [Hashcat]({{% ref "offline-hash-cracking.md" %}}) -- cracked hash = first domain user
    2. [ ] **AS-REP roast again (w/ creds)** -- authenticated enum finds accounts anonymous enum misses.
        - [ASREPRoasting (credentialed)]({{% ref "netexec.md#asreproast" %}})
    3. [ ] **Kerberoast (w/ creds)** -- any domain user can request TGS tickets for SPN accounts; crack offline.
        - [NetExec LDAP]({{% ref "netexec.md#kerberoast" %}}) or [`GetUserSPNs.py`]({{% ref "active-directory.md#impacket-getuserspns" %}}) (Linux) or [Rubeus]({{% ref "active-directory.md" %}}) (Windows)
        - Crack with [Hashcat]({{% ref "offline-hash-cracking.md" %}}) on a GPU rig

2. [ ] Check for [Group Policy Preferences (GPP) Passwords]({{% ref "netexec.md#gpp_password" %}}) in SYSVOL -- often cleartext credentials.

3. [ ] [Abuse any over-permissive ACL entries to gain control of more users and move laterally.]({{% ref "active-directory.md#access-control-list-acl" %}})

4. [ ] Check for [Active Directory Certificate Services (AD CS) attacks]({{% ref "active-directory.md#adcs-attack-reference" %}}).

5. [ ] Check [BloodHound]({{% ref "bloodhound.md" %}}) for CanRDP, CanPSRemote, or SQLAdmin abilities to move laterally. Abuse these rights and look for sensitive info on the new machines.
    1. [ ] [CanRDP]({{% ref "bloodhound.md#canrdp" %}})
    2. [ ] [CanPSRemote]({{% ref "bloodhound.md#canpsremote" %}})
    3. [ ] [SQLAdmin]({{% ref "bloodhound.md#sqladmin" %}})

6. [ ] Use obtained NTLM hashes or Kerberos tickets to move laterally.
    - [Pass the Hash (PtH)]({{% ref "pass-the-hash.md" %}})
    - [Pass the Ticket (PtT)]({{% ref "active-directory.md#pass-the-ticket-ptt" %}})
    - [OverPass the Hash / Pass the Key]({{% ref "active-directory.md#pass-the-key-ptk-overpass-the-hash-oth" %}})

7. [ ] Check for common vulnerabilities and misconfigurations to escalate privileges or move laterally:
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

8. [ ] Pillage for credentials and sensitive information across hosts and shares.
    - [Look for passwords in AD user description fields]({{% ref "active-directory.md#user-attributes-mining" %}})
    - [Check for PASSWD_NOTREQD accounts -- test for weak or blank passwords]({{% ref "active-directory.md#user-attributes-mining" %}})
    - Search accessible SMB shares with [Snaffler]({{% ref "finding-creds.md#snaffler" %}}) or [LaZagne]({{% ref "finding-creds.md#lazange" %}})

---

### Additional Auditing

1. [ ] Create a snapshot of the AD database with [AD Explorer]({{% ref "active-directory.md#active-directory-explorer-sysinternals" %}}) for offline analysis.

2. [ ] Use [PingCastle]({{% ref "active-directory.md#pingcastle" %}}) to discover additional AD misconfigurations and vulnerabilities.

3. [ ] Run [Group3r]({{% ref "active-directory.md#group3r" %}}) to uncover vulnerabilities in AD Group Policy.

4. [ ] Run [ADRecon.ps1]({{% ref "active-directory.md#adrecon" %}}) to discover additional AD misconfigurations and vulnerabilities that may have been missed.

#### Attacking AD Trusts (Parent Domain)

1. [ ] Discover any current domain trusts with other domains using `Get-ADTrust`, `Get-DomainTrust` ([PowerView]({{% ref "powerview.md#domain-trust-enumeration" %}})), or [BloodHound]({{% ref "bloodhound.md" %}}).

2. [ ] From a Windows or Linux machine with Domain Admin privileges, attempt an [ExtraSIDs attack]({{% ref "active-directory.md#abusing-access-between-domain-trusts" %}}) to create an Enterprise Admin user in the parent domain.

3. [ ] [Domain Trusts Overview]({{% ref "active-directory.md" %}})

4. [ ] [Child -> Parent Attacks - Windows]({{% ref "active-directory.md" %}})

5. [ ] [Child -> Parent Attacks - Linux]({{% ref "active-directory.md" %}})

#### Attacking AD Trusts (Cross Forest)

1. [ ] Discover any current domain trusts with other domains using `Get-ADTrust`, `Get-DomainTrust` ([PowerView]({{% ref "powerview.md#domain-trust-enumeration" %}})), or [BloodHound]({{% ref "bloodhound.md" %}}).

2. [ ] Attempt [cross-forest Kerberoasting]({{% ref "netexec.md#kerberoast" %}}).

3. [ ] If admin accounts share names across domains and one is compromised, try reused credentials.

4. [ ] Check for SIDHistory abuse.

5. [ ] [Cross-Forest Trust Abuse - Windows]({{% ref "active-directory.md" %}})

6. [ ] [Cross-Forest Trust Abuse - Linux]({{% ref "active-directory.md" %}})
