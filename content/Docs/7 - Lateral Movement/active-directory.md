+++
title = "Active Directory"
+++

# Sync Clock

```bash
# Linux
sudo ntpdate <DC_IP>

# Per app run
sudo apt install -y faketime
faketime <DC_TIME> <COMMAND>

# Windows
net.exe time /domain /set /y
```

- https://notes.dollarboysushil.com/active-directory-attacks
- AD Cheatsheet: https://wadcoms.github.io/
    - Filter by info currently known and by attack type like enumeration, exploitation, etc.
- https://adsecurity.org/

# Authentication Protocol Selection

| Method | Authentication Protocol | Encryption | Limitations |
| :----- | :--------------------- | :--------- | :---------- |
| **IP Address** (e.g., `192.168.1.10`) | **NTLM** | RC4, NTLMv2 | No Kerberos support, may be blocked by policies, more logging/alerting |
| **Hostname/FQDN** (e.g., `DC01.cooldomaininc.local`) | **Kerberos** (TGT/TGS) | AES-128, AES-256, RC4 | Requires DNS resolution, subject to Kerberos delegation restrictions (Double Hop problem) |

# Domain Enumeration

|          | DC Port Cheatsheet |                                                                         |
| -------- | ------------------ | ----------------------------------------------------------------------- |
| Port     | Service            | Role / Why it identifies a DC                                           |
| **53**   | **DNS**            | Almost all DCs run DNS (AD Integrated DNS).                             |
| **88**   | **Kerberos**       | **The Smoking Gun.** Only KDCs (Domain Controllers) listen here.        |
| **389**  | **LDAP**           | Directory Access. Essential for AD.                                     |
| **445**  | **SMB**            | Required for **SYSVOL** (Group Policy) replication.                     |
| **636**  | **LDAPS**          | Secure LDAP (Indicates a Certificate is installed).                     |
| **3268** | **Global Catalog** | **High Fidelity.** Indicates the server has a full index of the Forest. |
| **3269** | **GC SSL**         | Secure Global Catalog.                                                  |

```bash
sudo nmap -n -Pn -p 53,88,389,445,636,3268,3269 --open -oA dc_hunt.txt -v <TARGET>
```

{{< embed-section page="Docs/7 - Lateral Movement/Lateral Movement" header="network-info" >}}

# AD Enumeration

{{< embed-section page="Docs/9 - Notes/bloodhound" header="bloodhound" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-user-enumeration" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-getting-access-credentials" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-acl" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-escalating-pivoting" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-adcs" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-kerberos-delegation" >}}

# Mitigation

## Inventory

- `Naming conventions of OUs, computers, users, groups`
- `DNS, network, and DHCP configurations`
- `An intimate understanding of all GPOs and the objects that they are applied to`
- `Assignment of FSMO roles`
- `Full and current application inventory`
- `A list of all enterprise hosts and their location`
- `Any trust relationships we have with other domains or outside entities`
- `Users who have elevated permissions`

## Prevention

### Technology

- Run tools such as 5d, PingCastle, and Grouper periodically to identify AD misconfigurations.
- Ensure that administrators are not storing passwords in the AD account description field.
- Review SYSVOL for scripts containing passwords and other sensitive data.
- Avoid the use of "normal" service accounts, utilizing Group Managed (gMSA) and Managed Service Accounts (MSA) where ever possible to mitigate the risk of Kerberoasting.
- Disable Unconstrained Delegation wherever possible.
- Prevent direct access to Domain Controllers through the use of hardened jump hosts.
- Consider setting the `ms-DS-MachineAccountQuota` attribute to `0`, which disallows users from adding machine accounts and can prevent several attacks such as the noPac attack and Resource-Based Constrained Delegation (RBCD)
- Disable the print spooler service wherever possible to prevent several attacks
- Disable NTLM authentication for Domain Controllers if possible
- Use Extended Protection for Authentication along with enabling Require SSL only to allow HTTPS connections for the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services
- Enable SMB signing and LDAP signing
- Take steps to prevent enumeration with tools like BloodHound
- Ideally, perform quarterly penetration tests/AD security assessments, but if budget constraints exist, these should be performed annually at the very least.
- Test backups for validity and review/practice disaster recovery plans.
- Enable the restriction of anonymous access and prevent null session enumeration by setting the `RestrictNullSessAccess` registry key to `1` to restrict null session access to unauthenticated users.

### People

- The organization should have a strong password policy, with a password filter that disallows the use of common words (i.e., welcome, password, names of months/days/seasons, and the company name). If possible, an enterprise password manager should be used to assist users with choosing and using complex passwords.
- Rotate passwords periodically for **all** service accounts.
- Disallow local administrator access on user workstations unless a specific business need exists.
- Disable the default `RID-500 local admin` account and create a new admin account for administration subject to LAPS password rotation.
- Implement split tiers of administration for administrative users. Too often, during an assessment, you will gain access to Domain Administrator credentials on a computer that an administrator uses for all work activities.
- Clean up privileged groups. `Does the organization need 50+ Domain/Enterprise Admins?` Restrict group membership in highly privileged groups to only those users who require this access to perform their day-to-day system administrator duties.
- Disable Kerberos delegation for administrative accounts (the Protected Users group may not do this)
- Where appropriate, place accounts in the `Protected Users` group.
    - https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

```powershell
# Viewing the Protected Users Group (ADSI)
$root = [ADSI]"LDAP://RootDSE"
$defaultNC = $root.defaultNamingContext.Value
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNC")
$searcher.Filter = "(&(objectCategory=group)(samAccountName=Protected Users))"
$searcher.PropertiesToLoad.Add("name") | Out-Null
$searcher.PropertiesToLoad.Add("description") | Out-Null
$searcher.PropertiesToLoad.Add("member") | Out-Null
$searcher.FindOne() | ForEach-Object { $_.Properties }
```

# Reporting and Auditing

### PingCastle

**Role:** Generates a "Health Check" report based on a maturity model. Bridges the gap between technical findings and C-Level risk scores.
**OPSEC:** Moderate. Generates significant LDAP traffic but looks like admin activity.

```cmd
# Interactive Mode (Best for first run)
PingCastle.exe

# Healthcheck Report (Non-Interactive)
# Generates an HTML report in the current directory
PingCastle.exe --healthcheck --server <DC_FQDN>

# Scan specific risk areas (Scanner Mode)
# Options: aclcheck, antivirus, localadmin, laps_bitlocker, etc.
PingCastle.exe --scanner aclcheck
```

### Active Directory Explorer (Sysinternals)

**Role:** Creates (and mounts) snapshots of the AD Database for offline analysis.
**Attack Vector:** If you find `.dat` snapshot files on shares, you can mount them to browse AD as it was at that time *without* alerting the DC.

```cmd
# Create a Snapshot (Requires Creds)
# -snapshot: Create a snapshot
# "" : Prompt for password
ADExplorer.exe -snapshot "" <DC_FQDN> output_filename

# Mount a Snapshot (Offline Analysis)
# Allows you to browse a .dat file found on a share
ADExplorer.exe -snapshot "" <PATH_TO_DAT_FILE>
```

### Group3r

**Role:** Deep-dive auditing of **Group Policy Objects (GPOs)**. Unlike standard tools that check permissions, this parses the *content* of GPOs to find hardcoded passwords, local admin deployments, and script definitions.

```cmd
# Basic Scan (Output to Console)
group3r.exe -s

# Full Scan (Output to File)
# -f: Output file path
group3r.exe -f results.log
```

### ADRecon

**Role:** Extracts *everything* from the domain (Users, Computers, GPOs, DNS, LAPS, BitLocker) and compiles it into a massive Excel report.
**OPSEC:** 💀 **EXTREMELY LOUD.** Do not use during a Red Team engagement unless you have burned the environment or are simulating an "Ignorant Insider."

```powershell
# Run Audit (Requires Excel installed for pretty reports, otherwise CSV)
.\ADRecon.ps1

# Run on specific target Domain Controller
.\ADRecon.ps1 -DomainController <DC_IP>

# Generate Excel report from CSVs (Run offline on analyst machine)
.\ADRecon.ps1 -GenExcel <PATH_TO_CSV_FOLDER>
```
