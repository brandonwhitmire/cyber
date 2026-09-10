+++
title = "Active Directory"
+++

- https://adsecurity.org/
# Sync Clock

```bash
# Linux
sudo timedatectl set-ntp false && sudo ntpdate <DC_IP> && date

# Windows
net.exe time /domain /set /y
```

# Authentication Protocol Selection

| Method | Authentication Protocol | Encryption | Limitations |
| :----- | :--------------------- | :--------- | :---------- |
| **IP Address** (e.g., `192.168.1.10`) | **NTLM** | RC4, NTLMv2 | No Kerberos support, may be blocked by policies, more logging/alerting |
| **Hostname/FQDN** (e.g., `DC01.cooldomaininc.local`) | **Kerberos** (TGT/TGS) | AES-128, AES-256, RC4 | Requires DNS resolution, subject to Kerberos delegation restrictions (Double Hop problem) |

# Domain Enumeration

| **Port** | Service            | **Role**                                                                |
| -------- | ------------------ | ----------------------------------------------------------------------- |
| **53**   | **DNS**            | Almost all DCs run DNS (AD Integrated DNS).                             |
| **88**   | **Kerberos**       | **The Smoking Gun.** Only KDCs (Domain Controllers) listen here.        |
| **389**  | **LDAP**           | Directory Access. Essential for AD.                                     |
| **445**  | **SMB**            | Required for **SYSVOL** (Group Policy) replication.                     |
| **636**  | **LDAPS**          | Secure LDAP (Indicates a Certificate is installed).                     |
| **3268** | **Global Catalog** | **High Fidelity.** Indicates the server has a full index of the Forest. |
| **3269** | **GC SSL**         | Secure Global Catalog.                                                  |

```bash
sudo nmap -n -Pn -p 53,88,389,445,636,3268,3269 --open -oA nmap_find_dc.txt -v <TARGET>
```

{{< embed-section page="Docs/7 - Lateral Movement/Lateral Movement" header="network-info" >}}

# AD Enumeration

```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    $result = $DirectorySearcher.FindAll()

    $count = 0
    foreach ($obj in $result) {
        $count++
        Write-Host "`n[Object $count]" -ForegroundColor Cyan
        foreach ($prop in $obj.Properties.PropertyNames | Sort-Object) {
            $val = $obj.Properties[$prop] -join ", "
            Write-Host "  $prop : $val"
        }
    }
    Write-Host "`n[Total: $count objects]" -ForegroundColor Yellow
}
```

```powershell
# Common queries
# all users
LDAPSearch "(samAccountType=805306368)"
# all groups
LDAPSearch "(objectclass=group)"
# all computers
LDAPSearch "(objectclass=computer)"
# all OUs
LDAPSearch "(objectclass=organizationalUnit)"
# admin users
LDAPSearch "(&(objectclass=user)(adminCount=1))"
# kerberoastable users
LDAPSearch "(servicePrincipalName=*)"
```

{{< embed-section page="Docs/9 - Notes/bloodhound" header="bloodhound" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-user-enumeration" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-getting-access-credentials" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-acl" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-escalating-pivoting" >}}

{{< embed-section page="Docs/7 - Lateral Movement/active-directory-kerberos-delegation" >}}

### Group3r (Group Policy)

Deep-dive of GPOs. Unlike standard tools that check permissions, this parses the *content* of GPOs to find hardcoded passwords, local admin deployments, and script definitions

```cmd
# Basic Scan (Output to Console)
group3r.exe -s

# Full Scan (Output to File)
group3r.exe -f results.log
```
