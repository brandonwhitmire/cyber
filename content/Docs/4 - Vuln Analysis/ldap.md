+++
title = "🔷 LDAP: TCP 389/636"
+++

* `TCP 389` : unencrypted
* `TCP 636` : encrypted (LDAPS)

LDAP (Lightweight Directory Access Protocol) is the protocol used to query and modify Active Directory: to enumerate users, groups, computers, and other domain objects

**LDAP Format**
```ldap
LDAP://HostName[:PortNumber][/DistinguishedName]
```

**Distinguished Name (DN)**
```ldap
CN=Bobby,CN=Users,DC=corp,DC=com
```

- Common Name (CN): object or container
- Domain Component (DN): top of LDAP tree (usu. domain)

## PowerShell Enumerator

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

### LDAP Queries

The LDAP queries in the quotes can be ran via other methods as well like `netexec ldap --query '<QUERY>'`

```powershell
# All users
LDAPSearch "(samAccountType=805306368)"

# Users With Specific Attributes Set (PASSWD_NOTREQD)
# 1.2.840.113556.1.4.803:=32 means PASSWD_NOTREQD must be set
LDAPSearch "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"

# Kerberoastable users
LDAPSearch "(servicePrincipalName=*)"

# Protected admin accounts
LDAPSearch "(&(objectclass=user)(adminCount=1))"

# Security groups only (equivalent to net group /domain)
LDAPSearch "(&(objectclass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))"

# All groups (more than net group /domain)
LDAPSearch "(objectclass=group)"

# All OUs/containers
LDAPSearch "(objectclass=organizationalUnit)"

# All computers
LDAPSearch "(objectclass=computer)"

# Search DCs in Current Domain
LDAPSearch "(userAccountControl:1.2.840.113556.1.4.803:=8192)"

# Search disabled accounts
LDAPSearch "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(adminCount=1)(description=*))"
```

- https://ldap.com/ldap-oid-reference-guide/

{{< img src="LDAP-OID-UAC-values.png" caption="User Account Control Bit Values" >}}