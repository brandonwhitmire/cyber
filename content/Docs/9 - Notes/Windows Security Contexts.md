+++
title = "Windows Security Contexts"
+++

**NOTE: AI summary of Windows security contexts edited by hand**

## Quick Decision Tree

```
Land shell
    ↓
whoami /all
    ↓
Check integrity level
    ├── System/High → proceed to post-exploitation (Mimikatz, dump SAM, etc.)
    └── Medium → UAC bypass needed before Mimikatz/sensitive ops
         ↓
Check whoami /priv
    ├── SeImpersonatePrivilege → Potato attack → SYSTEM token
    ├── SeBackupPrivilege → read SAM/SYSTEM hive directly
    └── SeDebugPrivilege (+ High integrity) → Mimikatz sekurlsa works
         ↓
Check icacls on service binaries / scheduled task paths
    └── Writable by your SID → binary hijack privesc
```

## The Two Sides of Every Access Check

```
PROCESS (subject)          vs.          RESOURCE (object)
Access Token                            Security Descriptor
  - Identity (who you are)                - DACL (who can do what)
  - Privileges (what you can bypass)      - SACL (what gets audited)
  - Integrity Level (trust ceiling)       - Integrity Label (minimum level to write)
```

When your process touches a resource, the kernel compares your token against the resource's security descriptor. You need to win BOTH checks.

## (Processes) Access Token

- [_Security Identifier_](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) (SID)
- [_access token_](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [_Mandatory Integrity Control_](https://docs.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [_User Account Control_](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-overview)

### Identity

- User SID + all group SIDs
- Pentest relevance: impersonation/token theft lets you act as a different identity without knowing the password (`token::elevate`, Potato attacks, `ImpersonateLoggedOnUser`).

A thread can also have an impersonation token that provides a different security context meaing the thread interacts with objects on behalf of the impersonation

**Read identity / groups:**
```cmd
:: CMD
whoami /user          :: your SID
whoami /groups        :: all group SIDs + names + flags
whoami /all           :: everything at once (user, groups, privs, integrity)
```
```powershell
# PowerShell
[System.Security.Principal.WindowsIdentity]::GetCurrent()           # full token info
[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups    # group SIDs
```

**High-value groups:**

|Group|Why it matters|
|---|---|
|`BUILTIN\Administrators`|Local admin -- UAC-filtered at Medium, full at High|
|`Domain Admins`|Full domain control -- DA on any machine = game over|
|`Enterprise Admins`|Forest-wide admin -- more powerful than DA|
|`Schema Admins`|Can modify AD schema -- rare but catastrophic if abused|
|`Account Operators`|Can create/modify most AD accounts (not DA/EA) -- useful for backdoors|
|`Backup Operators`|`SeBackupPrivilege` + `SeRestorePrivilege` -- read SAM/SYSTEM hive, own the box|
|`Server Operators`|Can start/stop services, access server shares -- privesc path|
|`Print Operators`|`SeLoadDriverPrivilege` -- load kernel drivers → kernel exploit path|
|`Remote Management Users`|WinRM access -- lateral movement|
|`Remote Desktop Users`|RDP access -- lateral movement|
|`DnsAdmins`|Can load arbitrary DLL into DNS service (runs as SYSTEM) -- classic DA escalation|
|`BUILTIN\Hyper-V Administrators`|Access to VM files -- can read DC VMDK for offline NTDS.dit|
|`Event Log Readers`|Read security logs -- useful for local recon, rare privesc|
|`Group Policy Creator Owners`|Create GPOs -- link to OU for code exec as any user in that OU|

### Privileges

- Named capabilities that bypass normal ACL checks, disabled privs can usually be enabled easily:

**Read privileges:**
```cmd
:: CMD
whoami /priv          :: all privileges + enabled/disabled state
```
```powershell
# PowerShell
whoami /priv          # same -- no native PS equivalent, whoami works in both
# Check a specific process's token privileges (by PID):
Get-Process -Id <PID> | Select-Object Name, Id
# Then use handle.exe or Sysinternals Process Explorer for full token detail
```

|Privilege|Why it matters|
|---|---|
|`SeDebugPrivilege`|Read/write any process memory -- needed for Mimikatz LSASS access|
|`SeImpersonatePrivilege`|Impersonate any token that connects to you -- Potato attacks|
|`SeAssignPrimaryTokenPrivilege`|Assign a token to a new process -- stronger than impersonate|
|`SeBackupPrivilege`|Read any file ignoring ACLs -- SAM/SYSTEM hive theft|
|`SeRestorePrivilege`|Write any file ignoring ACLs|
|`SeLoadDriverPrivilege`|Load kernel drivers -- route to kernel exploits|
|`SeTakeOwnershipPrivilege`|Take ownership of any object|

### Integrity Level (Mandatory Label)

NOTE: **Administrator group** does not run at High by default due to UAC privilege separation. By default, administrator-launched processes run at **Medium** integrity:
- Which processes cannot modify system files or sensitive registry keys

Enforced regardless of permissions and separate from ACLs:

**Read integrity level:**
```cmd
:: CMD -- your current process
whoami /groups | findstr /i "label"

:: A specific process by PID
powershell -c "Get-Process -Id <PID> | Select-Object Name,Id"
```
```powershell
# PowerShell -- your current process integrity label
whoami /groups | Select-String "label"

# Integrity level of a specific process (needs Sysinternals or NtQueryInformationProcess)
# Native PS alternative -- check via token:
$proc = Get-Process -Id <PID>
# No pure-native cmdlet; use whoami for current, icacls/Sysinternal for others
```
```cmd
:: Integrity label on a FILE or FOLDER (resource side):
icacls <FILE>    :: look for "Mandatory Label\..." in output

:: All processes with their integrity via wmic:
wmic process get name,processid,sessionid
```

| Level         | Typical context                                     | Pentest meaning                                                |
| ------------- | --------------------------------------------------- | -------------------------------------------------------------- |
| **Untrusted** | Highly restricted unverified sources                | Rarely used                                                    |
| **Low**       | Sandboxed (browser tabs, IE Protected Mode)         | Very restricted -- escape sandbox first                        |
| **Medium**    | Normal user processes, WinRM shells (even as admin) | Default landing zone -- admin rights exist but filtered by UAC |
| **High**      | Elevated/admin (after UAC prompt, RDP as admin)     | Full admin rights active -- Mimikatz works here                |
| **System**    | LSASS, kernel services, PSExec                      | Top -- unrestricted                                            |

**Access method → typical integrity level:**

| Method                         | Integrity                    |
| ------------------------------ | ---------------------------- |
| Reverse shell via exploit      | Inherits service's token     |
| WinRM / evil-winrm             | Medium (even as local admin) |
| RDP as admin                   | High                         |
| Service / scheduled task shell | High or System               |
| PSExec                         | System                       |

## (Resources) Security Descriptor

On files, registry keys, pipes, processes, tokens themselves -- any securable object.

### DACL (Discretionary ACL)

- List of ACEs: `[Allow/Deny] [SID] [permissions]`
    - "Who can read/write/execute this thing"
- Pentest relevance: writable service binaries, writable registry keys, weak ACLs on scheduled task executables -- classic privesc vectors
- Check with `icacls` / `Get-Acl`

**Read DACL:**
```cmd
:: CMD
icacls <FILE>           :: file/folder ACL
icacls <FILE> :: bulk check, e.g. C:\Windows\System32\*.exe
```
```powershell
# PowerShell
Get-Acl <FILE> | Format-List          # full ACL
(Get-Acl <FILE>).Access               # just the ACE list
Get-Acl <REGKEY> | Format-List   # registry key ACL
```

### SACL (System ACL)

- **Logging configuration only -- does NOT control access.** Despite the name, only defines "if this SID does this operation, write an audit event to the Security log"

**Read SACL:**
```cmd
:: CMD (requires SeSecurityPrivilege -- usually needs admin)
icacls <FILE> /save acl.txt    :: exports ACL including SACL
```
```powershell
# PowerShell (requires admin + SeSecurityPrivilege)
$acl = Get-Acl -Path <FILE> -Audit
$acl.Audit    # shows SACL entries
```

### Integrity Label on resource

- Minimum integrity level required to _write_ to the resource.
- A Medium process cannot write to a High integrity object even if the DACL allows it.

**Read integrity label on a resource:**
```cmd
:: CMD
icacls <FILE>
:: look for line: "Mandatory Label\Medium Mandatory Level:(NW)" etc.
:: NW = no write up (can't write to higher integrity objects)
```
```powershell
# PowerShell -- no native cmdlet; icacls is the native way for resources
icacls <FILE> | Select-String "Mandatory"
```
