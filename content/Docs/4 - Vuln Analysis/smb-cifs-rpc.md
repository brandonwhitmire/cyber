+++
title = "🌐 SMB/CIFS/RPC: TCP 135/139/445"
+++

* `TCP 135`: RPC Endpoint Mapper (EPM)
* `UDP 137`: NetBIOS Name Service
* `UDP 138`: NetBIOS Datagram Service
* `TCP 139`: NetBIOS Session Service (SMB over NetBIOS, legacy)
* `TCP 445`: SMB direct (SMB2/3, no NetBIOS)
* Shares:
   * `C$` - default admin share (`C:` drive root)
   * `ADMIN$` - maps to `%SYSTEMROOT%` (usually `C:\Windows`)
   * `IPC$` - inter-process communication (RPC named pipes, enumeration)
   * `PRINT$` - printer drivers
   * `SYSVOL` - domain-wide GPO files (DCs only)
   * `NETLOGON` - logon scripts (DCs only)

## Enumeration

![[netexec#Basic Enumeration]]

![[netexec#User Enumeration]]

## Interactive

- Explanation: https://www.infosecmatter.com/rce-on-windows-from-linux-part-1-impacket/

- **NOTE**: all methods require local Administrator

```bash
# psexec: uploads RemComSvc binary to ADMIN$, creates service, INTERACTIVE shell, runs as SYSTEM
# Ports: 445
impacket-psexec <USER>:<PASS>@<TARGET>

# smbexec: creates temp batch file + service per command, SEMI-INTERACTIVE, no binary uploaded, runs as SYSTEM
# Ports: 445
impacket-smbexec <USER>:<PASS>@<TARGET>

# wmiexec: WMI/DCOM process create, output written to ADMIN$ temp file read back over SMB, SEMI-INTERACTIVE, runs as authenticated user (NOT SYSTEM)
# Ports: 135 + 445 + dynamic high port
impacket-wmiexec <USER>:<PASS>@<TARGET>

# dcomexec: DCOM endpoints (MMC20/ShellWindows/ShellBrowserWindow), SEMI-INTERACTIVE, runs as authenticated user
# Ports: 135 + 445 + dynamic high port
impacket-dcomexec <USER>:<PASS>@<TARGET>

# atexec: scheduled task via Task Scheduler (Atsvc), single command only (NOT interactive), unreliable on modern Windows
# Ports: 445
impacket-atexec <USER>:<PASS>@<TARGET> "<COMMAND>"
```
