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
## Enumeration (nxc)

{{< embed-section page="Docs/9 - Notes/netexec" header="basic-enumeration" >}}

{{< embed-section page="Docs/9 - Notes/netexec" header="user-enumeration" >}}

{{< embed-section page="Docs/9 - Notes/netexec" header="shares-enumeration" >}}

## RPC (rpcclient)

{{< embed-section page="Docs/9 - Notes/rpcclient" header="connecting" >}}

{{< embed-section page="Docs/9 - Notes/rpcclient" header="enumeration" >}}
