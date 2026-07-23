+++
title = "🌐 SMB/CIFS/RPC: TCP 135/139/445"
+++

SMB/CIFS/RPC: TCP 135/139/445

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

{{% details "Dangerous Settings" %}}

|**Setting**|**Description**|
|---|---|
|`browseable = yes`|Allow listing available shares in the current share?|
|`read only = no`|Forbid the creation and modification of files?|
|`writable = yes`|Allow users to create and modify files?|
|`guest ok = yes`|Allow connecting to the service without using a password?|
|`enable privileges = yes`|Honor privileges assigned to specific SID?|
|`create mask = 0777`|What permissions must be assigned to the newly created files?|
|`directory mask = 0777`|What permissions must be assigned to the newly created directories?|
|`logon script = script.sh`|What script needs to be executed on the user's login?|
|`magic script = script.sh`|Which script should be executed when the script gets closed?|
|`magic output = script.out`|Where the output of the magic script needs to be stored?|
{{% /details %}}

- https://hacktricks.wiki/en/network-services-pentesting/pentesting-rpcbind.html

## Enumeration (nxc)

{{< embed-section page="Docs/9 - Notes/netexec" header="basic-enumeration" >}}

{{< embed-section page="Docs/9 - Notes/netexec" header="user-enumeration" >}}

{{< embed-section page="Docs/9 - Notes/netexec" header="shares-enumeration" >}}

## RPC (rpcclient)

{{< embed-section page="Docs/9 - Notes/rpcclient" header="connecting" >}}

{{< embed-section page="Docs/9 - Notes/rpcclient" header="enumeration" >}}
