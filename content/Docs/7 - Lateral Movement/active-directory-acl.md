+++
title = "AD: Access Control List (ACL)"
+++

# Access Control List (ACL)

- `ObjectAceType` Permissions: https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights

- `ForceChangePassword` abused with `Set-DomainUserPassword`
- `Add Members` abused with `Add-DomainGroupMember`
- `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `GenericWrite` abused with `Set-DomainObject`
- `WriteOwner` abused with `Set-DomainObjectOwner`
- `WriteDACL` abused with `Add-DomainObjectACL`
- `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `AddSelf` abused with `Add-DomainGroupMember`
- `DS-Replication-Get-Changes-All` to perform a [DCSync attack]({{% ref "netexec.md#ntds-dump" %}})
- `AddKeyCredentialLink` to get user's NTLM Hash

| ACL                                     | Abuse                                                                    | Impact                             |
| --------------------------------------- | ------------------------------------------------------------------------ | ---------------------------------- |
| `DCSync` (`GetChanges`+`GetChangesAll`) | `lsadump::dcsync` / `secretsdump`                                        | Dump all domain hashes — game over |
| `GenericAll`                            | `Set-DomainUserPassword` / `Add-DomainGroupMember` / RBCD / Shadow Creds | Full control over object           |
| `AllExtendedRights`                     | `Set-DomainUserPassword` / `Add-DomainGroupMember` / DCSync              | Extended rights bundle             |
| `WriteDACL`                             | `Add-DomainObjectACL` → grant self GenericAll                            | Escalates to GenericAll            |
| `WriteOwner`                            | `Set-DomainObjectOwner` → WriteDACL → GenericAll                         | Escalates to GenericAll            |
| `Owns`                                  | `Set-DomainObjectOwner` → WriteDACL chain                                | Same as WriteOwner                 |
| `ReadLAPSPassword`                      | `Get-DomainComputer -Properties ms-mcs-AdmPwd`                           | Instant local admin                |
| `ReadGMSAPassword`                      | `gMSADumper.py`                                                          | Service account takeover           |
| `GenericWrite`                          | `Set-DomainObject` / Targeted Kerberoast / Shadow Creds / Logon script   | Partial control                    |
| `ForceChangePassword`                   | `Set-DomainUserPassword`                                                 | Password reset without old pass    |
| `AddMembers`                            | `Add-DomainGroupMember`                                                  | Add self to privileged group       |
| `AddSelf`                               | `Add-DomainGroupMember`                                                  | Add self to one group only         |

### Top ACL Attacks

- [ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password#forcechangepassword) - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
- [GenericWrite](https://bloodhound.specterops.io/resources/edges/generic-write#genericwrite) - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
- [AddSelf](https://bloodhound.specterops.io/resources/edges/add-self#addself) - shows security groups that a user can add themselves to.
- [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all#genericall) - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

{{< img src="ACL_attacks_graphic.png" alt="ACL Attacks" caption="by https://x.com/_nwodtuhs" >}}

### Enumerating ACLs of User

![[bloodhound#Enumerating ACLs of User]]
