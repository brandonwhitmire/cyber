+++
title = "BloodHound"
+++

## BloodHound

- https://github.com/SpecterOps/BloodHound
    - Queries Cheatsheet: https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
        - https://github.com/SpecterOps/BloodHoundQueryLibrary/tree/main/queries
- Attack Path: https://morimori-dev.github.io/posts/tech-bloodhound-attack-paths/

**NOTE:** sometimes the outputed zipfile doesn't get properly ingested... trying extracting and uploading the individual JSON files

BloodHound is **THE TOOL** for AD enumeration. "\[L\]everages graph theory to reveal hidden and often unintended relationships across identity and access management systems..." **visually** along with other pre-built queries to find weakness in domain structures.

## Setup

- https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart

```bash
# Start and reset password for BloodHound via Docker
sudo systemctl enable --now docker
sudo ~/cyber-tools/tools/bloodhound-cli install | tee ~/bh_install.log
netexec ; sleep 5 && sed -i 's/bh_enabled = False/bh_enabled = True/' ~/.nxc/nxc.conf
#sudo ./bloodhound-cli resetpwd  # needed if PW not grabbed from install
```

## Collecting Info

- Collection Methods: https://bloodhound.specterops.io/collect-data/ce-collection/sharphound-flags

### Uploading Info
- Transfer Bloodhound data to attacker
    - Upload zipfile: <http://127.0.0.1:8080/ui/administration/file-ingest>

### Windows

#### SharpHound

```bash
.\SharpHound.exe -c All --zipfilename bh_logs.zip --OutputDirectory <PATH>
```

```powershell
Import-Module .\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All -ZipFileName bh_logs.zip -OutputDirectory <PATH>
```

### Linux

This is helpful when on a non-Windows host or from outside of the domain:

#### RustHound-CE

- https://github.com/g0h4n/RustHound-CE

**RustHound-CE collects certificate information as well!**

```bash
./rusthound-ce --zip --collectionmethod All --domain <DOMAIN> --ldapusername <USER> --ldappassword <PASSWORD> --ldapfqdn <DC_FQDN>
```

![[netexec#BloodHound-CE-Python via `netexec`]]

## Analysis and Queries

| **BEST QUERIES**                                    | **Why**                                    |
| --------------------------------------------------- | ------------------------------------------ |
| `Find Shortest Paths to Domain Admins`              | Primary attack path                        |
| `Find Principals with DCSync Rights`                | Instant game over if found                 |
| `Find Kerberoastable Users`                         | Most common foothold                       |
| `Shortest Paths to DA from Kerberoastable Users`    | Combined path                              |
| `Find AS-REP Roastable Users`                       | No creds needed                            |
| `Find Computers where Domain Users are Local Admin` | Easy lateral movement                      |
| `Shortest paths from Owned objects`                 | See what currently owned users could yield |

## Domain Trusts

- Pre-built Query
- Analysis > Domain Information > Map Domain Trusts

## Enumerating ACLs of User

1) Select starting node user
2) Select Node Info > Scroll to `Outbound Control Rights`
3) `First Degree Object Control`
    1) Right-Click edge > Help for more info
4) `Transitive Object Control`
5) Analysis > Dangerous Rights

## CanRDP

- [BloodHound CanRDP](https://bloodhound.specterops.io/resources/edges/can-rdp):
    - Search for User > Node Info > Execution Rights
    - Analysis
        - `Find Workstations where Domain Users can RDP`
        - `Find Servers where Domain Users can RDP`

## CanPSRemote

- [Bloodhound CanPSRemote](https://bloodhound.specterops.io/resources/edges/can-ps-remote)
- https://queries.specterops.io/

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

## SQLAdmin

- [BloodHound SQLAdmin](https://bloodhound.specterops.io/resources/edges/sql-admin)

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```
