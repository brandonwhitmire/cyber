+++
title = "PrivHound: Windows PrivEsc Graph"
+++

* https://github.com/dazzyddos/PrivHound

Local privilege escalation grapher to map attack paths in BloodHound. Collects via its own PowerShell commands and shows the relationships via Cypher queries only

## Collect Survey

```powershell
# Skip testing found creds against target
.\PrivHound.ps1 -NoCredTest -OutputPath ".\privhound_$env:COMPUTERNAME.json"
```

**REQUIRES: this [temp fix](https://github.com/dazzyddos/PrivHound/issues/5#issuecomment-4573036467)**
```bash
jq '(.graph.nodes[]?.properties) |= (if type=="object" then del(.objectid) else . end)' privhound*.json > fixed.json
```
**UPLOAD output `.json` to BloodHound**

**Upload Schema and Icons**
```bash
curl -X POST http://127.0.0.1:8080/api/v2/custom-nodes -H "Content-Type: application/json" -H "Prefer: wait=30" -d @privhound_customnodes.json -v -H "Authorization: Bearer <JWT_TOKEN>"
```

## Key Cypher queries

- https://github.com/dazzyddos/PrivHound/blob/main/queries/privhound_queries.cypher

**NOTE:** scraped from above link and some built by AI, **use with caution**

### All privesc paths to SYSTEM

```cypher
MATCH p=(u:PHUser)-[*1..5]->(t:PHPrivTarget)
WHERE t.account = "NT AUTHORITY\\SYSTEM"
RETURN p
```

### Full PrivHound graph (see everything)

```cypher
MATCH p=()-[r]->() WHERE type(r) STARTS WITH "PH"
RETURN p
```

### Credential chain to admin (cross-user escalation)

```cypher
MATCH p=(u:PHUser)-[*1..6]->(t:PHPrivTarget)
WHERE any(r IN relationships(p) WHERE type(r) = "PHCanAccessProfile")
  AND any(r IN relationships(p) WHERE type(r) = "PHCanLoginAs")
RETURN p
```

### Overlay local privesc on AD attack paths (the killer query)

"Where does a domain user's AD session lead to SYSTEM locally?"

```cypher
MATCH (adUser:User)-[:HasSession]->(comp:Computer)
MATCH (phu:PHUser)-[*1..5]->(target:PHPrivTarget)
WHERE target.account = "NT AUTHORITY\\SYSTEM"
  AND phu.hostname = comp.name
RETURN adUser.name, comp.name, target.account
```

### 1. FASTEST SIGNAL: any path to SYSTEM (run this first, always)

```cypher
MATCH p=shortestPath((u:PHUser)-[*1..8]->(t:PHPrivTarget))
RETURN p
```

### 2. TOKEN PRIVILEGES (SeImpersonate, SeBackup etc -- instant win if present)

```cypher
MATCH p=(u:PHUser)-[:PHHasPrivilege]->(priv:PHTokenPrivilege)-[:PHCanEscalateTo]->(t:PHPrivTarget)
RETURN p
```

### 3. WRITABLE SERVICE BINARY (classic OSCP privesc)

```cypher
MATCH p=(u:PHUser)-[:PHCanWriteBinary]->(s:PHService)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p
```

### 4. MODIFIABLE SERVICE CONFIG (can change binary path)

```cypher
MATCH p=(u:PHUser)-[:PHCanModifyService]->(s:PHService)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p
```

### 5. UNQUOTED SERVICE PATH

```cypher
MATCH p=(u:PHUser)-[:PHCanHijackPath]->(uq:PHUnquotedPath)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p
```

### 6. WRITABLE SCHEDULED TASK BINARY (common OSCP vector)

```cypher
MATCH p=(u:PHUser)-[:PHCanWriteTaskBinary]->(task:PHScheduledTask)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p
```

### 7. CREDENTIALS IN PS HISTORY / SENSITIVE FILES (quick cred finds)

```cypher
MATCH p=(u:PHUser)-[:PHCanReadHistory]->(h:PHPSHistory)-[:PHContainsCreds]->(h)
RETURN p
```

### 8. ALWAYSINSTALLELEVATED

```cypher
MATCH p=(u:PHUser)-[:PHCanExploit]->(r:PHRegistryMisconfig)-[:PHEscalatesTo]->(t:PHPrivTarget)
RETURN p
```
