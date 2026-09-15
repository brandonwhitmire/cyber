+++
title = "PrivHound: Windows PrivEsc Graph"
+++

* https://github.com/dazzyddos/PrivHound

Local privilege escalation as a graph to map attack paths inside BloodHound

**REQUIRES:**
- its own PowerShell collector to run on target
- Cypher only (no prebuilt commands)

## Collect Survey

```powershell
# Skip testing found creds against target
.\PrivHound.ps1 -NoCredTest -OutputPath <PATH>
```

## Key Cypher queries

- https://github.com/dazzyddos/PrivHound/blob/main/queries/privhound_queries.cypher

**NOTE:** scraped from above adn some built by AI, use with caution

```cypher
-- All privesc paths to SYSTEM
MATCH p=(u:PHUser)-[*1..5]->(t:PHPrivTarget)
WHERE t.account = "NT AUTHORITY\\SYSTEM"
RETURN p

-- Full PrivHound graph (see everything)
MATCH p=()-[r]->() WHERE type(r) STARTS WITH "PH"
RETURN p

-- Credential chain to admin (cross-user escalation)
MATCH p=(u:PHUser)-[*1..6]->(t:PHPrivTarget)
WHERE any(r IN relationships(p) WHERE type(r) = "PHCanAccessProfile")
  AND any(r IN relationships(p) WHERE type(r) = "PHCanLoginAs")
RETURN p

-- Overlay local privesc on AD attack paths (the killer query)
-- "Where does a domain user's AD session lead to SYSTEM locally?"
MATCH (adUser:User)-[:HasSession]->(comp:Computer)
MATCH (phu:PHUser)-[*1..5]->(target:PHPrivTarget)
WHERE target.account = "NT AUTHORITY\\SYSTEM"
  AND phu.hostname = comp.name
RETURN adUser.name, comp.name, target.account
```

```cypher
-- 1. FASTEST SIGNAL: any path to SYSTEM (run this first, always)
MATCH p=shortestPath((u:PHUser)-[*1..8]->(t:PHPrivTarget))
RETURN p

-- 2. TOKEN PRIVILEGES (SeImpersonate, SeBackup etc -- instant win if present)
MATCH p=(u:PHUser)-[:PHHasPrivilege]->(priv:PHTokenPrivilege)-[:PHCanEscalateTo]->(t:PHPrivTarget)
RETURN p

-- 3. WRITABLE SERVICE BINARY (classic OSCP privesc)
MATCH p=(u:PHUser)-[:PHCanWriteBinary]->(s:PHService)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

-- 4. MODIFIABLE SERVICE CONFIG (can change binary path)
MATCH p=(u:PHUser)-[:PHCanModifyService]->(s:PHService)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

-- 5. UNQUOTED SERVICE PATH
MATCH p=(u:PHUser)-[:PHCanHijackPath]->(uq:PHUnquotedPath)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

-- 6. WRITABLE SCHEDULED TASK BINARY (common OSCP vector)
MATCH p=(u:PHUser)-[:PHCanWriteTaskBinary]->(task:PHScheduledTask)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

-- 7. CREDENTIALS IN PS HISTORY / SENSITIVE FILES (quick cred finds)
MATCH p=(u:PHUser)-[:PHCanReadHistory]->(h:PHPSHistory)-[:PHContainsCreds]->(h)
RETURN p

-- 8. ALWAYSINSTALLELEVATED
MATCH p=(u:PHUser)-[:PHCanExploit]->(r:PHRegistryMisconfig)-[:PHEscalatesTo]->(t:PHPrivTarget)
RETURN p

-- 9. GPP PASSWORDS (if SYSVOL readable)
MATCH p=(u:PHUser)-[:PHCanDecryptGPP]->(g:PHGPPPassword)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

-- 10. FULL GRAPH (if above return nothing -- see everything)
MATCH p=()-[r]->() WHERE type(r) STARTS WITH "PH"
RETURN p
```
