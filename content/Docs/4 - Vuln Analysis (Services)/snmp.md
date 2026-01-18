+++
title = "SNMP"
+++

- `UDP 161`: normal
- `UDP 162`: "trap" or alert
- OIDs: https://www.alvestrand.no/objectid/top.html
- Versions:
    - v1/v2c: unencrypted
    - v3: encryption via PSK
- `/etc/snmp/snmpd.conf`
    - https://www.net-snmp.org/docs/man/snmpd.conf.html

*Management Information Base (MIB)* is a text file of *Object Identifier (OID)* s, which provide addresses to access device info, in the *Abstract Syntax Notation One (ASN.1)* based ASCII text format. Community Strings are sort of "passwords" to manage the access level.

{{% details "Dangerous Settings" %}}

| **Settings**                                  | **Description**                                                                       |
| --------------------------------------------- | ------------------------------------------------------------------------------------- |
| `rwuser noauth`                               | Provides access to the full OID tree without authentication.                          |
| `rwcommunity <COMMUNITY_STRING> <IPv4_ADDR>`  | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <COMMUNITY_STRING> <IPv6_ADDR>` | Same access as with `rwcommunity` with the difference of using IPv6.                  |
{{% /details %}}

```bash
# Enum via nmap
sudo nmap -n -Pn -sU -p161 -sV --script 'snmp*' --reason -oA nmap_snmp_scan <TARGET>

### Brute-force names of Community Strings
# - Default Strings: "public" (Read-Only) and "private" (Read/Write) are common
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <TARGET>
// probably "public"

### Brute-force OIDs and info
# -v 1,2c,3
snmpwalk -v <VERSION> -c <COMMUNITY_STRING> <TARGET> .1

### Brute-force OIDs
# -2 : use v2
# braa usu. uses Version 1
braa <COMMUNITY_STRING>@<TARGET>:.1.*
braa <COMMUNITY_STRING>@<TARGET>:.1.3.6.*
```
