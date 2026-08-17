+++
title = "🌐 SNMP: UDP 161/162"
+++

- `UDP 161`: normal
- `UDP 162`: "trap" or alert
- OIDs: https://www.alvestrand.no/objectid/top.html
- Versions:
    - v1/v2c: unencrypted
    - v3: encryption via PSK
- `/etc/snmp/snmpd.conf`
    - https://www.net-snmp.org/docs/man/snmpd.conf.html
- https://hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html

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
sudo nmap -n -Pn -sU -p161 -sV --script 'snmp* and not snmp-brute' --reason -oA nmap_snmp_scan <TARGET>
```

### Brute-force names of Community Strings

- Common Default Strings:
    - "public" (Read-Only)
    - "private" (Read/Write)

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <TARGET>
```

### Brute-force OIDs and info

```bash
# -v 1,2c,3
snmpwalk -v <VERSION> -c <COMMUNITY_STRING> <TARGET> .1

# Enumerate Windows local user account names on the target
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25

# Enumerate all currently-running processes on the target
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2

# Enumerate all installed software on the target
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2

# Enumerate current TCP listening ports on the target
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
```

### Brute-force OIDs

```bash
# -2 : use v2
# braa usu. uses Version 1
braa <COMMUNITY_STRING>@<TARGET>:.1.*
braa <COMMUNITY_STRING>@<TARGET>:.1.3.6.*
```
