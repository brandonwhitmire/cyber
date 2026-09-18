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

*Management Information Base (MIB)* is a text file of *Object Identifiers (OID)*, which provide addresses to access device info, in the *Abstract Syntax Notation One (ASN.1)* based ASCII text format. *Community Strings* are sort of "passwords" to manage the access level

### Find Community Strings

- Common Default Strings:
    - `public` (Read-Only)
    - `private` (Read/Write)

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <TARGET>
```

### Brute-force OIDs and info

- Versions `-v`:
    - `1`
    - `2c`
    - `3`

```bash
snmpwalk -v <VERSION> -c <COMMUNITY_STRING> <TARGET> .1

# Windows local user account names
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25

# Installed software
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2

# Running processes
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2

# TCP listening ports
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
```

### Brute-force OIDs

```bash
# -2 : use v2
# braa uses Version 1
braa <COMMUNITY_STRING>@<TARGET>:.1.*
braa <COMMUNITY_STRING>@<TARGET>:.1.3.6.*
```
