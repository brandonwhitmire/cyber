+++
title = "DNS"
+++

- `UDP 53`: normal name queries
- `TCP 53`: zone transfers and syncs
- Server Config (Bind9)
    - `/etc/bind/named.conf.local`
    - `/etc/bind/named.conf.options`
    - `/etc/bind/named.conf.log`
    - https://wiki.debian.org/BIND9
- https://web.archive.org/web/20250329174745/https://securitytrails.com/blog/most-popular-types-dns-attacks
- Domain Takeover: https://github.com/EdOverflow/can-i-take-over-xyz

{{% details "Dangerous Settings" %}}

| **Option**        | **Description**                                                                |
| ----------------- | ------------------------------------------------------------------------------ |
| `allow-query`     | Defines which hosts are allowed to send requests to the DNS server.            |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones.                                            |
{{% /details %}}

```bash
# Registrar Info
whois <DOMAIN> | whois.txt

# Query Nameserver for domain
dig @<DNS_SERVER> ns <DOMAIN>

# PTR Record or Reverse DNS Query
dig @<DNS_SERVER> -x <IP_ADDRESS>

# OLD: version / all records / zone transfer
dig @<DNS_SERVER> +short CH TXT version.bind <DOMAIN>
dig @<DNS_SERVER> +short ANY <DOMAIN>
dig @<DNS_SERVER> +short AXFR <DOMAIN>

# --- Record Types ---
# ANY: return all records -- sometimes doesnt work!
# A: IPv4 address
# AAAA: IPv6 address
# CNAME: Canonical Name
# MX: Mail Servers
# NS: Name Servers
# PTR: Pointer Record
# SOA: Start of Authority
# TXT: Text Records
# SRV: Service Records
# CAA: Certification Authority Authorization
for type in A AAAA CNAME MX NS SOA SRV TXT CAA; do echo -e "\n--- $type ---"; dig @<DNS_SERVER> +short $type <DOMAIN>; done

# PASSIVE: subdomain enum
# NOTE: requires API keys
subfinder -v -d <DOMAIN>

# ACTIVE: subdomain enum (quick, external)
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt <DOMAIN>

# ACTIVE: subdomain enum (slower, internal)
# /usr/share/SecLists/Discovery/DNS/namelist.txt
gobuster dns --threads 64 --output gobuster_dns_top110000 --quiet -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --resolver <DNS_SERVER> --domain <DOMAIN>
```

### 🌐 Subdomains

- Certificate Transparency: https://crt.sh/
- https://domain.glass/
- (PAID) https://buckets.grayhatwarfare.com/

```bash
# Domain => Subdomains via Cert Registry
curl -s "https://crt.sh/?q=<DOMAIN>&output=json" | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u | tee subdomainlist.txt
# Full Info 
for i in $(cat subdomainlist.txt) ; do host $i | tee -a hostinfo.txt ; done
# (IPv4) Domain Name => IP Address
for i in $(cat subdomainlist.txt) ; do host $i | grep "has address" | cut -d" " -f1,4 | tee -a domain_ipaddress.txt ; done
# (IPv4) Addresses Only
for i in $(cat domain_ipaddress.txt) ; do host $i | grep "has address" | cut -d" " -f4 | tee -a ip-addresses.txt ; done
# (IPv4) Addresses => Services via Shodan
for i in $(cat ip-addresses.txt) ; do shodan host $i ; done

# DNS: old technique
dig any <DOMAIN>

# Content Search: google.com Dork
inurl:<DOMAIN> intext:<TERM>
```

### LLMNR & NBT-NS

- `UDP 5355`: LLMNR (modern)
- `UDP 137`: NBT-NS (ancient)

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that used as failover protocols when DNS is unavailable.

On a Windows, the box will attempt to resolve a hostname in this order:
1. Checks **Local HOSTS file**.
2. Checks **DNS Cache / DNS Server**.
3. **(If DNS Fails):** Sends **LLMNR** Multicast.
4. **(If LLMNR Fails):** Sends **NBT-NS** Broadcast.

#### Remediation

Typically, disabling LLMNR and NBT-NS can cautiously used (to ensure no breakages) at the network or host-level.

- Disable LLMNR by:
    - Group Policy -->
    - Computer Configuration -->
    - Administrative Templates -->
    - Network -->
    - DNS Client
    - Enable "Turn OFF Multicast Name Resolution"

- Disable NBT-NS (locally only on each host or via GPO w/ PowerShell):
    - Network and Sharing Center -->
    - Control Panel -->
    - Change adapter settings
    - Right-clicking on the adapter --> properties -->
    - Selecting Internet Protocol Version 4 (TCP/IPv4) --> Properties --> Advanced --> selecting the WINS tab
    - Select "Disable NetBIOS over TCP/IP"