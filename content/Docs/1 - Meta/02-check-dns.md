+++
title = "02 - Check - DNS Enumeration"
+++

## DNS Enumeration

### Active Recon

1. [ ] Identify authoritative nameservers and attempt zone transfer
    - [DNS Zone Transfer & Record Enumeration]({{% ref "dns.md#enumeration" %}})

2. [ ] Enumerate standard record types (A, AAAA, MX, TXT, SRV, NS)
    - Run PTR/reverse lookups against discovered IP ranges
    - [DNS Enumeration]({{% ref "dns.md#enumeration" %}})

3. [ ] If internal network -- check LLMNR/NBT-NS exposure
    - [LLMNR & NBT-NS Poisoning]({{% ref "dns.md#llmnr-nbt-ns" %}})
    - If enabled and no SMB signing: run [Responder]({{% ref "protocol-poisoners.md" %}}) to capture hashes
