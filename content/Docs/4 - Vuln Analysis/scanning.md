+++
title = "🌐 0) Scanning"
+++

- Ports:
    - https://github.com/epiecs/packetlife-backup/blob/master/cheat_sheets/common_ports.pdf
- OS Identification via:
    - TTL: https://subinsb.com/default-device-ttl-values/

## Manual Scanning

```bash
# TCP
nc -nvzw5 <TARGET> <PORT>
# UDP
nc -unvzw5 <TARGET> <PORT>

# Connect to Encrypted Service (TLS/SSL)
openssl s_client -starttls ftp -connect <TARGET>:<PORT>

# Banner Grabbing
sudo nmap -n -Pn --script banner.nse <TARGET>
```

## Ping Sweep

**NOTE:** sometimes ARP caches are delayed or not built... so running a ping sweep twice can discover new hosts

```bash
# fping
fping -ag <TARGET_SUBNET>
```

{{< embed-section page="Docs/6 - Post-Exploitation/nice-commands" header="ping-sweep" >}}

{{< embed-section page="Docs/6 - Post-Exploitation/nice-commands" header="windows-ping-sweep" >}}

{{< embed-section page="Docs/5 - Exploitation/metasploit" header="ping-sweep" >}}

## Full TCP Port Scan

{{< embed-section page="Docs/6 - Post-Exploitation/nice-commands" header="full-tcp-port-scan" >}}

## Metasploit

{{< embed-section page="Docs/5 - Exploitation/metasploit" header="tcp-port-scan" >}}

{{< embed-section page="Docs/9 - Notes/autorecon" >}}

{{< embed-section page="Docs/9 - Notes/nmap" >}}
