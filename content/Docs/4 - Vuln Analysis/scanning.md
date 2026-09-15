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

# Windows - TCP
Test-NetConnection -Port <PORT> <IP>
```

## Ping Sweep

**NOTE:** sometimes ARP caches are delayed or not built... so running a ping sweep twice can discover new hosts

```bash
# fping
fping -ag <TARGET_SUBNET>
```

![[nice-commands-linux#Ping Sweep]]

![[nice-commands-windows#Windows Ping Sweep]]

![[metasploit#Ping Sweep]]

## Full TCP Port Scan

![[nice-commands-windows#Full TCP Port Scan]]

## Metasploit

![[metasploit#TCP Port Scan]]

![[autorecon]]

![[nmap]]
