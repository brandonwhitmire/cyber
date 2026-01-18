+++
title = "Manual Scanning"
+++

```bash
# -p: source port
# TCP
nc -nvzw5 <TARGET> <PORT>
# UDP
nc -unvzw5 <TARGET> <PORT>

# Connect to Encrypted Service (TLS/SSL)
openssl s_client -starttls ftp -connect <TARGET>:<PORT>

# Banner Grabbing
sudo nmap -n -Pn --script banner.nse <TARGET>

### Ping Sweeps

# NOTE: sometimes ARP caches are delayed or not built... so running a ping sweep 2x is helpful

# NIX
for i in {1..254} ; do (ping -c1 <TARGET_SUBNET>.$i | grep "bytes from" &) ; done

###  WIN
# DOS
for /L %i in (1 1 254) do ping <TARGET_SUBNET>.%i -n 1 -w 100 | find "Reply"
# PowerShell
1..254 | % { $ip="<TARGET_SUBNET>.$_"; if ((New-Object System.Net.NetworkInformation.Ping).Send($ip, 100).Status -eq "Success") { "$($ip): True" } }

# Metasploit
run post/multi/gather/ping_sweep RHOSTS=<TARGET_SUBNET>
```
