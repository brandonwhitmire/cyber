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
# NIX
# !!! LEAVE OFF LAST OCTET !!!
for i in {1..254} ; do (ping -c1 <TARGET_SUBNET>.$i | grep "bytes from" &) ; done

#  WIN: DOS
# !!! LEAVE OFF LAST OCTET !!!
for /L %i in (1 1 254) do ping <TARGET_SUBNET>.%i -n 1 -w 100 | find "Reply"
# Win: PowerShell
# !!! LEAVE OFF LAST OCTET !!!
1..254 | % { $ip="<TARGET_SUBNET>.$_"; if ((New-Object System.Net.NetworkInformation.Ping).Send($ip, 100).Status -eq "Success") { "$($ip): True" } }

# fping
fping -ag <TARGET_SUBNET>

# Metasploit
run post/multi/gather/ping_sweep RHOSTS=<TARGET_SUBNET>
```

## Full TCP Port Scan

Very slow but useful for adjacent targets when tunnels or proxies keep failing.

```powershell
$target = "172.16.210.21"
1..65535 | % {
    $client = New-Object System.Net.Sockets.TcpClient
    $result = $client.BeginConnect($target,$_,$null,$null)
    $success = $result.AsyncWaitHandle.WaitOne(100,$false)
    if ($success -and $client.Connected) { "Port $_ is open" }
    $client.Close()
}
```

## Metasploit

```bash
# TCP port scan across a subnet
use auxiliary/scanner/portscan/tcp
set RHOSTS <TARGET_SUBNET>
set PORTS 22,80,443,445,3389,5985
set THREADS 20
run
```

{{< embed-section page="Docs/9 - Notes/nmap" >}}
