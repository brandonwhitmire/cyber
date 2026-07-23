+++
title = "Nmap"
+++

- `nmap` grep commands for filtering: https://github.com/leonjza/awesome-nmap-grep

## Scanning

| State                 | Description                                                                         |
| :-------------------- | :---------------------------------------------------------------------------------- |
| **`Open`**            | Received `TCP SYN-ACK`                                                              |
| **`Closed`**          | Received `TCP RST`                                                                  |
| **`Filtered`**        | No response                                                                         |
| **`Open/Filtered`**   | Can't tell if port is open or blocked by a firewall                                 |
| **`Closed/Filtered`** | with `-sI` IP ID idle scan -- Can't tell if port is closed or blocked by a firewall |
| **`Unfiltered`**      | with `-sA` `TCP ACK` scans -- Can't determine state, but port is accessible         |

### Quickstart

```bash
# Quick + All Ports
sudo nmap -n -Pn -sS -sV -sC --open --stats-every 30s -vvv -oA nmap_quick <TARGET> && sudo nmap -n -Pn -sS -p- -sV -sC --open --stats-every 30s -vvv -oA nmap_all <TARGET>
```

```bash
# Metasploit version
db_nmap -n -Pn -sS -sV -sC --open --stats-every 30s -vvv -oA nmap_quick <TARGET>
db_nmap -n -Pn -sS -p- -sV -sC --open --stats-every 30s -vvv -oA nmap_all <TARGET>
```

### Host Discovery

```bash
# ARP (default behavior)
sudo nmap -sn -PR --send-eth -n -v -oA host_discovery_simple.txt --excludefile scope_excludes.txt -iL scope.txt

# Basic host discovery
sudo nmap --open -oA host_discovery_simple.txt --excludefile scope_excludes.txt -iL scope.txt

# Optimized for labs (-T4 --max-rtt-timeout 150ms --min-parallelism 100 --min-rate 1000 --max-retries 1)
sudo nmap -n -sn -v --stats-every 30s -PS445,80,443,3389,135,5985,22,8080,111 -oA host_discovery_lab.txt --excludefile scope_excludes.txt -iL scope.txt -T4 --max-rtt-timeout 150ms --min-parallelism 100 --min-rate 1000 --max-retries 1

# Find live hosts + extract to list
sudo nmap -n -sn --reason -oA host_disc <TARGET>
grep 'Status: Up' host_disc.gnmap | awk '{print $2}' | tee live_hosts.txt
awk '/Up$/{print $2}' host_discovery.txt > live_hosts.txt
```

For "ghost hosts" consider: `-PU137,138,161,53,67,123,500,4500` to discover via UDP (though very slow)

### Port Scanning

```bash
# Scan live hosts with list (top 1000 ports)
sudo nmap -n -Pn -sS -sV -sC --reason --top-ports=1000 -oA host_disc_live --excludefile scope_excludes.txt -iL live_hosts.txt
```

#### All Ports

Full TCP + UDP coverage for thorough host enumeration.

##### TCP

- `rustscan` TCP Full-Scan (3-way handshake): https://github.com/bee-san/RustScan
- `masscan` TCP Half-Scan (SYN): https://github.com/robertdavidgraham/masscan

```bash
# RustScan (-sT)
rustscan -a live_hosts.txt --ulimit 5000 -- -sC -sV -v --stats-every 30s -oA rustscan_all_tcp

# Masscan (-sS) + Nmap: large networks
sudo masscan --rate 1000 -p1-65535 -iL live_hosts.txt -oL masscan.txt -e <INTERFACE>
PORTS=$(awk '/open/ {print $3}' masscan.txt | sort -u | paste -sd, -)
sudo nmap --stats-every 30s -sS -sV -sC -v -p$PORTS -oA masscan_nmap_all_tcp --excludefile scope_excludes.txt -iL live_hosts.txt

# nmap only
sudo nmap -n -Pn -sS -p- --stats-every 30s -oA nmap_all_tcp --excludefile scope_excludes.txt -iL live_hosts.txt
```

##### UDP

Top 100 (full `-p-` UDP is impractically slow)

```bash
sudo nmap -n -Pn -sU --top-ports 100 -sV -sC --open -vvv --stats-every 30s -oA nmap_top100_udp --excludefile scope_excludes.txt -iL live_hosts.txt
```

### Service Scanning

```bash
sudo nmap -n -Pn -sn -sV -sC -O --excludefile scope_excludes.txt -iL live_hosts.txt
```

### Statically-compiled `nmap`

**NOTE:**
- A static `nmap` will not be able to perform `-sC`/`--script` nor `-sV` and there might be some issues with `-O` OS detection.
- `-sT` and `-sS` (root-only) work fine

```bash
wget https://github.com/andrew-d/static-binaries/raw/refs/heads/master/binaries/linux/x86_64/nmap && chmod +x nmap
```

**Discovery-like Command (scans common ports)**
```bash
sudo ./nmap -n -sS -p21,22,23,53,80,135,139,389,443,445,1433,3389,5985,5986,8080 --open --stats-every 30s -vvv <SUBNET>
```

**Full Port Scan**
```bash
sudo ./nmap -p- -sS -Pn -n -T4 --min-rate 5000 -oN nmap_allports.txt -stats-every 30s -vvv <TARGET>
```

### Nmap Scripting Engine (NSE)

- [NSE Usage Guide](https://nmap.org/book/nse-usage.html)

The Nmap Scripting Engine (NSE) extends Nmap's functionality with custom scripts for vulnerability detection, service enumeration, and exploitation.

#### Usage

**Basic Usage:**
- `-sC` - Run a set of popular, common scripts
- `--script` - Run specific scripts by name, category, or file path
- `--script-help` - Show arguments for `--script-args`

**Advanced Usage:**
- Combine scripts with wildcards: `--script "smb-*,http-*"`
- Use comprehensive documentation: [NSE Script Database](https://nmap.org/nsedoc/scripts/)
- Search for scripts: `grep "ftp" /usr/share/nmap/scripts/script.db`

```bash
# --script-trace : trace script scans
nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php' -oA nmap_http_put <TARGET>
```

##### Script Categories

Location: `/usr/share/nmap/scripts`
- https://nmap.org/nsedoc/scripts/

| Category | Description |
| :--- | :--- |
| **`auth`** | Scripts related to authentication, such as bypassing credentials or checking for default ones. |
| **`broadcast`** | Used to discover hosts on the local network by broadcasting requests. |
| **`brute`** | Scripts that perform brute-force attacks to guess passwords or credentials. |
| **`default`** | The core set of scripts that are run automatically with `-sC` or `-A`. |
| **`discovery`** | Actively gathers more information about a network, often using public registries or protocols like SNMP. |
| **`dos`** | Tests for vulnerabilities that could lead to a denial-of-service attack. |
| **`exploit`** | Actively attempts to exploit known vulnerabilities on a target system. |
| **`external`** | Interacts with external services or databases. |
| **`fuzzer`** | Sends unexpected or randomized data to a service to find bugs or vulnerabilities. |
| **`intrusive`** | These scripts can be noisy, resource-intensive, or potentially crash the target system. |
| **`malware`** | Scans for known malware or backdoors on a target host. |
| **`safe`** | Scripts that are considered safe to run as they are not designed to crash services, use excessive resources, or exploit vulnerabilities. |
| **`version`** | Extends the functionality of Nmap's version detection feature. |
| **`vuln`** | Checks a target for specific, known vulnerabilities. |

#### Install New NSE Script

```bash
sudo wget --output-file /usr/share/nmap/scripts/<SCRIPT>.nse \
    https://svn.nmap.org/nmap/scripts/<SCRIPT>.nse

nmap --script-updatedb
```

## Miscellaneous

```bash
# Create HTML report from nmap XML
# https://nmap.org/book/output.html
xsltproc <SCAN_FILE>.xml -o <OUTPUT>.html

# Decoy scan using multiple source IPs
sudo nmap -n -Pn --max-retries=1 --source-port <SRC_PORT> -D RND:5 <TARGET>

# Performance and Behavior Flags
--max-retries <ATTEMPTS>
-T <AGGRESSION_1_5>
--packet-trace
--reason
--disable-arp-ping
--top-ports=<NUM>
--script <SCRIPT>
-g <SRC_PORT>
--dns-server <NAMESERVER>
```
