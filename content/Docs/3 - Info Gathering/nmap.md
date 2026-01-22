+++
title = "Nmap"
+++

- **`Open`** - received TCP SYN-ACK
- **`Closed`** - received TCP RST
- **`Filtered`** - no response
- **`Unfiltered`** - (with `-sA` TCP ACK scans) can't determine the state, but the port is accessible
- **`Open/Filtered`** - can't tell if the port is open or blocked by a firewall
- **`Closed/Filtered`** - (with `-sI` IP ID idle scan) can't tell if the port is closed or blocked by a firewall

Filtering out live hosts for `-iL`:

```bash
# Quick
sudo nmap -n -Pn -sS -sV -sC --stats-every 15s -oA scan_nmap_initial <TARGET> -v
# All Ports
sudo nmap -n -Pn -sS -p- --min-rate 5000 --stats-every 60s -oA scan_nmap_disc_all_ports <TARGET> -v
sudo nmap -n -Pn -sS -sV -sC -p <NEW_PORTS> --reason --stats-every 60s -oA scan_nmap_details_all_ports <TARGET> -v

---

# Find Live Hosts
sudo nmap -n -sn --reason -oA host_disc <TARGET>
# Create list
grep 'Status: Up' host_disc.gnmap | awk '{print $2}' | tee live_hosts.txt
# Scan normally w/ list
sudo nmap -n -Pn -sS -sV -sC --reason --top-ports=1000 -oA host_disc_live -iL live_hosts.txt
# Trace packet (MORE INFO)
sudo nmap -n -Pn -sS --packet-trace --disable-arp-ping -p <PORT> <TARGET>

# TCP Full-Connect (3-way handshake)
sudo nmap -n -Pn -sT -sV -sC --reason <TARGET>

# UDP (normally no response)
sudo nmap -n -Pn -sU -sV -sC --reason --top-ports=100 <TARGET>

# Create HTML reports from nmap XML scan
# https://nmap.org/book/output.html
xsltproc <SCAN_FILE>.xml -o <OUTPUT>.html

# SPAM: scan using multiple IP addresses
sudo nmap -n -Pn --max-retries=1 --source-port <SRC_PORT> -D RND:5 <TARGET>

# --max-retries <ATTEMPTS>
# -T <AGGRESSION_1_5>
# --packet-trace
# --reason
# --disable-arp-ping
# --top-ports=<NUM>
# --script <SCRIPT>
# -g <SRC_PORT>
# --dns-server <NAMESERVER>
```

### 📜 Nmap Scripting Engine (NSE)

The Nmap Scripting Engine (NSE) extends Nmap's functionality with custom scripts for vulnerability detection, service enumeration, and exploitation.

**Reference:** [NSE Usage Guide](https://nmap.org/book/nse-usage.html)

#### 📖 How to Use NSE

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

##### 📂 Script Categories

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

#### 📥 Install New NSE Script

```bash
sudo wget --output-file /usr/share/nmap/scripts/<SCRIPT>.nse \
    https://svn.nmap.org/nmap/scripts/<SCRIPT>.nse

nmap --script-updatedb
```
