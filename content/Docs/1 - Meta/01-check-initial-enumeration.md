+++
title = "01 - Check - Initial Enumeration"
+++

## Initial Setup

1. [ ] Setup:
    - Engagement folder (via Obsidian template)
    - [tmux]({{% ref "tmux.md#install-and-setup" %}})
    - [Metasploit database]({{% ref "metasploit.md#database" %}})
    - [Bloodhound (w/`netexec` integration enabled)]({{% ref "bloodhound.md#setup" %}})
    - [Flameshot](https://flameshot.org/) for screenshots and terminal:
```bash
pushd /usr/share/wordlists/ && sudo gunzip rockyou.txt.gz && popd
sudo apt update -y
sudo apt autoremove -y
sudo apt install -y --fix-missing flameshot ripgrep
sudo updatedb
mkdir ~/my_data
echo 'cd ~/my_data' >> ~/.bashrc
echo 'cd ~/my_data' >> ~/.zshrc
curl -LsSf https://astral.sh/uv/install.sh | sh && curl -LsSf https://astral.sh/uv/install.sh | sudo sh
```

2. [ ] Login into [SysReptor and create engagement report](https://labs.sysre.pt/projects?ordering=-created)
    - Use [trigger-based event reporting](https://www.brunorochamoura.com/posts/cpts-report/#triggers)

3. [ ] Read engagement and scoping documents target scope (IP ranges, domains, subnets)
    - **Create network diagram**

### Active Recon

1. [ ] Document all active hosts on the target network/IP range/subnet(s) in **Obsidian notes**.
    - **Ensure that off limits IPs are noted in `scope_excludes.txt` excluded `nmap --excludefile scope_excludes.txt`**

2. [ ] Start [Responder in Analyze mode]({{% ref "protocol-poisoners.md" %}}) as a background listener to passively capture hashes and hosts while scanning.

3. [ ] Host Discovery
    - [`nxc smb` or `nxc ssh` quick sweep (no creds)]({{% ref "netexec.md#basic-enumeration" %}})
    - [NMAP Host Discovery Scan]({{% ref "nmap.md#host-discovery" %}})
        - ARP scanning (same subnet only)
    - [ICMP sweep ping or fping]({{% ref "scanning.md#ping-sweep" %}})
    - TCP/UDP host discovery (`nmap -sn`, masscan)
    - **Add discovered hostnames (`nxc ... --generate-hosts-file`) to `/etc/hosts` file**

{{< embed-section page="Docs/9 - Notes/netexec" header="generating-hosts-file" expanded=true >}}

4. [ ] For each active host, scan ALL TCP/UDP ports. Document each open port per host in Obsidian.
    - [NMAP All Ports (TCP + UDP)]({{% ref "nmap.md#quickstart" %}})

5. [ ] For each open port, run service version scan with scripts and OS detection.
    - [NMAP service enumeration and OS detection]({{% ref "nmap.md#service-scanning" %}})
    - [Netcat banner grabbing (manual confirmation)]({{% ref "scanning.md#manual-scanning" %}})
    - **Document services and service versions in Obsidian**

6. [ ] For each detected service, do **individual service enumeration** to look for more information and vulnerabilities.

7. [ ] Check for vulnerabilities in discovered services / service versions.
    - [Search Metasploit for service exploits with the discovered version]({{% ref "metasploit.md" %}})
    - Search ExploitDB for service exploits with the discovered version
    - Look at NMAP script output for discovered vulnerabilities or misconfigurations (e.g. anonymous login)
    - Look for OS version exploits
    - Search Google for `Exploit GitHub <Service> <Version>`
    - **Document discovered vulnerabilities in Obsidian**

8. [ ] Check file share services (FTP, SMB, etc.) for anonymous logon and credential files.
    - [FTP Enumeration]({{% ref "ftp.md" %}})
    - [SMB Enumeration]({{% ref "smb-cifs-rpc.md" %}})

## with Credentials

9. [ ] [`netexec` sweep with ALL PROTOCOLS]({{% ref "netexec.md#protocol-spraying" %}})
