+++
title = "01 - Check - Initial Enumeration"
+++

## Initial Setup

1. [ ] Setup:

```bash
# Unzip rockyou.txt wordlist
pushd /usr/share/wordlists/ && sudo gunzip rockyou.txt.gz ; popd
# System update and install some packages
sudo apt update -y
sudo apt autoremove -y
sudo apt install -y --fix-missing flameshot ripgrep sshpass pocl-opencl-icd autorecon penelope
# Update locate DB
sudo updatedb
# Manual tool installs
go install -v github.com/nullt3r/udpx/cmd/udpx@latest
curl -LsSf https://astral.sh/uv/install.sh | sh && curl -LsSf https://astral.sh/uv/install.sh | sudo sh
sudo wget -q https://raw.githubusercontent.com/brandonwhitmire/nxcblast/main/nxcblast.py -O /usr/local/bin/nxcblast && sudo chmod +x /usr/local/bin/nxcblast
git clone https://github.com/brandonwhitmire/cyber-tools.git $HOME/cyber-tools
"$HOME/cyber-tools/tools.sh" --install
. "$HOME/.zshrc"
# Artifacts folder
mkdir ~/my_data
echo 'cd ~/my_data' >> ~/.bashrc
echo 'cd ~/my_data' >> ~/.zshrc
# Penelope shell auto-safe mode
echo "alias penelope='penelope --oscp-safe'" >> ~/.bashrc
echo "alias penelope='penelope --oscp-safe'" >> ~/.zshrc
sudo bash -c "echo \"alias penelope='penelope --oscp-safe'\" >> /root/.bashrc"
sudo bash -c "echo \"alias penelope='penelope --oscp-safe'\" >> /root/.zshrc"
```

{{< embed-section page="Docs/9 - Notes/tmux.md" header="setup" >}}

{{< embed-section page="Docs/5 - Exploitation/metasploit.md" header="database" >}}

{{< embed-section page="Docs/9 - Notes/bloodhound.md" header="setup" >}}

2. [ ] [SysReptor: Create engagement report](https://labs.sysre.pt/projects?ordering=-created)
    - Engagement folder (via Obsidian template)
    - Use [trigger-based event reporting](https://www.brunorochamoura.com/posts/cpts-report/#triggers)

3. [ ] **Create network diagram** from engagement and scoping documents target scope (IP ranges, domains, subnets)

4. [ ] Document all active hosts on the target network/IP range/subnet(s) in **Obsidian notes**
    - **Ensure that off limits IPs are noted in `scope_excludes.txt` excluded `nmap --excludefile scope_excludes.txt`**

### Active Recon

1. [ ] Start [Responder in Analyze mode]({{% ref "protocol-poisoners.md" %}}) as a background listener to passively capture hashes and hosts while scanning.

2. [ ] Host Discovery
    - [`nxc smb` or `nxc ssh` quick sweep (no creds)]({{% ref "netexec.md#basic-enumeration" %}})
    - [NMAP Host Discovery Scan]({{% ref "nmap.md#host-discovery" %}})
        - ARP scanning (same subnet only)
    - [ICMP sweep ping or fping]({{% ref "scanning.md#ping-sweep" %}})
    - TCP/UDP host discovery (`nmap -sn`, masscan)
    - **Add discovered hostnames:

{{< embed-section page="Docs/9 - Notes/netexec" header="generating-hosts-file" expanded=true >}}

3. [ ] For each active host, scan ALL TCP/UDP ports. Document each open port per host in Obsidian.
    - [NMAP All Ports (TCP + UDP)]({{% ref "nmap.md#quickstart" %}})
    - [Netcat banner grabbing (manual confirmation)]({{% ref "scanning.md#manual-scanning" %}})
    - **Document services and service versions in Obsidian**

4. [ ] Check for vulnerabilities in discovered services / service versions.
    - [Search Metasploit for service exploits with the discovered version]({{% ref "metasploit.md" %}})
    - Search ExploitDB for `searchsploit --nmap <NMAP_XML>`
    - Look at NMAP script output for discovered vulnerabilities or misconfigurations (e.g. anonymous login)
    - Look for OS version exploits
    - Search Google for `Exploit GitHub <Service> <Version>`
    - **Document discovered vulnerabilities in Obsidian**

5. [ ] Check file share services ([FTP]({{% ref "ftp.md" %}}), [SMB]({{% ref "smb-cifs-rpc.md" %}}), [NFS]({{% ref "nfs.md" %}}), etc.) for anonymous logon and credential files

6. [ ] [`netexec` sweep with ALL PROTOCOLS]({{% ref "netexec.md#protocol-spraying" %}}) and check for anonymous logons
