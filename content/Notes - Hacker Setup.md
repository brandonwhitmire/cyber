+++
title = "Notes - Hacker Setup"
type = "home"
+++

**NOTE: This is just a scratchpad. Don't take it too seriously...**

# TODO

## Kali

- make zsh hook or something that background scan commands, saves output to unique file in ~/kali_logs (maybe make this exportable $HACKER_LOG)
    - send notification when done?
    - force default pwd is in kali_logs and not ~
- set **some msfvenom** options automagically like LHOST (tun0 or listening port) and any other VARS? maybe random autoport
- vim highlighter for targets and split screen to have targets on top (maybe better thing exists without vim base)
- create shell function to get tun0 callback IP easily

## Windows

- add to VM:
    - zellij
        - make it for default for all terminals
    - plink/PuTTY (maybe not necesary)
    - proxifier
    - openvpn
        - maybe VPN connect helper script
    - nmap (already install in FLARE VM)
    - wsl first time setup
        - `wsl --install --distribution Debian`
- set default display resolution: 1920x1080
- add automatic VPN configs files

## Notes

- add `dnstt` to `lateral-movement` section
- make cheatsheet guide:
    - scan IP or block
    - run forked background scan per service that is specialized (SMB, Wordpress, etc.)
    - maybe AI to read scan and highlight top moves?
- Add standards to notes from: https://academy.hackthebox.com/beta/module/108/section/1027
- Add firewall probing to notes: https://tryhackme.com/room/redteamfirewalls
- Make file transfer quick pastables script for dummy files (to see what works)... maybe 1 command to run them all or something? (e.g autosetup SMB, HTTP, etc. server and print out connection info or pastables), auto encryption or encoding for files placed in certain folders
- Various windows priv esc techniques: https://academy.hackthebox.com/beta/module/24/section/159
- Vuln Scoring system: https://academy.hackthebox.com/beta/module/108/section/1228
- Add standards to notes from: https://academy.hackthebox.com/beta/module/108/section/1027
- Make notes from THM Red Teaming Section

---

```bash
# Reqs

## First Time

### Plugins
vagrant plugin install vagrant-libvirt
vagrant plugin install vagrant-dns
vagrant plugin install vagrant-scp

### Firewall rules (GUFW)
sudo ufw allow proto udp from any to any port 67,68

## Each boot

### Use system scope by default
export LIBVIRT_DEFAULT_URI=qemu:///system

### Vagrant use libvirt by default
export VAGRANT_DEFAULT_PROVIDER=libvirt

# New Box - Kali

## Kali setup

### Hunter.io API Key (in theHarvester)

mkdir -p ~/.theHarvester && echo "HUNTERIO_API_KEY=<API_KEY>" >> ~/.theHarvester/api-keys.yaml

# New Box - Windows 10

Build a clean Win10 from scratch.

## https://github.com/rgl/windows-vagrant

git clone https://github.com/rgl/windows-vagrant.git
cd windows-vagrant
make
make build-windows-2022-libvirt
vagrant box add -f windows-2022-amd64 windows-2022-amd64-libvirt.box.json

# Quick Commands

sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y

virsh list --all

vagrant destroy --force

vagrant reload --provision

VAGRANT_LOG=info
vagrant up

virt-viewer --attach $(virsh --connect=qemu:///system list --name | head --lines=1)

xrandr --output Virtual-1 --mode 1900x987
xrandr --output Virtual-1 --mode 1920x1080

# run sudo command with log output as unpriv user
sudo nohup openvpn --config /vagrant/*.ovpn > >(tee nohup.log) 2>&1 &  

# Scrape PDFs to Text
pdftotext -layout *.pdf - | grep -v "Penetration Testing Professional" > info.txt

# Vagrant Tunneling
vagrant ssh -- -N -L <LPORT>:<TARGET_IP>:<TARGET_PORT>

# DNS Server Reconfig
sudo rm -f /etc/resolv.conf && \
echo -e "nameserver <DNS_SERVER>" | sudo tee /etc/resolv.conf && \
sudo chattr +i /etc/resolv.conf

dig +short <TARGET>

# PowerShell on Kali
sudo apt update && sudo apt install gss-ntlmssp
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
# === Core Modules for Pentesting on Kali ===

# --- Remote Management ---
# Enables native PowerShell Remoting (Invoke-Command, New-PSSession) from Linux.
Install-Module -Name PSWSMan -Scope CurrentUser -Force

# --- Active Directory & Enumeration ---
# The go-to suite for AD enumeration. Contains PowerView.
Install-Module -Name PowerSploit -Scope CurrentUser -Force

# Automated AD reconnaissance script that generates a comprehensive report.
Install-Module -Name ADRecon -Scope CurrentUser -Force

# --- Post-Exploitation & Payloads ---
# Classic post-exploitation framework with reverse shells, keyloggers, etc.
Install-Module -Name Nishang -Scope CurrentUser -Force

# The "Netcat of PowerShell" for reverse/bind shells and file transfers.
Install-Module -Name powercat -Scope CurrentUser -Force

# --- Console Enhancement (Quality of Life) ---
# Improves the PowerShell command-line experience with better history, syntax highlighting, etc.
Install-Module -Name PSReadLine -Scope CurrentUser -Force

# A powerful theme engine for creating an informative and customized prompt.
Install-Module -Name oh-my-posh -Scope CurrentUser -Force

# --- Update All Modules ---
# After installation, you can keep them all up to date with this single command.
Update-Module -Scope CurrentUser
```