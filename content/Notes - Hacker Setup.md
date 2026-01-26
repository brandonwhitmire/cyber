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

## Website:

- ~~add Hugo shortcode to `relref` just a header section of a page like "See [LINK]" but it's an expandable block of the sourced information to prevent duplication but allow easy access of contextually relevant information~~
- scrollable tables to not overflow in mobile view
## Notes

- make bloodhound its own page
- make responder and web traffic capture as pre-actions (before any active scanning)
- make checklist for sections
    - web enum
    - AD
        - especially workflow process to compromise a domain (users, pass, machines, trust, etc.)
        - domain user and computer attributes, group membership, Group Policy Objects, permissions, ACLs, trusts
        - `adsisearcher` instead of PS module `ActiveDirectory`
    - DNS
    - NMAP (or ARP) for host discovery
    - SMB (enum4linux-ng, anon/null sessions)
- **fix `mirror.yml` for website**
- TASTY BINARIES?: https://github.com/Flangvik/SharpCollection?tab=readme-ov-file
- SAMPLE PENTEST ENGAGEMENT FLOW: https://archive.ph/i6AeU
- split out Hydra from password into its own section?
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

---

# Pentest Engagement Sample

- https://archive.ph/i6AeU

```
a lot of crappy pentest companies will just run nessus or other vulnerability scanners and call it good. When you guys actually look for and hire a pentest company you should try to get one that performs RISK based pentesting, this means that theyll do much more than just run nessus. I'm a senior pentester for a RISK based pentesting company and this is a rough break out of our standard TTP (much more is included, this is just a standard scenario):
​
Internal:
Nmap discovery scan (quick scan for ports 21,22,23,53,80,139,443,445,3389)
Aquatone or Eyewitness against results from discovery scan
Nmap full port scan
Nessus scan
crackmapexec --gen-relay-list (to create a list of hosts that have smb signing disabled)(crackmapexec as also known as cme)
Responder and/or MITM6 (to poison network and attempt to get ntlmv2 hashes, this only works against hosts that are within the same broadcast domain that your attack box is in)
Pcredz (run at same time as responder because it will collect more hashes than responder, but responder has to be running)
Impacket ntlmrelayx.py (must be run with responder, this will attempt to relay any incoming ntlmv2 hashes to other hosts that have smb signing disabled)
crackmapexec --shares (with user and pass empty to see if any hosts have shares that do not require auth to connect to)
-------
At this point you should at least have ntlmv2 hashes the have been collected by Responder or Pcredz, hopefully youve been able to crack the password using Hashcat (keep in mind that you CANNOT crack hashes if they are using MFA such as smart cards, in this case your only attack would be ntlmrelayx as long as they have machines that dont have smb signing enabled).
We'll assume that youve gained user access by this point by cracking a ntlmv2 user hash, so now you have the username and plaintext password for a user.
-------
The following is how to own the domain without using cobalt strike - this is assuming that you have a username and password:
crackmapexec using the username and pass to see if the user has admin access to any hosts - if the user has admin to any host then:
                crackmapexec --sam (to dump the local admin hash of the host that you have admin access to)
                crackmapexec -M lsassy (to dump lsass of the host that you have admin access to)
                DonPapi.py (to dump sam, chrome, IE, last created files, of hosts you have admin to)
Impacket getuserspns.py (this will kerberoast the domain and retrieve service account hashes to crack with hashcat)
Bloodhound (this will map out AD and give you attack paths, show you where domain admins are logged into non-DC)
At this point it is fairly typical that we'll have the local admin ntlm hash for a workstation because we dumped the sam of the workstation that we have access to.
In this case we can use crackmapexec to pass that hash to every other machine using the --local-auth flag. Assuming that they re-use the local admin pw on most workstations (which they normally do), we should have access to many more workstations now.
Check bloodhound output to see where domain admins are logged on (lets now assume that we have the local admin hash for a host that has a DA logged in)
Dump sam of that host
Dump lsass of the host (if you get the DA hash from lsass then you win, you now own the domain)
DonPapi against that host to see if you can get their AD password from chrome or IE or a password file
If you dont get the hash of DA, but you know that they are logged into the box, then you need to spawn a beacon or meterpreter on that box
Once you have interactive access to the box, list processes, find one owned by the DA, and inject into it (you now own the domain)
-----------
The following is a quick rundown of what to do if you have a beacon from cobalt strike:
execute assembly is used for running C# assembly executables, you will use this a LOT
Rubues kerberoast (get those service account hashes)
SharpUp (you could also use PowerUp.ps1 if you want, will output possible ways to privesc)
Watson (to find missing patches to possibly find ways to privesc)
SeatBelt -group=user (to find lots of stuff, dump browser passwords, files, etc)
net computers (internal CS command will get a list of all machines on the network and import them into the 'targets' view)
SharpView (or powerview.ps1, run the command to query which boxes the user has admin access to)
SharpHound (C# implementation of the bloodhound ingester)
At this point hopefully you have local admin or system on a box, either from privesc or because you found that the user has admin to other machines via the sharpview command.
hashdump (to dump sam)
logonpasswords (to dump lsass)
​
As you can see from this TTP, we run nessus but typically only for the customers benefit. Exploiting vulnerabilities discovered via nessus is typically something that we dont do, primarily because we emulating an actual threat actor that gain access to your network, and threat actors DO NOT RUN NESSUS.
```