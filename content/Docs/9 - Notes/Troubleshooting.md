+++
title = "0) Troubleshooting & Snippets"
+++

Random fixes, one-liners, and useful commands for lab machines and general fuckery.

## Fix Go

When system Go is broken or missing (HTB / online lab VMs)...

```bash
go: github.com/hahwul/dalfox/v2@latest (in github.com/hahwul/dalfox/v2@v2.12.0): go.mod:3: invalid go version '1.23.0': must match format 1.23
```

...Install a local Go and wire it into `PATH`:

```bash
wget https://go.dev/dl/go1.23.6.linux-amd64.tar.gz
mkdir -p ~/go_bin
tar -C ~/go_bin -xzf go1.23.6.linux-amd64.tar.gz
export PATH=$HOME/go_bin/go/bin:$HOME/go/bin/:$PATH
echo -e '\nexport PATH=$HOME/go_bin/go/bin:$HOME/go/bin/:$PATH' | tee -a ~/.bashrc ~/.zshrc
go version
```

## Manual DNS Server

Sometimes there are DNS issues with certain tools that may not read `/etc/hosts`, so this will fix it at the DNS layer.

```bash
# Add target endpoints
sudo dnsmasq \
  --no-daemon \
  --listen-address=127.0.0.1 \
  --bind-interfaces \
  --no-resolv \
  --server=1.1.1.1 \
  --server=8.8.8.8 \
  --address=/<FQDN_TARGET>/<IP_ADDR> \
  --address=/<FQDN_TARGET>/<IP_ADDR> \
  &

# Prepend resolv.conf, give priority to dnsmasq
sudo sed -i '1s/^/nameserver 127.0.0.1\n/' /etc/resolv.conf

# Verify
dig +short <FQDN_TARGET>
```

## Access Domain Names

For a box that is not joined to the domain, but has domain access, add the DC (or DNS server) to resolve DNS names.

**Split DNS Resolution (w/ VPN)**
```bash
# 1. Enable dnsmasq plugin (Global Config)
sudo cp /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/NetworkManager.conf.bak
sudo sed -i '/\[main\]/a dns=dnsmasq' /etc/NetworkManager/NetworkManager.conf

# 2. Create the Domain Rule (Persistent)
# Syntax: server=/domain.com/10.10.10.10
echo "server=/<FQDN>/<DNS_SERVER>" | sudo tee /etc/NetworkManager/dnsmasq.d/split_dns.conf

# 3. Restart NetworkManager to apply the plugin change
sudo systemctl restart NetworkManager

# 4. Configure the VPN Connection
# Replace <CONNECTION_NAME> with your VPN profile name (e.g., 'tun0' or 'lab_vpn')
sudo nmcli connection modify "<CONNECTION_NAME>" ipv4.dns ""
sudo nmcli connection modify "<CONNECTION_NAME>" ipv4.ignore-auto-dns yes
sudo nmcli connection modify "<CONNECTION_NAME>" ipv4.never-default yes

# 5. Reconnect VPN
sudo nmcli connection down "<CONNECTION_NAME>"
sudo nmcli connection up "<CONNECTION_NAME>"
```

**All DNS Resolution (no Internet access)**
```bash
# Configure the VPN connection to strictly use the Target DNS
sudo nmcli connection modify "<CONNECTION_NAME>" ipv4.dns "<DNS_SERVER>"
sudo nmcli connection modify "<CONNECTION_NAME>" ipv4.ignore-auto-dns yes

# Reconnect to apply
sudo nmcli connection down "<CONNECTION_NAME>"
sudo nmcli connection up "<CONNECTION_NAME>"
```

**Verify**
```bash
nslookup <TARGET>
```

## Wine Installation

The Parrot OS PwnBox has some trouble with `wine` and `mono`, but this is necessary for Windows binaries like `ysoserial.exe`.

**NOTE:** this is not an automatic installation as it will pop-up a few windows that require the user to agree to the terms and conditions

```bash
# Clean up the broken backports source
sudo rm /etc/apt/sources.list.d/parrot-echo-backports.list

# Add Debian sid (unstable) which has wine32
echo "deb http://deb.debian.org/debian sid main contrib non-free non-free-firmware" | sudo tee /etc/apt/sources.list.d/debian-sid.list

# Pin sid to low priority so it doesn't take over your system
cat <<EOF | sudo tee /etc/apt/preferences.d/sid
Package: *
Pin: release a=sid
Pin-Priority: 100
EOF

# Install Wine
sudo apt update -y
sudo apt install -t sid wine wine32:i386 wine64 -y

# Install .NET
sudo apt install winetricks -y
winetricks dotnet48
```
