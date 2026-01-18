+++
title = "Nix: Rsync"
+++

- `TCP 873`: normal
- Pentesting: https://archive.ph/flPtZ
- Rsync via `ssh`: https://phoenixnap.com/kb/how-to-rsync-over-ssh

```bash
# Enum via nmap
sudo nmap -sV -p873 <TARGET>

# Enum dir
rsync -av --list-only rsync://<TARGET>/<DIR>

# Download dir optionally via SSH
rsync -av -e "ssh -p <SSH_PORT>" rsync://<TARGET>/<DIR>
```
