+++
title = "Nix: SSH"
+++

- `TCP 22`: normal
- Server Config:
    - `/etc/ssh/sshd_config`
    - https://www.ssh.com/academy/ssh/sshd_config
- Versions:
    - v1: obselete and vuln to MITM
    - v2: modern

{{% details "Dangerous Settings" %}}
- https://www.ssh-audit.com/hardening_guides.html

| **Setting**                  | **Description**                             |
| ---------------------------- | ------------------------------------------- |
| `PasswordAuthentication yes` | Allows password-based authentication.       |
| `PermitEmptyPasswords yes`   | Allows the use of empty passwords.          |
| `PermitRootLogin yes`        | Allows to log in as the root user.          |
| `Protocol 1`                 | Uses an outdated version of encryption.     |
| `X11Forwarding yes`          | Allows X11 forwarding for GUI applications. |
| `AllowTcpForwarding yes`     | Allows forwarding of TCP ports.             |
| `PermitTunnel`               | Allows tunneling.                           |
| `DebianBanner yes`           | Displays a specific banner when logging in. |
{{% /details %}}

```bash
# Audit sercurity of SSH server
# https://github.com/jtesta/ssh-audit
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py -l warn <TARGET> | tee ssh_audit.txt

# Specify auth-method: password
ssh -v -o PreferredAuthentications=password <USER>@<TARGET>

sshpass -p '<PASSWORD>' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 <USER>@<TARGET>

# Force auth-method: privkey
ssh -i <PRIVATE_KEY> <USER>@<TARGET>
```
