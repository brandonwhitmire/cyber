+++
title = "🐧 SSH: TCP 22"
+++

- `TCP 22`: normal
- Server Config:
    - `/etc/ssh/sshd_config`
        - https://www.ssh.com/academy/ssh/sshd_config
- Versions:
    - v1: obselete and vuln to MITM
    - v2: modern

```bash
sshpass -p '<PASSWORD>' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -p 22 <USER>@<TARGET>
```

```bash
# Force auth-method: privkey
ssh -i <PRIVATE_KEY> <USER>@<TARGET>
```
