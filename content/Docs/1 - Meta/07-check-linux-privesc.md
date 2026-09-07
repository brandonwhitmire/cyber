+++
title = "07 - Check - Linux Privilege Escalation"
+++

Tasty info:

- Sudo rights (`sudo -l`) + SUID/SGID binaries
- Group memberships (docker, lxd, disk, adm, shadow, wheel)
- File capabilities
- Cron jobs + writable scripts / services
- Installed packages + versions (public exploits)
- Kernel + distro version (kernel exploits)
- Running processes + command-line args
- Network info + NFS shares (`no_root_squash`)
- Credentials in env, history, and config files

---

1. [ ] Escape restricted shell (rbash/lshell), then stabilize to a fully interactive TTY.
    - [Restricted Shell Bypass](https://vk9-sec.com/linux-restricted-shell-bypass/)
    - [Shell Upgrade]({{% ref "shells.md#best-upgrade" %}})

2. [ ] Run automated scanners in background.
    - [LinPEAS]({{% ref "privilege-escalation-linux.md#linpeas" %}})
    - [RootHound]({{% ref "privilege-escalation-linux.md#roothound" %}}) -- parse the LinPEAS output visual graph

3. [ ] Manual commands -- `sudo -l`, `id`, domain-join check (`realm list`).
    - [Manual Survey]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - Access rights sudo/SUID/SGID -> cross-check [GTFOBins](https://gtfobins.github.io/)
    - [Privileged Groups]({{% ref "privilege-escalation-linux.md#groups" %}}) + [Capabilities]({{% ref "privilege-escalation-linux.md#capabilities" %}})

4. [ ] Hunt for credentials -- env, history, config files (`/opt`, web app configs).
    - [Credential Hunting]({{% ref "finding-creds.md#linux" %}})

5. [ ] Work escalation paths -- cron/wildcard abuse, NFS `no_root_squash`, kernel exploits, vulnerable service versions, [Python library hijacking]({{% ref "privilege-escalation-python.md" %}}).

6. [ ] Containers -- [LXC/LXD & Docker]({{% ref "privilege-escalation-linux.md#groups" %}}), [Kubernetes]({{% ref "privilege-escalation-kubernetes.md" %}}).
