+++
title = "07 - Check - Linux Privilege Escalation"
+++

### Initial Foothold

1. [ ] If landed in a restricted shell (rbash, lshell), escape it before proceeding with enumeration.
    - [Restricted Shell Bypass Reference](https://vk9-sec.com/linux-restricted-shell-bypass/)

2. [ ] Stabilize the shell to a fully interactive TTY before running any tools.
    - [Shell Upgrade]({{% ref "shells.md#best-upgrade" %}})

3. [ ] Launch LinPEAS in the background -- runs while working through manual checks below.
    - [LinPEAS]({{% ref "privilege-escalation-linux.md#linpeas" %}})

4. [ ] Establish identity and orientation: user, hostname, groups
    - [Manual Survey]({{% ref "privilege-escalation-linux.md#manual-survey" %}})

5. [ ] Map the network: interfaces, routes, hosts file; note any unexpected subnets

6. [ ] Check if the host is domain-joined (`realm list` or `/etc/krb5.conf`)
    - If joined: search for keytab files and list Kerberos tickets

7. [ ] Check sudo privileges immediately -- `NOPASSWD` entries are instant escalation paths
    - [Checking Sudo Privileges]({{% ref "privilege-escalation-linux.md#manual-survey" %}})

8. [ ] Hunt for credentials in env vars, shell history, and web app config files
    - [Linux Credential Harvesting]({{% ref "finding-creds.md#linux" %}})

9. [ ] Check ARP table for other hosts and pivot scope

---

### Default Methodology

1. [ ] Review LinPEAS output (launched at Initial Foothold step 1). Transfer to attack box and examine in a text editor.
    - [LinPEAS]({{% ref "privilege-escalation-linux.md#linpeas" %}})

2. [ ] Run the full Manual Survey -- identity, network, users, processes, filesystem, cron, SUID/SGID, writable files.
    - [Manual Survey]({{% ref "privilege-escalation-linux.md#manual-survey" %}})

3. [ ] Enumerate for hardcoded / cleartext credentials on the system (quickly check config files).
    - **BE ESPECIALLY ATTENTIVE TO OUT-OF-THE-ORDINARY SERVICES**
    - Look for things in `/opt`
    - Look for web config files
    - [Enumeration: Credential Hunting]({{% ref "finding-creds.md" %}})

4. [ ] Look at access rights of the user we gained a foothold with (Sudo/SUID/GUID).
    - [Checking for Sudo privileges]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
        - If sudo over binary not in GTFOBins: try LD_PRELOAD Privilege Escalation
    - [Checking SUID/GUID Privileges]({{% ref "privilege-escalation-linux.md#file-permissions" %}})
        - If custom binary with SETUID: try [Shared Object Hacking]({{% ref "privilege-escalation-linux.md#file-permissions" %}})
    - Check these rights in GTFOBins

5. [ ] Check the groups the user is a part of -- look for privileged group membership.
    - [Privileged Groups]({{% ref "privilege-escalation-linux.md#groups" %}})

6. [ ] Look for [abusable Linux capabilities]({{% ref "privilege-escalation-linux.md#capabilities" %}}).

7. [ ] Look for cronjobs running writable scripts / services running as root or another privileged user.

8. [ ] Check for NFS shares exposed with `no_root_squash` -- mount and write a SUID shell as root.
    - [NFS Enumeration]({{% ref "nfs.md" %}})

9. [ ] Check for kernel exploits and recent zero days.
    - Search for exploits on GitHub, ExploitDB, and Metasploit

10. [ ] Check for Wildcard abuse in cron jobs or custom scripts.

11. [ ] If Python script exists, check for [Python Library Hijacking]({{% ref "privilege-escalation-python.md" %}}).

12. [ ] Look for vulnerable application / service versions.

13. [ ] Check for PATH abuse (unlikely).

14. [ ] Check for hijackable tmux sessions.

15. [ ] If `tcpdump` exists on the machine, try capturing cleartext traffic for credentials.

16. [ ] Check `/etc/bash.bashrc` for actions taken on login for any user.

17. [ ] Attempt to brute force root user with password file and `sucrack`.

### Linux Container Privilege Escalation

1. [ ] [Linux Containers (LXC/LXD)]({{% ref "privilege-escalation-linux.md#groups" %}})

2. [ ] [Docker Privilege Escalation]({{% ref "privilege-escalation-linux.md#groups" %}})

3. [ ] [Kubernetes Privilege Escalation]({{% ref "privilege-escalation-kubernetes.md" %}})
