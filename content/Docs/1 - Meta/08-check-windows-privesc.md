+++
title = "08 - Check - Windows Privilege Escalation"
+++

Tasty info:

- Privileges
- Groups
- Services
- Scheduled tasks
- Installed applications + versions (for public exploits)
- OS version + architecture (for kernel exploits)
- Running processes
- Network info
- Sensitive files / credentials
- Registry

---

1. [ ] Run automated survey tools in background
    - [SharpUp]({{% ref "privilege-escalation-windows.md#sharpup" %}})
    - [Seatbelt]({{% ref "privilege-escalation-windows.md#seatbelt" %}})
    - [winPEAS]({{% ref "privilege-escalation-windows.md#winpeas" %}})
    - (Domain) [Bloodhound]({{% ref "bloodhound.md" %}})

2. [ ] Manual comands
    - `whoami /priv`
    - [Manual Survey]({{% ref "privilege-escalation-windows.md#manual-survey" %}})
    - [User Attributes Mining (via netexec)]({{% ref "netexec.md#user-account-description" %}})

3. [ ] Look for interesting files on the server that may have credentials or other sensitive info.
    - [Credential Hunting]({{% ref "finding-creds.md" %}})
    - [Credential Hunting Other Files]({{% ref "finding-creds.md#searching" %}})
    - [Dumping Hashes / Credentials]({{% ref "netexec.md#sam-database" %}})
    - [Mimikatz]({{% ref "mimikatz-post-exploit.md" %}})
