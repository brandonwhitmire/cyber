+++
title = "08 - Check - Windows Privilege Escalation"
+++

### Initial Foothold

1. [ ] Launch winPEAS in the background -- it runs while you work through manual checks below.
    - [winPEAS]({{% ref "privilege-escalation-windows.md#winpeas" %}})

2. [ ] Establish identity: user, groups, privileges
    - [Manual Survey]({{% ref "privilege-escalation-windows.md#manual-survey" %}})

3. [ ] Map the network: interfaces, routes, hosts file -- note any unexpected subnets

4. [ ] Run BloodHound if on domain
    - [BloodHound Collection]({{% ref "bloodhound.md" %}})

5. [ ] Check token privileges -- SeImpersonate/SeDebug/SeBackup are instant escalation
    - [Good Privileges]({{% ref "privilege-escalation-windows.md#good-privileges" %}})

6. [ ] Hunt for credentials in the registry, files, and via LaZagne
    - [Windows Credential Harvesting]({{% ref "finding-creds.md" %}})

7. [ ] Check ARP table and routes for other hosts and pivot scope

---

### Webserver

1. [ ] Check web configuration files and source code for vulnerabilities, hardcoded credentials, etc.
    - [Enumeration: Credential Hunting]({{% ref "finding-creds.md" %}})
    - Check the source code of all pages, including index
    {{< embed-section page="Docs/4 - Vuln Analysis/http" header="default-server-directories" >}}

### Default Methodology

1. [ ] Review winPEAS output (launched at Initial Foothold step 1). Transfer to attack box and examine in a text editor.
    - [winPEAS]({{% ref "privilege-escalation-windows.md#winpeas" %}}) (Things to check)
    - [Seatbelt]({{% ref "privilege-escalation-windows.md#seatbelt" %}})
    - [SharpUp]({{% ref "privilege-escalation-windows.md#sharpup" %}})
    - [Bloodhound]({{% ref "bloodhound.md" %}})

2. [ ] Run the full Manual Survey -- identity, network, system info, installed software, processes, users, tasks.
    - [Manual Survey]({{% ref "privilege-escalation-windows.md#manual-survey" %}})

3. [ ] Check token privileges -- `SeImpersonate`/`SeAssignPrimaryToken` and `SeDebug`/`SeTakeOwnership` are instant escalation.
    - [Windows Privileges Overview]({{% ref "privilege-escalation-windows.md#privileges-vs-access-rights" %}})
    - SeImpersonate / SeAssignPrimaryToken ([JuicyPotato]({{% ref "privilege-escalation-windows.md#juicypotato" %}}) / [RoguePotato / PrintSpoofer]({{% ref "privilege-escalation-windows.md#roguepotato-godpotato-printspoofer-printnightmare" %}}))
    - [SeDebugPrivilege]({{% ref "privilege-escalation-windows.md#via-sedebug" %}})
    - [SeTakeOwnershipPrivilege]({{% ref "privilege-escalation-windows.md#setakeownershipprivilege" %}})

4. [ ] Check for saved credentials.
    - [Cmdkey Saved Credentials]({{% ref "finding-creds.md" %}})
    - `cmdkey /list`
    - If we get access this way, run [Mimikatz]({{% ref "mimikatz-post-exploit.md" %}}) to try to extract their plaintext password

5. [ ] Check if user is a member of privileged groups.
    - [Backup Operators]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [Event Log Readers]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [DnsAdmins]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [Hyper-V Admins]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [Print Operators]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [Server Operators]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - WSUS Administrators

6. [ ] Check for 'Always Install Elevated' setting and exploit with MSI package.
    - [Always Install Elevated]({{% ref "privilege-escalation-windows.md#alwaysinstallelevated" %}})

7. [ ] Check for Weak File / Service Permissions.
    - [Permissive File System ACLs]({{% ref "privilege-escalation-windows.md#file-folder-permissions" %}})
    - [Weak Service Permissions]({{% ref "privilege-escalation-windows.md#weak-service-acls" %}})
    - [Unquoted Service Path]({{% ref "privilege-escalation-windows.md#unquoted-service-paths" %}})
    - Permissive Registry ACLs
    - Modifiable Registry Autorun Binary

8. [ ] Look for scheduled tasks that we can modify.
    - [Scheduled Tasks]({{% ref "privilege-escalation-windows.md#manual-survey" %}})

9. [ ] Look for credentials in process command line.
    - [Process Command Line]({{% ref "privilege-escalation-windows.md#manual-survey" %}})

10. [ ] Look for interesting files on the server that may have credentials or other sensitive info.
    - [Credential Hunting]({{% ref "finding-creds.md" %}})
    - [Credential Hunting Other Files]({{% ref "finding-creds.md#searching" %}})
    - Further Credential Theft
    - [Dumping Hashes / Credentials]({{% ref "netexec.md#sam-database" %}})
    - [Mimikatz]({{% ref "mimikatz-post-exploit.md" %}})

11. [ ] Attempt to bypass UAC Controls if present.
    - [User Account Control (UAC) Attacks]({{% ref "security-products.md#user-account-control" %}})

12. [ ] [DLL Hijacking]({{% ref "privilege-escalation-windows.md#dll-hijacking" %}}).

13. [ ] Look for Kernel / OS exploits.
    - Kernel Exploits:
        - Zero Logon
        - PrintNightmare
    - EOL Systems and their exploits (Windows Server 2008, Windows 7, etc.)

14. [ ] Check for Active Directory Certificate Services (ADCS) attacks.
    - [AD CS Attack Reference]({{% ref "active-directory.md#adcs-attack-reference" %}})

15. [ ] Pillage for credentials or other interesting information.
    - [Pillaging Overview]({{% ref "finding-creds.md" %}})
    - Pillaging Applications
    - Accessing Instant Messaging Clients Through Cookies
    - Pillaging the Clipboard + Keylogging
    - Roles and Services (pillaging backups)

16. [ ] Enumerate User/Computer Description Fields for cleartext credentials or other useful information.
    - [User Attributes Mining]({{% ref "active-directory.md#user-attributes-mining" %}})

17. [ ] Look for services running on internal ports that were not accessible from the outside.
    - Databases we can connect to?
    - Vulnerable Services

18. [ ] Look for vulnerable applications and services.
    - Vulnerable Services

19. [ ] Attempt to capture network traffic with Inveigh/Responder, Wireshark, or Snaffler.
    - [Traffic Capture]({{% ref "finding-creds.md#creds-in-network-traffic" %}})
    - [Snaffler -- SMB Share Enumeration Tool]({{% ref "finding-creds.md#snaffler" %}})
    - [LLMNR/NBT-NS Poisoning from Windows]({{% ref "protocol-poisoners.md" %}})
    - [LLMNR/NBT-NS Poisoning from Linux]({{% ref "protocol-poisoners.md" %}})

20. [ ] If the system has `.vhd`, `.vhdx`, or `.vmdk` files, mount them to potentially dump machine hashes.
    - Mount VHDX/VMDK

21. [ ] Capture hashes with a Malicious LNK file or SCF file.
    - **ESPECIALLY USEFUL IF WE THINK USERS WILL VISIT A SHARE THAT WE HAVE UPLOADED TO**
    - [Capturing Hashes with Malicious .lnk File]({{% ref "protocol-poisoners.md" %}})
    - [Capture hashes with SCF on a File Share]({{% ref "protocol-poisoners.md" %}}) (no longer works on Windows Server 2019 or greater)

22. [ ] If trying to be evasive or if custom executables are locked down, check LOLBAS for alternative methods.
    - Living Off The Land Binaries and Scripts (LOLBAS)

### With `Administrator`

1. [ ] Attempt to recover all user passwords or NTLM hashes on the system.
    - [Dump the LSASS process to try and recover more user passwords or NTLM hashes]({{% ref "privilege-escalation-windows.md#via-sedebug" %}})
    - [Stealing NTLM Hashes from an LSASS.DMP Memory Dump]({{% ref "privilege-escalation-windows.md#via-sedebug" %}})
    - [Dumping the SAM Database to recover password hashes]({{% ref "netexec.md#sam-database" %}})

2. [ ] If on a Domain Controller, dump NTDS.dit to recover all domain account hashes.
    - [NTDS Extraction via NetExec]({{% ref "netexec.md#ntds-dump" %}})
