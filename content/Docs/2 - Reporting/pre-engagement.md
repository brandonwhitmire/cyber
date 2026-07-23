+++
title = "Pre-Engagement"
+++

# Evidence Collection

- Using SysReptor for Report Writing: https://www.hackthebox.com/blog/certification-templates
- Writing Triggers: https://www.brunorochamoura.com/posts/cpts-report/

*   **Centralize Project Data:** Maintain one place for scope (IPs/URLs), client contacts, Rules of Engagement (RoE), and a running to-do list.
*   **Document the Attack Path:** As you move through the network, document the full chain of exploits with raw command output and screenshots.
*   **Maintain a Credential Log:** Keep a separate, centralized list of all compromised credentials, keys, and secrets.
*   **Isolate Findings:** Create a dedicated folder/note for each distinct vulnerability. Write the narrative and save evidence as you discover it, not after.
*   **Track Payloads & Modifications:** Keep a log of all uploaded payloads (with file hashes and paths) and any system modifications made (accounts created, settings changed, timestamps, host IPs).
*   **Get Approval for Destructive Actions:** Always get written client approval before making system changes or running tests that could impact stability.
    * For any big changes always save:
        - IP address of the host(s)/hostname(s) where the change was made
        - Timestamp of the change
        - Description of the change
        - Location on the host(s) where the change was made
        - Name of the application or service that was tampered with
        - Name of the account (if you created one) and perhaps the password in case you are required to surrender it
*   **Prioritize Terminal Output:** Use raw text from your terminal over screenshots. It's easier to redact, format, and allows clients to copy-paste commands. Use `<SNIP>` for brevity but never alter the output.
*   **Redact Securely:**
    *   Use **solid black boxes** to redact PII and credentials, not blur or pixelation (which can be reversed).
    *   Burn redactions directly into the image file itself, not as a shape overlay in a Word document.
*   **Handle Sensitive Data Safely:** Do not exfiltrate raw PII. Screenshot directory listings instead of downloading sensitive files to prove access.

## Collection Structure

Also see [tmux]({{% ref "tmux.md" %}}) and use `tmux` logging to automatically collect the terminal output.

```bash
mkdir -p {Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,'Service Enum','Web Enum','AD Enum'},Notes,OSINT,'Log Output','Misc Files'},Retest}
```

- `Admin`
    - Scope of Work (SoW) that you're working off of, your notes from the project kickoff meeting, status reports, vulnerability notifications, etc
- `Deliverables`
    - Folder for keeping your deliverables as you work through them. This will often be your report but can include other items such as supplemental spreadsheets and slide decks, depending on the specific client requirements.
- `Evidence`
    - Findings
        - Keep a folder for each finding you plan to include in the report to keep your evidence for each finding in a container to make piecing the walkthrough together easier when you write the report.
    - Scans
        - Vulnerability scans
            - Export files from your vulnerability scanner (if applicable for the assessment type) for archiving.
        - Service Enumeration
            - Export files from tools you use to enumerate services in the target environment like Nmap, Masscan, Rumble, etc.
        - Web
            - Export files for tools such as ZAP or Burp state files, EyeWitness, Aquatone, etc.
        - AD Enumeration
            - JSON files from BloodHound, CSV files generated from PowerView or ADRecon, Ping Castle data, Snaffler log files, CrackMapExec logs, data from Impacket tools, etc.
    - Notes
        - A folder to keep your notes in.
    - OSINT
        - Any OSINT output from tools like Intelx and Maltego that doesn't fit well in your notes document.
    - Wireless
        - Optional if wireless testing is in scope, you can use this folder for output from wireless testing tools.
    - Logging output
        - Logging output from Tmux, Metasploit, and any other log output that does not fit the `Scan` subdirectories listed above.
    - Misc Files
        - Web shells, payloads, custom scripts, and any other files generated during the assessment that are relevant to the project.
- `Retest`
    - This is an optional folder if you need to return after the original assessment and retest the previously discovered findings. You may want to replicate the folder structure you used during the initial assessment in this directory to keep your retest evidence separate from your original evidence.

## Client Communication

Send `start notification` email including information such as:

- Tester name
- Description of the type/scope of the engagement
- Source IP address for testing (public IP for an external attack host or the internal IP of our attack host if we are performing an Internal Penetration Test)
- Dates anticipate for testing
- Primary and secondary contact information (email and phone)

At the **end of each day**, we should send a **stop notification** to signal the end of testing

### Email Template

```
Subject: External Penetration Test - Start of Testing
From:
To:
Cc:
Date: Mon 6/20/2022 8:29AM

Good Morning,

This email is to notify you that the External Penetration Test against <COMPANY>'s internet-facing network assets has begun. All testing traffic will originate from the following IP address:
<TARGETS>

While we do not anticipate service disruptions during testing, if any issues arise, please do not hesitate to reach out via the cell phone number or email address in my signature line.

If I am unavailable for any reason, the secondary contact for this engagement will be:

<NAME>
<TITLE>
<PHONE>
<EMAIL>

As discussed during the kickoff call, I will send out a vulnerability notification for any high-risk vulnerabilities uncovered against internet-facing hosts. The assessment will begin with manual and automated information gathering and enumeration scans, then proceed to manual testing and validation of scan results.


Thank you, and I look forward to a productive assessment.

Regards,
<NAME>
<TITLE> | <COMPANY>
<PHONE>
<WEBSITE>
<EMAIL>
```

# Baseline Tracking of Technological Assets

Diagrams.net: https://app.diagrams.net/

- DNS records, network device backups, and DHCP configurations
- Full and current application inventory
- A list of all enterprise hosts and their location
- Users who have elevated permissions
- A list of any dual-homed hosts (2+ network interfaces)
- Keeping a visual network diagram of your environment

# People, Processes, and Technology

## Processes

- Proper policies and procedures for asset monitoring and management
    - Host audits, the use of asset tags, and periodic asset inventories can help ensure hosts are not lost
- Access control policies (user account provisioning/de-provisioning), multi-factor authentication mechanisms
- Processes for provisioning and decommissioning hosts (i.e., baseline security hardening guideline, gold images)
- Change management processes to formally document who did what and when they did it

### Perimeter First

- What exactly are we protecting?
- What are the most valuable assets the organization owns that need securing?
- What can be considered the perimeter of our network?
- What devices & services can be accessed from the Internet? (Public-facing)
- How can we detect & prevent when an attacker is attempting an attack?
- How can we make sure the right person &/or team receives alerts as soon as something isn't right?
- Who on our team is responsible for monitoring alerts and any actions our technical controls flag as potentially malicious?
- Do we have any external trusts with outside partners?
- What types of authentication mechanisms are we using?
- Do we require Out-of-Band (OOB) management for our infrastructure. If so, who has access permissions?
- Do we have a Disaster Recovery plan?

### Internal Considerations

- Are any hosts that require exposure to the internet properly hardened and placed in a DMZ network?
- Are we using Intrusion Detection and Prevention systems within our environment?
- How are our networks configured? Are different teams confined to their own network segments?
- Do we have separate networks for production and management networks?
- How are we tracking approved employees who have remote access to admin/management networks?
- How are we correlating the data we are receiving from our infrastructure defenses and end-points?
- Are we utilizing host-based IDS, IPS, and event logs?

# 3rd Parties Infrastructure

- AWS: https://aws.amazon.com/es/security/penetration-testing/
- Oracle: https://www.oracle.com/corporate/security-practices/testing/

# Sensitive Data Regulations

- UK: https://www.gov.uk/data-protection
- US:
    - Baselines/Govt: https://public.cyber.mil/stigs/
    - General: https://www.cisecurity.org/cis-benchmarks
    - Info Security: https://www.iso.org/standard/27001
    - Privacy: https://www.ftc.gov/business-guidance/privacy-security
    - Financial: https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act
    - Health: https://www.hhs.gov/hipaa/for-professionals/security/index.html