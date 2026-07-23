
+++
title = "Post-Engagement"
+++

***UNDERSTANDABLE* and *ACTIONABLE*: DON'T assume people understand everything or know the technical details IN the REPORT... explain your thought process... make things easily reproducible (copy&pastable) where possible...**

---
## Reports and Sections

- REAL REPORTS: https://github.com/juliocesarfort/public-pentesting-reports

- Writing the Report: https://www.blackhillsinfosec.com/how-to-not-suck-at-reporting-or-how-to-write-great-pentesting-reports/
- Report Writing Tools:
    - https://github.com/pwndoc/pwndoc
    - https://github.com/blacklanternsecurity/writehat
    - https://github.com/Syslifters/sysreptor
    - https://github.com/GhostManager/Ghostwriter
    - https://dradis.com/ce/
    - Tracking: https://github.com/SecurityRiskAdvisors/VECTR
- Report/Findings Boilerplate:
    - https://attack.mitre.org/techniques/enterprise/

### 1. The Executive Summary
**Target Audience:** Non-technical executives (CISO, Board of Directors) managing budgets.
**Goal:** Translate technical risk into business impact and justify remediation funding.
*   **Engagement Overview:** Scope, objective, and high-level results (e.g., "7 findings, 5 High, 1 Medium, 1 Low").
*   **The Narrative:** Explain the overall security posture (e.g., "Patch management is excellent, but configuration management is poor").
*   **Key Impacts:** Describe what was accessed in plain English (e.g., "Gained access to HR and banking systems" instead of "Domain Admin").
*   **Strategic Recommendations:** Focus on broken processes, not just patches (e.g., "Implement a stronger password policy" instead of "Change 500 passwords").

#### *Do's and Don'ts* of Executive Summaries

| DO | DON'T |
| :--- | :--- |
| **Be specific with metrics.** ("We found 25 instances," not "We found several"). | **Name specific vendors.** (Say "an EDR solution," not "Buy CrowdStrike"). |
| **Keep it under 2 pages.** Consolidate minor issues into process-level themes. | **Use technical acronyms.** (Translate LLMNR, XSS, or TGT into plain English). |
| **Focus on business impact.** (What data was stolen, what processes were halted). | **Waste space on minor findings.** (Focus on the critical attack paths). |
| **Set remediation expectations.** (Acknowledge if fixing a GPO will take significant time). | **Reference technical sections.** (The Exec Summary must be 100% standalone). |

### 2. The Remediation Summary (Roadmap)
**Goal:** A prioritized checklist for IT managers.
*   **Short-Term:** Immediate fixes (Patch X, disable Service Y).
*   **Medium/Long-Term:** Process fixes (Implement LAPS, redesign SDLC, deploy EDR).

### 3. The Attack Chain (Narrative)
**Goal:** Show how multiple low/medium vulnerabilities chain together to create a critical impact.
*   Step-by-step walkthrough (e.g., LLMNR Poisoning $\rightarrow$ Crack Hash $\rightarrow$ Kerberoast SPN $\rightarrow$ Crack Hash $\rightarrow$ DCSync).
*   Include screenshots and command output.

### 4. Detailed Findings
**Goal:** Technical reproduction steps and exact fixes for sysadmins/developers.
*   Severity Rating, CVE/CVSS/OWASP/MITRE IDs
*   Affected systems, networks, environments, or applications
*   Vulnerability Description.
*   Reproduction Steps (Commands & Output).
*   Remediation Advice:
    * **Each finding should include one or more external references for further reading on a particular vulnerability or misconfiguration**
    * Reference links with additional information about the tool/method itself

### 5. Appendices
*   **Scope:** IPs, Domains, URLs tested.
*   **Methodology:** The standard tested against (e.g., PTES, OWASP).
*   **Severity Ratings Matrix:** How you calculate High vs. Medium risk.
*   **Payloads/Artifacts Log:** File hashes, paths, and timestamps of all tools dropped on disk (crucial for Blue Teams/Forensics).
*   **Compromised Credentials:** List of accounts cracked (do not list passwords in cleartext if possible).
*   **Configuration Changes:** List of any settings modified during the test that need reverting.
*   *(Optional)* **Domain Password Analysis:** Statistics on cracked AD passwords (e.g., via DPAT).
*   *(Optional)* **OSINT / External Footprint:** Open ports, breached credentials (DeHashed), DNS records.

## Cleanup

Keep notes of:

- Every scan
- Attack attempt
- File placed on a system
- Changes made (accounts created, minor configuration changes, etc.)

Before the engagement closes, we should delete any files we uploaded (tools, shells, payloads, notes) and restore everything to the way we found it. Regardless of if we were able to clean everything up, we should still note down in our report appendices every change, file uploaded, account compromise, and host compromise, along with the methods used

## Misc Tips/Tricks

- Aim to tell a story with your report. Why does it matter that you could perform Kerberoasting and crack a hash? What was the impact of default creds on X application?
- Write as you go. Don't leave reporting until the end. Your report does not need to be perfect as you test but documenting as much as you can as clearly as you can during testing will help you be as comprehensive as possible and not miss things or cut corners while rushing on the last day of the testing window.
- Stay organized. Keep things in chronological order, so working with your notes is easier. Make your notes clear and easy to navigate, so they provide value and don't cause you extra work.
- Show as much evidence as possible while not being overly verbose. Show enough screenshots/command output to clearly demonstrate and reproduce issues but do not add loads of extra screenshots or unnecessary command output that will clutter up the report.
- Clearly show what is being presented in screenshots. Use a tool such as [Greenshot](https://getgreenshot.org/) to add arrows/colored boxes to screenshots and add explanations under the screenshot if needed. A screenshot is useless if your audience has to guess what you're trying to show with it.
- Redact sensitive data wherever possible. This includes cleartext passwords, password hashes, other secrets, and any data that could be deemed sensitive to our clients. Reports may be sent around a company and even to third parties, so we want to ensure we've done our due diligence not to include any data in the report that could be misused. A tool such as `Greenshot` can be used to obfuscate parts of a screenshot (using solid shapes and not blurring!).
- Redact tool output wherever possible to remove elements that non-hackers may construe as unprofessional (i.e., `(Pwn3d!)` from CrackMapExec output). In CME's case, you can change that value in your config file to print something else to the screen, so you don't have to change it in your report every time. Other tools may have similar customization.
- Check your Hashcat output to ensure that none of the candidate passwords is anything crude. Many wordlists will have words that can be considered crude/offensive, and if any of these are present in the Hashcat output, change them to something innocuous. You may be thinking, "they said never to alter command output." The two examples above are some of the few times it is OK. Generally, if we are modifying something that can be construed as offensive or unprofessional but not changing the overall representation of the finding evidence, then we are OK, but take this on a case-by-case basis and raise issues like this to a manager or team lead if in doubt.
- Check grammar, spelling, and formatting, ensure font and font sizes are consistent and spell out acronyms the first time you use them in a report.
- Make sure screenshots are clear and do not capture extra parts of the screen that bloat their size. If your report is difficult to interpret due to poor formatting or the grammar and spelling are a mess, it will detract from the technical results of the assessment. Consider a tool such as Grammarly or LanguageTool (but be aware these tools may ship some of your data to the cloud to "learn"), which is much more powerful than Microsoft Word's built-in spelling and grammar check.
- Use raw command output where possible, but when you need to screenshot a console, make sure it's not transparent and showing your background/other tools (this looks terrible). The console should be solid black with a reasonable theme (black background, white or green text, not some crazy multi-colored theme that will give the reader a headache). Your client may print the report, so you may want to consider a light background with dark text, so you don't demolish their printer cartridge.
- Keep your hostname and username professional. Don't show screenshots with a prompt like `azzkicker@clientsmasher`.
- Establish a QA process. Your report should go through at least one, but preferably two rounds of QA (two reviewers besides yourself). We should never review our own work (wherever possible) and want to put together the best possible deliverable, so pay attention to the QA process. At a minimum, if you're independent, you should sleep on it for a night and review it again. Stepping away from the report for a while can sometimes help you see things you overlook after staring at it for a long time.
- Establish a style guide and stick to it, so everyone on your team follows a similar format and reports look consistent across all assessments.
- Use autosave with your notetaking tool and MS Word. You don't want to lose hours of work because a program crashes. Also, backup your notes and other data as you go, and don't store everything on a single VM. VMs can fail, so you should move evidence to a secondary location as you go. This is a task that can and should be automated.
- Script and automate wherever possible. This will ensure your work is consistent across all assessments you perform, and you don't waste time on tasks repeated on every assessment.

## Acronyms

- `VPN, SSH` - a protocol used for secure remote administration
- `SSL/TLS` - technology used to facilitate secure web browsing
- `Hash` - the output from an algorithm commonly used to validate file integrity
- `Password Spraying` - an attack in which a single, easily-guessable password is attempted for a large list of harvested user accounts
- `Password Cracking` - an offline password attack in which the cryptographic form of a user’s password is converted back to its human-readable form
- `Buffer overflow/deserialization/etc.` - an attack that resulted in remote command execution on the target host
- `OSINT` - Open Source Intelligence Gathering, or hunting/using data about a company and its employees that can be found using search engines and other public sources without interacting with a company's external network
- `SQL injection/XSS` - a vulnerability in which input is accepted from the user without sanitizing characters meant to manipulate the application's logic in an unintended manner