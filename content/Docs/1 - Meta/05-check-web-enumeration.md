+++
title = "05 - Check - Web Enumeration"
+++

[Review the default server directories for the particular webserver]({{% ref "http.md#default-server-directories" %}})

## Active Recon

1. [ ] Add domain to `/etc/hosts` file and [`EyeWitness` all pages from `nmap` results]({{% ref "common-web-applications.md#eyewitness" %}})

2. [ ] Fingerprint server technology and check for known CVEs.
    - [Web Technology Fingerprinting]({{% ref "http.md#basic-enumeration" %}})
    - Known CVE for detected version: 
        - Search [ExploitDB](https://www.exploit-db.com/) or GitHub for service exploits with the discovered version
        - Use `searchsploit` locally
        - Search Google for `<Service> <Version> Exploit GitHub`
        - [Search Metasploit for service exploits with the discovered version]({{% ref "metasploit.md" %}})

3. [ ] Look in [`robots.txt` or `sitemap.xml` for hidden endpoints]({{% ref "http.md#basic-enumeration" %}}).

4. [ ] [Crawl the webpage for all links]({{% ref "http.md#crawling" %}})

5. [ ] Run directory brute force.
    - [First fuzz for file extensions]({{% ref "ffuf.md#find-file-extension" %}})
    - [When web technology used (e.g. PHP)  is known, fuzz for directories and other pages (with extension appended)]({{% ref "ffuf.md#search-file-extensions" %}})
    - [Directory Brute-Forcing]({{% ref "http.md#directory-brute-forcing" %}})

6. [ ] Run vhost brute force discovery (**run multiple wordlists**).
    - [vHost Brute Force]({{% ref "ffuf.md#vhost-brute-force" %}})

7. [ ] Fuzz for hidden GET/POST parameters on discovered endpoints.
    - [Parameter Fuzzing]({{% ref "ffuf.md#parameter-fuzzing" %}})

8. [ ] Look for comments in HTML for sensitive information.
    - Check all crawled and discovered pages (EyeWitness)

9. [ ] Capture server errors (e.g. 500, 403) that might leak tech stack info.

10. [ ] Look for web service versions on discovered pages (Jenkins, WP, blog platforms, etc.). Use enumeration techniques depending on the technology.
    - Look for CMS or app-specific files (`wp-content`, `.git/`, etc.)
    - [WordPress Enumeration]({{% ref "common-web-applications.md#wordpress" %}})
    - [Joomla Enumeration]({{% ref "common-web-applications.md#joomla" %}})
    - [Drupal Enumeration]({{% ref "common-web-applications.md#drupal" %}})
    - [Tomcat Enumeration]({{% ref "common-web-applications.md#tomcat" %}})
    - [Jenkins Enumeration]({{% ref "common-web-applications.md#jenkins" %}})
    - IIS Tilde Enumeration
    - Other

## By Finding on Webpage

### Login Form

- [ ] Try default credentials first -- [Default Credential Lists]({{% ref "online-credentials-attacks.md#default-creds" %}})
- [ ] [Test for SQL injection auth bypass]({{% ref "sql-injection.md" %}})
- [ ] [Brute force with Hydra if lockout policy permits]({{% ref "online-credentials-attacks.md#brute-force-hydra" %}})

### Search Field

- [ ] [Test for SQL injection to dump database info]({{% ref "sql-injection.md" %}})

### File Path Parameters

`?page=`, `?file=`, `?path=`

- [ ] [File Inclusion / Path Traversal]({{% ref "web-file-inclusion.md" %}})
- [ ] Run an LFI automation scan against any parameters that reference a file
- [ ] If LFI confirmed, try:
    - local PHP files (in case of filtering)
    - `/etc/passwd`
    - `/home/<username>/.ssh/id_rsa`
    - `/var/mail/<username>` (PHP webshell via mail poisoning)
    - Webserver config: `/etc/nginx/nginx.conf`, `/etc/apache2/sites-enabled/default`
    - Log poisoning: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`
    - Any file paths leaked from error pages

### Admin Panel

- [ ] Try default credentials
- [ ] Test auth bypass headers (`X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`)
- [ ] Test for [IDOR]({{% ref "web-exploitation.md#insecure-direct-object-references-idor" %}}) on user ID parameters

### File Upload

- [ ] [File Upload Exploitation]({{% ref "web-file-upload.md" %}})
- [ ] Chain: extension bypass → `Content-Type` mismatch → magic bytes → SVG XXE → RCE or LFI

### Sequential IDs / Object References

- [ ] [IDOR]({{% ref "web-exploitation.md#insecure-direct-object-references-idor" %}})

### Reflected Input Parameters

- [ ] Template expression (`{{7*7}}`): [SSTI]({{% ref "web-ssti-xxe.md" %}})
- [ ] HTML/JS injection (`<script>alert(1)</script>`): [XSS]({{% ref "web-xss.md" %}})
- [ ] OS command (`; id`): [Command Injection]({{% ref "web-command-injection.md" %}})
- [ ] Path traversal (`../../../etc/passwd`): [File Inclusion / LFI]({{% ref "web-file-inclusion.md" %}})
- [ ] [Intercept and test all input with Burp Suite]({{% ref "web-proxy-tools-zap-burp.md" %}})

### XML Endpoint

`Content-Type: application/xml`, SOAP

- [ ] [XXE Injection]({{% ref "web-ssti-xxe.md" %}})
- [ ] Probe with entity injection → reflected: classic XXE
    - No reflection: try OOB exfil

### HTTP Verb Tampering

- [ ] [HTTP Verb Tampering]({{% ref "web-exploitation.md#http-verb-tampering" %}})

### API Endpoint

- [ ] [API Injection with sqlmap]({{% ref "sqlmap.md" %}})

### Nothing Bites -- Hidden Surface

- [ ] Look for parameters accepting URLs or destinations (`?url=`, `?dest=`, webhooks): [SSRF]({{% ref "web-ssrf.md" %}})
- [ ] Review JavaScript source for hidden endpoints, API keys, GraphQL introspection paths

---

The same information said another way:

# Big Picture

1. Screenshot everything first (EyeWitness) -> triage by interest
2. Prioritize `dev`/`staging`/`vault`/`git` named hosts
3. Every input field maps to a vuln class -- match the observation, test that class first
4. When something's "off" but unfamiliar -> note the behavior, research the class, don't freeze

## By Observation: See This -> Test This First

- **Upload form (CV, profile pic, attachment)**
    - Unrestricted file upload. Test client-side bypass first (change Content-Type to image/png), then extension tricks. Find the upload dir (/uploads) to reach your shell.

- **Parameter referencing a file (`?page=`, `?file=`, `?pl=`)**
    - LFI / path traversal. Pull /etc/passwd to confirm, then log poisoning or source disclosure.

- **Sequential ID in URL (`?id=9`, `/profile/123`, `/invoice/456`)**
    - IDOR. Increment/decrement the number, see if you reach other users' data.

- **Login form**
    - In order: weak creds (admin:admin), SQLi auth bypass (`'`), username enumeration via error messages, then brute force (hydra) as last resort.

- **Single quote throws a DB error**
    - SQLi. Confirm with UNION, then sqlmap to dump.

- **Search box / any field hitting a database**
    - SQLi. Same flow.

- **User-controllable text rendered back to other users (tickets, comments, profiles)**
    - Stored/Blind XSS. Inject a callback payload, escalate to cookie theft.

- **Input generates a PDF / document**
    - SSRF to local file read. HTML/JS renders server-side -> XHR `file:///etc/passwd` payload.

- **XML in the request body**
    - XXE. Define an external entity pointing at /etc/passwd.

- **Restricted shell / "monitoring console" / ping tool**
    - Command injection. Bypass filters with `%0a`, `$IFS`, quote-splitting (`'i'd`).

- **Registration form**
    - Register, then hunt: privilege escalation at signup (role tampering), IDOR once inside, what new pages unlock.

- **Non-standard HTTP methods allowed (OPTIONS shows PUT/TRACK)**
    - HTTP verb tampering. Custom auth headers (`X-Custom-IP-Authorization`) may unlock hidden functionality.

---

## By Application/Service: Fingerprint -> Known Weakness

- **WordPress**
    - wpscan `-e ap` (plugins are the kill, not core). Old plugins = LFI/RCE. Then `-e u` for users -> brute force -> theme editor (404.php) for RCE.

- **Drupal / Joomla**
    - Version check. Old = Drupalgeddon/known CVE. Current = weak admin creds or vulnerable module only.

- **GitLab / Gitea / self-hosted Git**
    - Register if open, browse `/explore`. Hunt exposed repos for secrets, SSH keys, configs, and _hidden subdomains_ referenced in projects.

- **Tomcat**
    - /manager/html, default creds, WAR deploy for RCE.

- **Jenkins**
    - Script console (Groovy) = instant RCE if accessible.

- **Drupal/WP/any CMS with `dev`, `staging`, `test`, `uat` in the name**
    - Assume not hardened. Dig harder. Highest-value targets on the list.

- **VPN / SSL portal (Fortinet, Citrix, Pulse)**
    - Version-check for known CVE. Otherwise careful password spray (lockout risk).

- **Key Vault / password manager / homegrown auth app**
    - High data-exposure payoff. Worth dir brute-forcing for hidden upload/admin pages.
