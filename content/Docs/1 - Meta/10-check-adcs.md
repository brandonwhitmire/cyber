+++
title = "10 - Check - ADCS (Certificate Services)"
draft = true
+++

## Active Directory Certificate Services (ADCS)

### Enumeration

1. [ ] Scan for vulnerable certificate templates using Certipy
    - [ADCS Attack Reference]({{% ref "active-directory-adcs.md#adcs-attack-reference" %}})
    - Look for `[!] Vulnerabilities:` lines in output
    - Identify ESC type and jump to the matching step below

### Exploitation

2. [ ] ESC1 -- Enrollee controls the Subject Alternative Name (SAN)
    - [ESC1 -- User-Controllable SAN]({{% ref "active-directory-adcs.md#esc1-user-controllable-san" %}})
    - Request cert with administrator UPN -> authenticate -> NT hash

3. [ ] ESC2 -- Any Purpose EKU on template
    - [ESC2 -- Any Purpose EKU]({{% ref "active-directory-adcs.md#esc2-any-purpose-eku" %}})
    - Enroll on ESC2 template -> use result as enrollment agent -> chain into ESC3 path

4. [ ] ESC3 -- Enrollment Agent certificate abuse
    - [ESC3 -- Enrollment Agent Abuse]({{% ref "active-directory-adcs.md#esc3-enrollment-agent-abuse" %}})
    - Obtain agent cert -> request cert on behalf of Administrator

5. [ ] ESC4 -- Write access over a certificate template ACL
    - [ESC4 -- Vulnerable Template ACL]({{% ref "active-directory-adcs.md#esc4-vulnerable-template-acl" %}})
    - Save original config -> overwrite with ESC1-exploitable settings -> exploit as ESC1 -> restore

6. [ ] ESC6 -- CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
    - [ESC6 -- EDITF_ATTRIBUTESUBJECTALTNAME2]({{% ref "active-directory-adcs.md#esc6-editf_attributesubjectaltname2" %}})
    - Any Client Auth template allows SAN specification -> request with admin UPN

7. [ ] ESC7 -- Low-privileged user has Officer or Manager rights on the CA
    - [ESC7 -- Vulnerable CA ACL]({{% ref "active-directory-adcs.md#esc7-vulnerable-ca-acl" %}})
    - Add self as Officer -> enable SubCA template -> issue denied request manually

8. [ ] ESC8 -- NTLM relay to HTTP certificate enrollment endpoint
    - [ESC8 -- NTLM Relay to HTTP Enrollment]({{% ref "active-directory-adcs.md#esc8-ntlm-relay-to-http-enrollment" %}})
    - Relay to `/certsrv/certfnsh.asp` + coerce DC authentication (PetitPotam) -> DC certificate -> NT hash

### Nothing Found

9. [ ] Pivot to other attack paths
    - [Unconstrained / Constrained / RBCD Delegation]({{% ref "netexec.md#unconstrained-delegation" %}})
    - Check BloodHound for `GenericWrite` on users (Shadow Credentials)
    - [NoPac / SAMAccountName Spoofing]({{% ref "active-directory.md" %}})
    - [Active Directory Checklist]({{% ref "09-check-active-directory.md" %}})
