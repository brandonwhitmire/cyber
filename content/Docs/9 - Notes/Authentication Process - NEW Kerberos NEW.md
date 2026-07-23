+++
title = "Authentication Process - Kerberos"
type = "home"
+++

**WIP: currently this is AI slop distilled from handouts and notes** 

## Core Concepts & Flow

Kerberos is a ticket-based authentication protocol. It relies on a trusted third party, the **Key Distribution Center (KDC)**, which resides on the Domain Controller (DC).

{{< img src="AD-auth-process.png" alt="Kerberos Authentication Process" >}}

1.  **AS-REQ (Authentication Service Request):** User encrypts a timestamp with their password hash and sends it to the KDC.
2.  **AS-REP (Authentication Service Reply):** KDC validates the hash. If correct, issues a **TGT (Ticket Granting Ticket)**. The TGT is valid for a specific time (default 10 hours) and is signed by the **KRBTGT** account.
3.  **TGS-REQ (Ticket Granting Service Request):** User presents the TGT to the KDC and requests access to a specific service (e.g., SQL, CIFS).
4.  **TGS-REP (Ticket Granting Service Reply):** KDC validates the TGT. Issues a **TGS (Service Ticket)**. This ticket is encrypted using the **Service Account's** password hash (Machine account or User account).
5.  **AP-REQ (Application Request):** User presents the TGS to the Application Server/Service. Service decrypts the ticket using its own hash to validate access.
6.  **AP-REP (Application Reply):** Access Granted

---

## Ticket Forgery Attacks

### Golden Tickets (Forged TGT)
A Golden Ticket is a forged TGT. It bypasses the authentication step (`AS-REQ`) entirely.

*   **Requirement:** The NTLM hash of the `KRBTGT` account.
*   **Scope:** **Complete Domain Compromise.** You can request a TGS for *any* service on *any* machine.
*   **Mechanics:**
    *   You are forging the proof of identity that the KDC trusts.
    *   You can impersonate non-existent users (as long as the ticket timestamp is >20 mins old).
    *   You can set the ticket validity to 10+ years.
    *   Bypasses Smart Card requirements (since TGT issuance is the result of SC checks).
*   **Persistence:**
    *   Access remains valid until the `KRBTGT` password is rotated **twice** (AD keeps the current and previous hash valid).
    *   Detection is difficult as TGT generation can occur off-domain.

### Silver Tickets (Forged TGS)
A Silver Ticket is a forged Service Ticket. It bypasses the KDC entirely and interacts directly with the target server.

*   **Requirement:** The NTLM hash of the **Target Service Account** (usually the Computer Account hash).
*   **Scope:** **Limited.** Grants administrative access *only* to the specific service on the specific host targeted.
*   **Mechanics:**
    *   You are skipping the KDC/DC steps (1-4). There is no network traffic to the DC.
    *   Logs only appear on the target server, making detection difficult for centralized SIEMs.
    *   Can create non-existent users with custom SIDs (e.g., Domain Admin SID) inside the ticket.
*   **Persistence:**
    *   Valid until the Machine Account password rotates (default 30 days).
    *    Attackers may disable machine password rotation in the registry to maintain access.

---

## Account & Attribute Persistence

### SID History Injection
The `sidHistory` attribute is designed for domain migrations to allow users to retain access to resources in their old domain.

*   **Attack:** Injecting the SID of a privileged group (e.g., Enterprise Admins) into the `sidHistory` of a low-privileged account.
*   **Mechanism:** When a user logs in, the PAC (Privilege Attribute Certificate) includes SIDs from their own groups **AND** their SID History.
*   **Stealth:** The user does *not* appear in the "Domain Admins" group in AD Users and Computers. Detection requires filtering specific user attributes.
*   **Removal:** Difficult; requires clearing the protected attribute via AD-RSAT tools.

### Certificate Persistence (AD CS)
Forging authentication certificates using a compromised Certificate Authority (CA).

*   **Mechanism:** Exporting the CA certificate and private key to mint new user certificates.
*   **Impact:** Allows requesting TGTs indefinitely.
*   **Severity:** **Critical/Nuclear.**
    *   Persists through user password changes.
    *   Persists through `KRBTGT` rotation.
    *   The rogue certificates are not in the CA's issued list, so they cannot be individually revoked.
    *   **Remediation:** Requires revoking the **Root CA**, effectively breaking the entire trust infrastructure of the domain.

---

## Structural Persistence

### AdminSDHolder & SDProp
A mechanism to ensure protected groups (Domain Admins, etc.) stay secure, often abused for "self-healing" persistence.

*   **Mechanism:** The `AdminSDHolder` container acts as a template. Every 60 minutes, the **SDProp** process copies permissions from `AdminSDHolder` to all protected groups.
*   **Attack:** An attacker modifies the ACL of `AdminSDHolder` to give a low-priv user "Full Control."
*   **Persistence:** Even if an admin manually removes the attacker's permissions from the Domain Admin group, SDProp will automatically re-add them within an hour.

### Group Nesting & Modification
Hiding access in plain sight by manipulating group structures.

*   **Nesting:** Adding a compromised account to a mundane group (e.g., "Printer Admins"), which is nested inside "IT Support," which is nested inside "Domain Admins." Bypasses shallow monitoring alerts.
*   **Shadow Groups:** Leveraging groups with indirect access, such as groups that have write access to GPOs or password reset rights on Admin accounts.

### GPO Implants
Using Group Policy Objects to deploy persistence across the fleet.

*   **Restricted Groups:** Pushing a policy that adds a compromised domain user to the Local Administrators group of every PC.
*   **Logon Scripts:** Configuring a GPO to run a reverse shell script every time a user (or specifically an Admin) logs in.

---

## Machine/Host Persistence

### DSRM (Directory Services Restore Mode)
Every DC has a local administrator account used for recovery (DSRM).

*   **Attack:** Dumping this local hash (often set at DC promotion and never changed).
*   **Persistence:** Configuring the DC to allow DSRM login via network (registry key `DsrmAdminLogonBehavior`). Allows persistent local admin access to the DC essentially independent of AD.

### MOSTLY DEAD TECHNIQUES

#### Skeleton Keys
Patching the `lsass.exe` process on a Domain Controller memory to accept a "Master Password."

*   **Effect:** The attacker can authenticate as *any* user using the master password.
*   **Stealth:** The real user passwords still work normally.
*   **Limitation:** Persistence is lost if the DC reboots.

#### Malicious SSP (Security Support Provider)
Registering a malicious DLL (like `mimilib.dll`) as a security provider on the DC.

*   **Effect:** Logs cleartext passwords of every user authenticating against that DC to a local file or network share.
*   **Persistence:** Survives reboots and operates as part of the OS authentication subsystem.