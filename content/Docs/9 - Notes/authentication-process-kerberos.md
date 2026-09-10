+++
title = "Authentication Process - Kerberos"
type = "home"
+++

**NOTE:** AI + manually written hybrid

## Core Concepts

Kerberos is a ticket-based authentication protocol. It relies on a trusted third party, the **Key Distribution Center (KDC)**, which resides on the Domain Controller (DC).

{{< img src="AD-auth-process.png" alt="Kerberos Authentication Process" >}}

1.  **AS-REQ (Authentication Service Request):** User encrypts a timestamp with their password hash and sends it to the KDC.
2.  **AS-REP (Authentication Service Reply):** KDC validates the hash. If correct, issues a **TGT (Ticket Granting Ticket)**. The TGT is valid for a specific time (default 10 hours) and is signed by the **KRBTGT** account.
3.  **TGS-REQ (Ticket Granting Service Request):** User presents the TGT to the KDC and requests access to a specific service (e.g., SQL, CIFS).
4.  **TGS-REP (Ticket Granting Service Reply):** KDC validates the TGT. Issues a **TGS (Service Ticket)**. This ticket is encrypted using the **Service Account's** password hash (Machine account or User account).
5.  **AP-REQ (Application Request):** User presents the TGS to the Application Server/Service. Service decrypts the ticket using its own hash to validate access.
6.  **AP-REP (Application Reply):** Access Granted

### DC Replication (KCC)
The **Knowledge Consistency Checker (KCC)** generates a replication topology for the AD forest and automatically connects to other domain controllers through Remote Procedure Calls (RPC) to synchronize information.

## Target Prioritization

`Domain Admins` is the technical end goal, but those credentials get rotated quickly once compromise is suspected. Prioritize near-privileged accounts instead:

*   **Credentials with local admin rights on several machines.** Most orgs have a group (or two -- one for workstations, one for servers) with local admin rights across the estate. Harvesting these gives access to most of the environment.
*   **Service accounts with delegation permissions.** These let you force golden and silver tickets to perform Kerberos delegation attacks.
*   **Accounts used for privileged AD services.** Compromising Exchange, WSUS, or SCCM service accounts can be leveraged for a privileged foothold into AD.

We often want to persist through service accounts with delegation permissions specifically to forge silver and golden tickets.

## Ticket Forgery Attacks

### Golden Tickets (Forged TGT)
A Golden Ticket is a forged TGT. It bypasses the authentication step (`AS-REQ`) entirely.

*   **Requirement:** The NTLM hash of the `KRBTGT` account. You do **not** need the target user's password -- only the domain name, domain SID, and target user ID, all of which are derivable once you have the KRBTGT hash.
*   **Scope:** **Complete Domain Compromise.** You can request a TGS for *any* service on *any* machine.
*   **Mechanics:**
    *   You are forging the proof of identity that the KDC trusts.
    *   You can impersonate non-existent, disabled, or deleted users, as long as the ticket timestamp is >20 mins old (the KDC only validates the account if the ticket is older than 20 minutes).
    *   You can set the ticket validity to 10+ years, overriding the default 10-hour KDC policy.
    *   Bypasses Smart Card requirements (since TGT issuance is the result of SC checks).
    *   Can be generated on any machine, even one that isn't domain-joined, making detection harder.
*   **Persistence:**
    *   Access remains valid until the `KRBTGT` password is rotated **twice** (AD keeps the current and previous hash valid).
    *   Rotating KRBTGT is painful for the blue team -- it breaks services that hold a TGT with a still-valid timestamp but a now-invalid signature. Not all services are smart enough to detect this and auto-request a new TGT, so services can silently fail for hours after rotation.
    *   Detection is difficult as TGT generation can occur off-domain.

### Silver Tickets (Forged TGS)
A Silver Ticket is a forged Service Ticket. It bypasses the KDC entirely and interacts directly with the target server.

*   **Requirement:** The NTLM hash of the **Target Service Account** (usually the Computer Account hash).
*   **Scope:** **Limited.** Grants administrative access *only* to the specific service on the specific host targeted -- versus a Golden Ticket's domain-wide scope.
*   **Mechanics:**
    *   You are skipping the KDC/DC steps (1-4). There is no network traffic to the DC, so no associated TGT exists.
    *   Logs only appear on the target server, making detection difficult for centralized SIEMs -- more limited in scope than a Golden Ticket, but significantly harder to detect.
    *   Can create non-existent users with custom SIDs (e.g., Domain Admin SID) inside the ticket, since permissions are resolved via SIDs.
*   **Persistence:**
    *   Valid until the Machine Account password rotates (default 30 days).
    *   Attackers may disable machine password rotation via the registry to maintain access.
    *   A compromised machine account isn't just a dead end -- it can be used like a normal AD account, giving you a foothold to continue enumerating and exploiting AD beyond the single host.

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
    *   You can continue requesting TGTs regardless of how many rotations occur -- the only way to get kicked out is revocation or expiry of the certificate itself, giving roughly 5 years of persistence by default.
    *   **Remediation:** Requires revoking the **Root CA**, effectively breaking the entire trust infrastructure of the domain.

## Engagement Scope Warning

**The techniques from Structural Persistence and Machine/Host Persistence onward are incredibly invasive and hard to remove.** Even with signoff on a red team exercise, exercise utmost caution:

*   In real-world scenarios, exploiting most of these techniques would result in a full domain rebuild.
*   Make sure you fully understand the consequences and only perform them if you have prior approval and they are deemed necessary.
*   In most cases, a red team exercise would be de-chained at this point instead of executing these techniques -- meaning you'd most likely simulate rather than perform them.

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
