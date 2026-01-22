+++
title = "Authentication Process - Windows"
type = "home"
+++

![Authentication Process - Windows](/images/win_auth_process.png)

### 1. Key Processes & Architecture

**WinLogon** (`WinLogon.exe`)
*   **Role:** The "orchestrator." Intercepts keyboard input (`Ctrl+Alt+Del`), manages the workstation lock status, and handles password changes.
*   **Workflow:** Launches `LogonUI` -> Collects Creds -> Sends to `LSASS`.
*   **Legacy Note (GINA):** In older Windows (NT/XP), `msgina.dll` handled this. Replaced by **Credential Providers** in modern Windows.

**LogonUI** (`LogonUI.exe`)
*   **Role:** The graphical user interface that asks for the password.
*   **Mechanism:** Uses **Credential Providers** (COM Objects/DLLs) to accept different auth types (Password, PIN, Biometrics).

**LSASS** (`%SystemRoot%\System32\Lsass.exe`)
*   **Role:** The "Gatekeeper." Enforces security policy, validates the password against SAM/AD, and writes to the Event Log.
*   **Resources:** [Microsoft: LSA Architecture](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication/local-security-authority-architecture)

---

### 2. Authentication DLLs (The Packages)
These modules live inside `LSASS` to handle specific tasks.

| DLL Name | Function / Description |
| :--- | :--- |
| **Lsasrv.dll** | **The Manager.** Enforces policy and chooses the protocol (Negotiate: Kerberos vs NTLM). |
| **Msv1_0.dll** | **Local / NTLM.** Handles non-domain logins and legacy NTLM authentication. |
| **Kerberos.dll** | **Domain.** Handles Kerberos ticket requests and validation. |
| **Samsrv.dll** | **SAM Interface.** Talks to the local SAM database. |
| **Netlogon.dll** | **Network.** Handles the secure channel for network logons. |
| **Ntdsa.dll** | **AD Interface.** Used to create/manage records in the Registry or AD. |

---

### 3. Credential Storage Locations

**Local Users (SAM)**
*   **File Path:** `%SystemRoot%\system32\config\SAM`
*   **Registry Mount:** `HKLM\SAM`
*   **Protection:** Partially encrypted by **SYSKEY** (`syskey.exe`) to prevent offline extraction.
*   **Content:** Local user NTLM/LM hashes.

| Registry Hive   | Description                                                                                                                                                       |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `HKLM\SAM`      | Contains password hashes for local user accounts. These hashes can be extracted and cracked to reveal plaintext passwords.                                        |
| `HKLM\SYSTEM`   | Stores the system boot key, which is used to encrypt the SAM database. This key is required to decrypt the hashes.                                                |
| `HKLM\SECURITY` | Contains sensitive information used by the Local Security Authority (LSA), including cached domain credentials (DCC2), cleartext passwords, DPAPI keys, and more. |

**Domain Users (NTDS)**
*   **File Path:** `%SystemRoot%\ntds.dit`
*   **Location:** Found only on **Domain Controllers**.
*   **Content:** Active Directory database (Users, Groups, Computers, GPOs, Hashes).
*   **Sync:** Replicates to all DCs (except Read-Only DCs).

**Credential Manager (The Vault)**
*   **Role:** Stores saved passwords for RDP, Websites, and Network Shares.
*   **`Policy.vpol` in File Path:**
- `%UserProfile%\AppData\Local\Microsoft\Vault\`
- `%UserProfile%\AppData\Local\Microsoft\Credentials\`
- `%UserProfile%\AppData\Roaming\Microsoft\Vault\`
- `%ProgramData%\Microsoft\Vault\`
- `%SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\`

*   **Resource:** [Microsoft: Credential Manager](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-manager)

![Windows Credential Manager](/images/win_credential_manager.gif)