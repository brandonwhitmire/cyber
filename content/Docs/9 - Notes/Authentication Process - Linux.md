+++
title = "Authentication Process - Linux"
type = "home"
+++

### 1. Core Architecture: PAM
**Pluggable Authentication Modules (PAM)** manage the authentication, session setup, and password changes.
*   **Key Module:** `pam_unix.so` (Standard Unix auth).
*   **Location:** `/usr/lib/x86_64-linux-gnu/security/`
*   **Function:** Bridges the gap between user input (e.g., `passwd` command) and flat files (`/etc/passwd`, `/etc/shadow`).

---

### 2. Critical Files & Storage

#### A. The User Registry (`/etc/passwd`)
*   **Permissions:** World-Readable.
*   **Format:** `Username:Password:UID:GID:GECOS:Home:Shell`
*   **Key Fields:**
    *   **Password (`x`):** Indicates the hash is actually in `/etc/shadow`.
    *   **Exploit:** If writeable, deleting the `x` removes the password requirement for that user (e.g., `root::0:0...` allows passwordless login).

#### B. The Secrets (`/etc/shadow`)
*   **Permissions:** Root-Readable only.
*   **Format:** `Username:Hash:LastChange:Min:Max:Warn:Inactive:Expire:Reserved`
*   **Status Flags:**
    *   `!` or `*`: Account is locked (cannot login via password).
    *   *Note:* SSH Key auth or `su` might still work even if locked.

#### C. Password History (`/etc/security/opasswd`)
*   **Permissions:** Root-Readable.
*   **Function:** Stores previously used password hashes to enforce history policies (prevent reuse).
*   **Value:** Often contains older, weaker hashes (MD5) useful for pattern analysis.

---

### 3. Hash Formats & Algorithms
Linux hashes follow the format: `$<id>$<salt>$<hash>`

| ID | Algorithm | Notes |
| :--- | :--- | :--- |
| **$1$** | **MD5** | Weak. Fast to crack. |
| **$2a$** | **Blowfish** | Slower (Bcrypt). |
| **$5$** | **SHA-256** | Standard. |
| **$6$** | **SHA-512** | Standard / Strong. |
| **$y$** | **Yescrypt** | Modern Default (Debian/Kali). Harder to crack. |
| **$7$** | **Scrypt** | Memory hard. |

---

### 4. Cracking Workflow

**1. Prepare the File (Unshadow)**
Combine `passwd` and `shadow` to give the cracker the necessary context (Usernames, GECOS, and Hash).
```bash
# Syntax: unshadow <PASSWD_FILE> <SHADOW_FILE>
unshadow /etc/passwd /etc/shadow > unshadowed.hashes
```

**2. Crack (Hashcat)**
*   **Format:** SHA-512 (Mode 1800) is the most common legacy default.
```bash
hashcat -m 1800 -a 0 unshadowed.hashes rockyou.txt
```

**3. Crack (John the Ripper)**
*   **Mode:** `--single` is highly effective here because `unshadow` provides the GECOS fields for guessing.
```bash
john --single unshadowed.hashes
```