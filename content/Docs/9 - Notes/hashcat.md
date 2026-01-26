+++
title = "Hashcat"
+++

Hashcat is a fast password recovery tool that supports multiple attack modes and hash types. It's the world's fastest and most advanced password recovery utility.

**References:**
- Hash Type Codes: <https://hashcat.net/wiki/doku.php?id=example_hashes>
- Permutation Rules: `/usr/share/hashcat/rules`
- Cheat Sheet: <https://pentesting.site/cheat-sheets/hashcat/>
- Rule-Based Attack: <https://hashcat.net/wiki/doku.php?id=rule_based_attack>

## Basic Usage

```bash
# Basic syntax
hashcat -m <HASH_MODE> -a <ATTACK_MODE> <HASH_FILE> <WORDLIST>

# Common flags
-m <MODE>     : Hash type mode (see hash types below)
-a <MODE>    : Attack mode (0=straight, 1=combinator, 3=brute-force/mask, 6=hybrid wordlist+mask)
-r <RULE>    : Rule file for rule-based attack
--force      : Ignore warnings (use with caution)
--stdout     : Output to stdout instead of cracking
-w <LEVEL>   : Workload profile (1-4, higher = faster but more resource intensive)
-O            : Optimized kernels (limits password length)
```

## Attack Modes

| Mode | Description | Example |
| :--- | :--- | :--- |
| **0** | **Straight** (Dictionary) | `hashcat -a 0 -m 1000 hash.txt wordlist.txt` |
| **1** | **Combinator** | Combines words from two wordlists |
| **3** | **Brute-Force/Mask** | `hashcat -a 3 -m 1000 hash.txt ?a?a?a?a?a?a` |
| **6** | **Hybrid Wordlist + Mask** | Wordlist + mask pattern |

## Common Hash Types & Modes

### Windows Hashes

```bash
# NT hashes (NTLM)
hashcat -m 1000 <HASHES> <WORDLIST>

# PBKDF2 (DCC2 hashes for domain - cached domain credentials)
hashcat -m 2100 <HASHES> <WORDLIST>
```

### Linux Hashes

```bash
# SHA-512crypt (most common legacy default)
hashcat -m 1800 hashes.txt <WORDLIST>

# MD5crypt (with salt)
hashcat -m 20 <HASH>:<SALT> <WORDLIST>
```

### Kerberos (Active Directory)

```bash
# Kerberoasting - RC4 encrypted TGS (Type 23)
hashcat -m 13100 spn_tickets.txt <WORDLIST>

# Kerberoasting - AES-256 encrypted TGS (Type 18)
hashcat -m 19600 spn_tickets.txt <WORDLIST>

# Kerberoasting - AES-128 encrypted TGS (Type 17)
hashcat -m 19700 spn_tickets.txt <WORDLIST>
```

### Other Hash Types

```bash
# Bitlocker
hashcat -a 0 -m 22100 hash_crackme_vhd.txt <WORDLIST>

# IPMI (HP iLO)
hashcat -m 7300 ipmi_hash.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
hashcat -m 7300 -w 3 -O "<HASH>" /usr/share/wordlists/rockyou.txt
```

## Rule-Based Attacks

Rule-based attacks apply transformations to words in a wordlist, creating permutations and variations.

### Rule Files Location

```bash
# Default rule files location
/usr/share/hashcat/rules
```

### Rule Comparison Table

| Rule File | Rule Count | Use Case |
| :--- | :--- | :--- |
| **`best64.rule`** | 64 | **First Run.** Instant results for easy passwords. |
| **`d3ad0ne.rule`** | ~34,000 | **Deep Crack.** Good for standard "complex" user passwords. |
| **`dive.rule`** | ~100,000+ | **Paranoid.** Extremely slow; last resort for dictionary attacks. |

### Using Rules

```bash
# Apply rule file to wordlist
hashcat -m 1800 -r /usr/share/hashcat/rules/best64.rule hashes.txt <WORDLIST>
```

### Creating Custom Rules

Common rule transformations:

| Rule | Description | Example |
| :--- | :--- | :--- |
| `c` | Capitalize first character, lowercase rest | `password` → `Password` |
| `C` | Lowercase first character, uppercase rest | `password` → `pASSWORD` |
| `t` | Toggle case of all characters | `password` → `PASSWORD` |
| `$!` | Append `!` to end | `password` → `password!` |
| `$1$9$9$8` | Append `1998` to end | `password` → `password1998` |
| `sa@` | Replace all `a` with `@` | `password` → `p@ssword` |
| `so0` | Replace all `o` with `0` | `password` → `passw0rd` |
| `ss$` | Replace all `s` with `$` | `password` → `pa$$word` |

**Example Custom Rule File:**

```bash
cat << EOF > custom.rule
c
C
t
\$!
\$1\$9\$9\$8
\$1\$9\$9\$8\$!
sa@
so0
ss\$
EOF

# Generate permutated wordlist
hashcat --force -r custom.rule keywords.txt --stdout | sort -u > wordlist.txt

# Crack hash with custom rule
hashcat -a 0 -m <HASH_ID> -r custom.rule <HASH> wordlist.txt
```

## Mask Attacks (`-a 3`)

Mask attacks use placeholders to define character sets and patterns for brute-force attacks.

### Charset Symbols

| Symbol | Description | Charset / Definition |
| :--- | :--- | :--- |
| **`?l`** | Lowercase | `abcdefghijklmnopqrstuvwxyz` |
| **`?u`** | Uppercase | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| **`?d`** | Digits | `0123456789` |
| **`?h`** | Hex (Lower) | `0123456789abcdef` |
| **`?H`** | Hex (Upper) | `0123456789ABCDEF` |
| **`?s`** | Special | «space»!"#$%&'()*+,-./:;<=>?@[]^_{` |
| **`?a`** | All | `?l?u?d?s` |
| **`?b`** | Binary | `0x00 - 0xff` |

### Custom Charsets

```bash
# Define custom charset with -1, -2, -3, -4
# -1 ?d?u means charset 1 = digits + uppercase
hashcat -a 3 -m 7300 hash.txt ?1?1?1?1?1?1?1?1 -1 ?d?u
```

### Mask Examples

```bash
# Pattern: 1 uppercase, 4 lowercase, 1 digit, 1 special
hashcat -a 3 -m <HASH_ID> <HASH> '?u?l?l?l?l?d?s'

# 8 characters: digits or uppercase
hashcat -a 3 -m 7300 hash.txt ?1?1?1?1?1?1?1?1 -1 ?d?u
```

## Hash Identification

Before cracking, identify the hash type:

```bash
# Use hashid to identify hash and get hashcat mode
hashid -jm '<HASH>'

# Alternative: online tool
# https://hashes.com/en/tools/hash_identifier
```

## Common Hash Values

| Hash Value | Type | Meaning |
| :--- | :--- | :--- |
| **`d41d8cd98f00b204e9800998ecf8427e`** | **MD5** | **Empty String** (0 byte input) |
| **`da39a3ee5e6b4b0d3255bfef95601890afd80709`** | **SHA1** | **Empty String** (0 byte input) |
| **`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`** | **SHA256** | **Empty String** (0 byte input) |

## Workflow Examples

### Linux Password Cracking

```bash
# 1. Prepare unshadowed file
unshadow /etc/passwd /etc/shadow > unshadowed.hashes

# 2. Crack with hashcat (SHA-512, mode 1800)
hashcat -m 1800 -a 0 unshadowed.hashes rockyou.txt
```

### Kerberoasting

```bash
# 1. Get TGS tickets
impacket-GetUserSPNs -dc-ip <DC_IP> <DOMAIN>/<USER> -request -outputfile spn_tickets.txt

# 2. Crack TGS (RC4, most common)
hashcat -m 13100 spn_tickets.txt <WORDLIST>

# 3. If AES-256, use mode 19600
hashcat -m 19600 spn_tickets.txt <WORDLIST>
```

### Windows NT Hashes

```bash
# Extract hashes from SAM
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL

# Crack NT hashes
hashcat -m 1000 <HASHES> <WORDLIST>
```

## Important Notes

- **Hash Mode**: Always specify the correct `-m` mode for your hash type. Use `hashid` or check the hash format to determine the mode.
- **Wordlists**: Common wordlists include `rockyou.txt`, `SecLists`, and custom wordlists generated from OSINT.
- **Rules**: Start with `best64.rule` for quick results, then move to more comprehensive rules if needed.
- **Performance**: Use `-w 3` or `-w 4` for faster cracking (uses more resources). Use `-O` for optimized kernels (may limit password length).
- **GPU Acceleration**: Hashcat automatically uses GPU if available. Ensure proper drivers are installed.
- **Resume Sessions**: Hashcat saves progress automatically. Use `--restore` to resume interrupted sessions.
- **Output**: Cracked passwords are saved to `~/.hashcat/hashcat.potfile` by default.
