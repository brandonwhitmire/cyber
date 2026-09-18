+++
title = "Hashcat"
+++

Hashcat is a fast password recovery tool that supports multiple attack modes and hash types. It's the world's fastest and most advanced password recovery utility.

**References:**
- Permutation Rules: `/usr/share/hashcat/rules`
- Cheat Sheet: <https://pentesting.site/cheat-sheets/hashcat/>
- Rule-Based Attack: <https://hashcat.net/wiki/doku.php?id=rule_based_attack>

## Common Hash Values

| Hash Value | Type | Meaning |
| :--- | :--- | :--- |
| **`d41d8cd98f00b204e9800998ecf8427e`** | **MD5** | **Empty String** (0 byte input) |
| **`da39a3ee5e6b4b0d3255bfef95601890afd80709`** | **SHA1** | **Empty String** (0 byte input) |
| **`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`** | **SHA256** | **Empty String** (0 byte input) |

## Hash Identification

Before cracking, identify the hash type:

```bash
# Use hashid to identify hash and get hashcat mode
hashid -jm '<HASH>'

# Alternative: online tool
# https://hashes.com/en/tools/hash_identifier
```


## Quick Password Mutation

If making a custom password list from some target and environment information, that list can be mutated with `hashcat` given a list of something like:

**`pwlist.txt`**:
```
Welcome1
Password1
Password
P@ssw0rd
Changem123
Secret
January
February
March
April
May
June
July
August
September
October
November
December
Winter
Spring
Summer
Fall
<BOX_HOSTNAME>
<COMPANY>
```

```bash
for i in $(cat pwlist.txt); do echo $i; echo ${i}\!; echo ${i}2025; echo ${i}2026; done > passwords.txt

hashcat \
    -r /usr/share/hashcat/rules/best66.rule \
    -r /usr/share/hashcat/rules/toggles1.rule \
    --stdout passwords.txt | sort -u > passwords_mutated.txt
```

## Important Notes

- **Hash Mode**: Always specify the correct `-m` mode for your hash type. Use `hashid` or check the hash format to determine the mode.
- **Wordlists**: Common wordlists include `rockyou.txt`, `SecLists`, and custom wordlists generated from OSINT.
- **Rules**: Start with `best66.rule` for quick results, then move to more comprehensive rules if needed.
- **Performance**: Use `-w 3` or `-w 4` for faster cracking (uses more resources). Use `-O` for optimized kernels (may limit password length).
- **GPU Acceleration**: Hashcat automatically uses GPU if available. Ensure proper drivers are installed.
- **Resume Sessions**: Hashcat saves progress automatically. Use `--restore` to resume interrupted sessions.
- **Output**: Cracked passwords are saved to
    - `~/.hashcat/hashcat.potfile`
    - `~/.local/share/hashcat/hashcat.potfile`
- **Username**: Sometimes it strips the name from hits... to show username and passwords run:
    - `hashcat --username --show <CRACKME>`

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

- Hash Type Codes: <https://hashcat.net/wiki/doku.php?id=example_hashes>
    - `hashcat --example-hashes | grep -i <SEARCH>`

| Hash Type | Explanation |
| :--- | :--- |
| **NTLM** (`-m 1000`) | Windows NT hashes; usable for Pass-the-Hash. |
| **DCC2 / MS Cache 2** (`-m 2100`) | Domain Cached Credentials 2 (`$DCC2$`), PBKDF2-based. Much stronger than NTLM and cannot be used for Pass-the-Hash. |
| **SHA-512crypt** (`-m 1800`) | Most common legacy Linux default (`$6$`). |
| **MD5crypt** (`-m 20`) | Linux MD5 with salt, formatted `<HASH>:<SALT>`. |
| **Kerberoast RC4 TGS** (`-m 13100`) | AD service ticket, Type 23 (RC4-encrypted). |
| **Kerberoast AES-256 TGS** (`-m 19600`) | AD service ticket, Type 18 (AES-256). |
| **Kerberoast AES-128 TGS** (`-m 19700`) | AD service ticket, Type 17 (AES-128). |
| **BitLocker** (`-m 22100`) | Encrypted volume recovery. |
| **IPMI / HP iLO** (`-m 7300`) | RAKP hashes; often numeric PINs -- brute-force with `-a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u`. |

## Rule-Based Attacks

Rule-based attacks apply transformations to words in a wordlist, creating permutations and variations

### Rule Files Location

```bash
# Default rule files location
/usr/share/hashcat/rules
```

### Rule Comparison Table

| Rule File           | Rule Count | Use Case                                                                                                       |
| :------------------ | :--------- | :------------------------------------------------------------------------------------------------------------- |
| **`best66.rule`**   | 66         | **First Run.** Instant results for easy passwords.                                                             |
| **`toggles1.rule`** |            | **Optional: Add w/ `base64.rule`** Toggles the case of exactly one letter at a time in each password candidate |
| **`d3ad0ne.rule`**  | ~34,000    | **Deep Crack.** Good for standard "complex" user passwords.                                                    |
| **`dive.rule`**     | ~100,000+  | **Paranoid.** Extremely slow; last resort for dictionary attacks.                                              |

### Using Rules

```bash
# Apply rule file to wordlist
hashcat -m 1800 -r /usr/share/hashcat/rules/best66.rule hashes.txt <WORDLIST>
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
# Keep password as-is, add "1" to end, or "!" to end
cat << EOF > custom.rule
:
\$1
\$!
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

## SSH Key Passphrase Cracking

- https://github.com/HashPals/Name-That-Hash/pull/150

**Known issue:** `hashcat -m 22921` does not support the OpenSSH key-v1 format

| Header                                | Format                                | Cracker            |
| :------------------------------------ | :------------------------------------ | :----------------- |
| `-----BEGIN RSA PRIVATE KEY-----`     | Legacy PEM                            | `hashcat -m 22921` |
| `-----BEGIN OPENSSH PRIVATE KEY-----` | OpenSSH key-v1 (ed25519 / modern RSA) | John only          |

```bash
ssh2john <KEY_FILE> > crackme_ssh_id_rsa.txt

# PEM (RSA legacy)
hashcat -m 22921 --username crackme_ssh_id_rsa.txt /usr/share/wordlists/rockyou.txt

# OpenSSH key-v1 (ed25519 / modern RSA)
john --wordlist=/usr/share/wordlists/rockyou.txt crackme_ssh_id_rsa.txt
```
