+++
title = "Offline Hash Cracking"
+++

**Offline attacks = touching the rig.** You use local GPU/CPU on captured data. Risks: none (except overheating).

- https://openwall.info/wiki/john/sample-hashes
- https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats
- https://hashes.com/en/tools/hash_identifier

---

## Hash identification

Prefer **`nth` (Name That Hash)** over `hashid`: it outputs the exact **Hashcat `-m`** and **John format** so you can paste and run. Hashcat can also suggest a mode if you run it without `-m`.

```bash
# Name That Hash (recommended)
uv tool install name-that-hash
nth -t '<HASH_STRING>'
nth -f <HASH_FILE.txt>
```

```bash
# Hashcat autodetect (no -m; it will suggest or prompt)
echo '<HASH>' > detect.hash
hashcat detect.hash --show
# or
hashcat detect.hash <WORDLIST>
```

*Ambiguity:* e.g. 32-char hex can be MD5 or NTLM — context (source) matters. Don’t truncate `==` or leading `$` when copying.

---

## Extraction/Format Conversion

### File to Hash

Convert files/artefacts to a hash format that hashcat or John can crack.

```bash
# Find all JtR utilities
sudo updatedb && locate '*2john' | grep -v 'pycache'

# Zip (then crack: hashcat -m 17200 for PKZIP, or JtR for zips)
zip2john <ZIP_FILE> > hash_zip.txt

# RAR
rar2john <RAR_FILE> > hash_rar.txt

# Office docs
office2john <OFFICE_FILE> > hash_office.txt

# PDF
pdf2john <PDF_FILE> > hash_pdf.txt

# Bitlocker
bitlocker2john -i <VHD_FILE> > pre_hash_vhd.txt
grep "bitlocker\$0" pre_hash_vhd.txt > hash_crackme_vhd.txt
hashcat -a 0 -m 22100 hash_crackme_vhd.txt <WORDLIST>

# Mount with Bitlocker (after cracking)
sudo apt install -y dislocker
sudo mkdir -p /media/{bitlocker,bitlockermount}
sudo losetup -f -P Backup.vhd
ls -la /dev/loop*
sudo dislocker /dev/<LOOP_DEV> -u<PASSWORD> -- /media/bitlocker
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

# SSH: find private keys
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
# Check if key is password protected
ssh-keygen -yf <PRIVKEY>
# Get hash
ssh2john <PRIVKEY> > ssh.hash

# OpenSSL-encrypted archive
while read p; do
    openssl enc -aes-256-cbc -d -in <ENC_FILE> -k "$p" 2>/dev/null | tar xz 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Success! Password is: $p"
        break
    fi
done < <WORDLIST>
```

### Common Hash Values (Empty Input)

| Hash Value | Type | Meaning |
| :--- | :--- | :--- |
| **`d41d8cd98f00b204e9800998ecf8427e`** | **MD5** | **Empty String** (0 byte input) |
| **`da39a3ee5e6b4b0d3255bfef95601890afd80709`** | **SHA1** | **Empty String** (0 byte input) |
| **`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`** | **SHA256** | **Empty String** (0 byte input) |

---

## Wordlist Customization

### Mutating Wordlists

**cewl:** Scrape target site to build a wordlist (e.g. company jargon, names).

```bash
# Create wordlist from website (lowercase, spider depth, min word length)
cewl --lowercase -d <SPIDER_DEPTH> -m <MIN_WORD_LENGTH> -w <WORDLIST_FILENAME> http://<TARGET>
```

**Hashcat rules:** Mutate a small keyword list into a large wordlist.

- https://hashcat.net/wiki/doku.php?id=rule_based_attack

```bash
# Manually generate keywords or use cewl via OSINT
cat << EOF > keywords.txt
<KEYWORDS>
EOF

# Rule examples: c (Capitalize first), C (lowercase first, rest upper), t (toggle case)
# $! append ! ; $1$9$9$8 append 1998 ; sa@ replace a with @ ; so0 replace o with 0 ; ss$ replace s with $
cat << EOF > custom.rule
c
C
t                                                                \$!
\$1\$9\$9\$8
\$1\$9\$9\$8\$!
sa@
so0
ss\$
EOF

# Generate permutated wordlist
hashcat --force -r custom.rule keywords.txt --stdout | sort -u > wordlist.txt

# Crack with same rules
hashcat -a 0 -m <HASH_ID> -r custom.rule <HASH> wordlist.txt
```

### CUPP Profiling

Build a **targeted wordlist** from personal information (name, birthday, pet, company, etc.). Use when you have OSINT on the target and want passwords likely derived from that data.

```bash
git clone https://github.com/Mebus/cupp.git
cd cupp
python3 cupp.py -i
```

Interactive prompts: name, surname, nickname, birthday, partner, pet, company, keywords, etc. Output is a wordlist tailored to the target.

---

## Cracking

### Hash Identification

See **§0. Hash identification** above. Fallback: `hashid -jm '<HASH>'`.

### Hashcat

- Hash type codes: https://hashcat.net/wiki/doku.php?id=example_hashes  
- Common: **1000** (NTLM), **18200** (Kerberoast), **5600** (NetNTLMv2), **17200** (PKZIP)
- Rules: `/usr/share/hashcat/rules`  
- https://pentesting.site/cheat-sheets/hashcat/

#### Rule comparison

| Rule File | Rule Count | Use Case |
| :--- | :--- | :--- |
| **`best64.rule`** | 64 | **First run.** Fast for easy passwords. |
| **`d3ad0ne.rule`** | ~34,000 | **Deep crack.** Standard "complex" passwords. |
| **`dive.rule`** | ~100,000+ | **Paranoid.** Very slow; last resort. |

```bash
# Wordlist attack
hashcat -m 1800 hashes.txt <WORDLIST>
hashcat -m 1800 -r /usr/share/hashcat/rules/best64.rule hashes.txt <WORDLIST>

# MD5crypt with salt
hashcat -m 20 <HASH>:<SALT> <WORDLIST>

# Zip (PKZIP); for some zips JtR is easier
hashcat -m 17200 hash_zip.txt <WORDLIST>
```

#### Mask attack (`-a 3`) charsets

| Symbol | Description | Charset |
| :--- | :--- | :--- |
| **`?l`** | Lowercase | `a-z` |
| **`?u`** | Uppercase | `A-Z` |
| **`?d`** | Digits | `0-9` |
| **`?h`** | Hex lower | `0-9a-f` |
| **`?H`** | Hex upper | `0-9A-F` |
| **`?s`** | Special | space and !"#$%&'()*+,-./:;<=>?@[]^_` |
| **`?a`** | All | `?l?u?d?s` |
| **`?b`** | Binary | 0x00–0xff |

```bash
hashcat -a 3 -m <HASH_ID> <HASH> '?u?l?l?l?l?d?s'
```

### John the Ripper

- https://www.openwall.com/john/doc/OPTIONS.shtml

```bash
john --list=formats

# Wordlist (specify format when possible)
john --format=<FORMAT> --wordlist=<WORDLIST> <HASH_FILE>

# Single crack: permutations from username (e.g. unshadowed passwd)
unshadow passwd.txt shadow.txt > unshadowed.txt
john --single <UNSHADOW_FILE>

# Incremental (Markov-style)
john --incremental <HASH_FILE>
```
