+++
title = "SMTP/ESMTP"
+++

- `TCP 25`: unencrypted
- `TCP 465/587/2525`: encrypted
- Security:
    - DKIM: https://dkim.org/
    - Sender Policy Framework (SPF): https://dmarcian.com/what-is-spf/
    - DMARC: https://dmarc.org/
- https://serversmtp.com/smtp-error/
{{% details "Dangerous Settings" %}}

| **Option**               | **Description**                                                                                                                                                                          |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mynetworks = 0.0.0.0/0` | With this setting, this SMTP server can send fake emails and thus initialize communication between multiple parties. Another attack possibility would be to spoof the email and read it. |
{{% /details %}}

```bash
# CAREFUL! Open relay check
sudo nmap -p25,465,587,2525 --script smtp-open-relay <TARGET>

# User enum
# TRY: -M VRFY
smtp-user-enum -v -M RCPT -U <USERLIST> -D <DOMAIN> -t <TARGET>

# Manual enumeration
telnet <TARGET> 25
EHLO <HOSTNAME>
VRFY <USER>  # 250 success; 252 maybe/not; 550 failure
EXPN
```
