+++
title = "06 - Check - SQL Injection (SQLMap)"
+++

### Manual Triage & Setup

1. [ ] Manually confirm injection in Burp first -- verify a True vs False response difference before running SQLMap
    - [SQL Injection -- Manual Testing]({{% ref "sql-injection.md" %}})
    - Never run SQLMap blind

2. [ ] Set up SQLMap with a captured request and run baseline
    - [SQLMap Workflow]({{% ref "sqlmap.md#workflow" %}})
    - Save request from Burp to `req.txt`, mark injection point with `*`

3. [ ] Tune SQLMap if the baseline fails (wrong boundaries, slow checks, logic issues)
    - [Attack Tuning & Escalation]({{% ref "sqlmap.md#attack-tuning-escalation" %}})
    - Adjust level/risk, prefix/suffix, and technique flags to match what Burp shows

### Stability & Evasion

4. [ ] Fix hallucinated or garbage output by anchoring to a known success string
    - [SQLMap Troubleshooting]({{% ref "sqlmap.md#troubleshooting" %}})

5. [ ] Bypass WAF blocking or 403 responses
    - [Evasion & Protections Bypass]({{% ref "sqlmap.md#evasion-protections-bypass" %}})
    - Use tamper scripts and random user-agent

### Loot & Shells

6. [ ] Check DBA status and current database before dumping
    - [Database Enumeration]({{% ref "sqlmap.md#database-enumeration" %}})

7. [ ] Perform surgical extraction -- target specific tables/columns, do not dump entire DB
    - [Database Enumeration]({{% ref "sqlmap.md#database-enumeration" %}})

8. [ ] If DBA: attempt OS shell or web shell write for RCE
    - [Silver Bullet Commands]({{% ref "sqlmap.md#silver-bullet-commands" %}})
