+++
title = "🌐 HTTP: TCP 80/443"
+++

- `TCP 80`: HTTP unencrypted
- `TCP 443`: HTTPS encrypted
- `PORT` (Web is oftentimes on other ports, especially internal proxies or admin pages on `8080` or `8433`)

- OWASP Top 10:
    - https://owasp.org/www-project-top-ten/
- HTTP Codes:
    - https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#Standard_codes
- Web Page Scanner:
    - https://github.com/RedSiege/EyeWitness
- `/.well-known/` URIs:
    - https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml
- User-Agent: https://useragents.io/explore

## Default Server Directories

- Linux: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt
- Windows: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt

| Server | Default Web Root |
|---|---|
| Apache | `/var/www/html/` |
| Nginx | `/usr/local/nginx/html/` |
| IIS | `C:\inetpub\wwwroot\` |
| XAMPP | `C:\xampp\htdocs\` |

**Apache (httpd):**
- Web roots: `/var/www/html`, `/var/www/`, `/srv/http/` (Arch), `/usr/share/httpd/` (RHEL/CentOS)
- Config: `/etc/apache2/apache2.conf`, `/etc/httpd/conf/httpd.conf` (RHEL/CentOS)
- VirtualHost: `/etc/apache2/sites-available/000-default.conf`, `/etc/apache2/sites-enabled/`
- Extra configs: `/etc/apache2/conf-enabled/`, `/etc/httpd/conf.d/`
- Logs: `/var/log/apache2/access.log`, `/var/log/apache2/error.log`, `/var/log/httpd/access_log`

**Nginx:**
- Web roots: `/usr/share/nginx/html`, `/var/www/html`
- Config: `/etc/nginx/nginx.conf`
- Sites: `/etc/nginx/sites-available/default`, `/etc/nginx/sites-enabled/default`, `/etc/nginx/conf.d/`
- Logs: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`

**IIS:**
- Web root: `C:\inetpub\wwwroot\`
- Main config: `C:\Windows\System32\inetsrv\config\applicationHost.config`
- App config: `C:\inetpub\wwwroot\web.config`
- ASP.NET Core: `C:\inetpub\wwwroot\appsettings.json`, `C:\inetpub\wwwroot\appsettings.Production.json`
- Logs: `C:\inetpub\logs\LogFiles\`

**XAMPP (Windows):**
- Web root: `C:\xampp\htdocs\`
- Config: `C:\xampp\apache\conf\httpd.conf`
- VirtualHost: `C:\xampp\apache\conf\extra\httpd-vhosts.conf`
- PHP: `C:\xampp\php\php.ini`
- Logs: `C:\xampp\apache\logs\access.log`, `C:\xampp\apache\logs\error.log`

## Basic Enumeration

```bash
# WAF detection
wafw00f http://<TARGET>

# Headers
curl -skLIio- http://<TARGET>

# Passive recon
curl -skLI http://<TARGET>/{sitemap.xml,robots.txt}

# Enum web server + version + OS + frameworks + libraries
whatweb --log-brief=whatweb_scan.txt --aggression 3 http://<TARGET>

# Fingerprint + vuln scan
nikto -o nikto_vuln_scan.txt -C all -h http://<TARGET>
```

{{< embed-section page="Docs/9 - Notes/ffuf" header="vhost-brute-force" >}}

## Crawling

- https://github.com/projectdiscovery/katana

```bash
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

katana -output katana_crawl.txt -depth 5 -u http://<TARGET>
```

## Directory Brute-Forcing

- Larger directory list:
    - `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
- Older websites:
    - `/usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt`

**NOTE: watch the SECURE in http`S`**

Sometimes `feroxbuster` has issues with `https` and DNS resolution... [see fix here]({{% ref "troubleshooting.md#manual-dns-server" %}})

```bash
# Directory Bruteforce
feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 5 -o feroxbuster_dir_common --scan-dir-listings --insecure -u http://<TARGET>

# Bruteforce w/ File Extensions
# LIN:  -x php,html,htm,txt,bak,zip,xml,json,js,sh,py,config
# WIN:  -x asp,aspx,ashx,asmx,html,htm,txt,bak,zip,xml,json,js,config,cs
feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 5 -o feroxbuster_dir_extensions --scan-dir-listings --insecure -u http://<TARGET> -x <EXTENSIONS>
```

## URL Encoding

URL Encoding (Percent-Encoding) it is a requirement of the HTTP protocol. Encoded characters are needed to stop a web server from confusing **Payload Data** with **HTTP Syntax**.

| Context                                        | Encode?           | Why                                |
| ---------------------------------------------- | ----------------- | ---------------------------------- |
| Browser URL bar                                | Auto              | Browser handles it                 |
| Burp Repeater                                  | Manual            | Burp sends raw by default          |
| `curl` with `--data-urlencode`                 | Auto              | Curl handles it                    |
| `curl` with `--data-raw` or inline URL         | Manual            | Sent as-is                         |
| XSS/SQLi/CMDi payload in URL                   | **Always manual** | Special chars break HTTP parsing   |
| Python `requests.get(params=)`                 | Auto              | Library handles it                 |
| Python `requests.get(url=)` with inline params | Manual            | Sent as-is                         |
| POST body `application/x-www-form-urlencoded`  | **Always**        | That's what the content type means |
| POST body `application/json`                   | Never             | JSON has its own escaping          |
| POST body `multipart/form-data`                | Never             | Binary-safe encoding               |

**Rule of thumb:** if a payload contains `& # + ? ; | space < >`:
- **ENCODE:** if it goes into a URL or form body
- **VERFIY:** if it encodes automatically, verify with `-v` or Burp proxy

```bash
# Curl Auto-Encoding for GET requests
curl --get -i "http://<TARGET>/cgi/welcome.bat" --data-urlencode "cmd=C:\windows\system32\whoami.exe & id"

# Python One-Liner (payload generation)
python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" 'cat /etc/passwd && id'
```

| Character | HTTP Syntax Meaning | Why it breaks exploits if unencoded |
| :--- | :--- | :--- |
| **`&`** | Parameter Separator | Server splits your payload. `?cmd=id & whoami` becomes Param 1: `cmd=id`, Param 2: `whoami`. |
| **`#`** | URL Fragment | Browser stops sending data after `#`. The backend never sees it. |
| **`+`** / **` `** | Space | Raw spaces break the HTTP header structure (`GET /page HTTP/1.1`). |
| **`?`** | Query String Start | Truncates or confuses path traversal payloads. |

### Command Injection Rule

When exploiting CGI scripts (`.sh`, `.bat`, `.cgi`), the web server unwraps the URL and hands the raw string directly to the OS shell (`/bin/bash` or `cmd.exe`). If you do not URL-encode your shell operators (`&`, `|`, `;`), the web server strips them out during the HTTP parsing phase, and the OS shell never executes them.

*   **Double Encoding (WAF Bypass):** If a WAF blocks `%5C` (`\`), encode the `%` symbol itself (`%` = `%25`). The payload becomes `%255C`. The WAF sees `%255C` (Allowed), passes it to the backend, which decodes it once to `%5C`, and the application decodes it again to `\`.
*   **Space Variants:** 
    *   In the **URL Path** (`GET /path%20here`), use `%20`.
    *   In the **Query String / Body** (`?cmd=id+whoami`), `+` is historically interpreted as a space (`application/x-www-form-urlencoded`), but `%20` is universally safer to avoid parsing desyncs. Default to `%20`.