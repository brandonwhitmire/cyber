+++
title = "Web"
+++

- OWASP Top 10:
    - https://owasp.org/www-project-top-ten/
- HTTP Codes:
    - https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#Standard_codes
- Web Page Scanner:
    - https://github.com/RedSiege/EyeWitness
- `/.well-known/` URIs:
    - https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml
- User-Agent: https://useragents.io/explore

```bash
# HTTP Headers + robots.txt
curl -skLI -o curl_http_headers.txt http://<TARGET>
curl -skL -o curl_robots.txt http://<TARGET>/robots.txt

---

# Checks for WAF (wbapp firewall)
wafw00f <TARGET>

# Enum web server + version + OS + frameworks + libraries
whatweb --aggression 3 http://<TARGET> --log-brief=whatweb_scan.txt

# Fingerprint web server
nikto -o nikto_fingerprint_scan.txt -Tuning b -h http://<TARGET>

# Enum web server vulns
nikto -o nikto_vuln_scan.txt -h http://<TARGET>

# Enum web app logic & vulns
wapiti -f txt -o wapiti_scan.txt --url http://<TARGET>

# vHost Brute-force
gobuster --quiet --threads 64 --output gobuster_vhost_top5000 vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --exclude-length 250-320 --domain <DOMAIN> -u "http://<IP_ADDR>"  # uses IP addr

# Webpage Crawler
pip3 install --break-system-packages scrapy
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip && unzip ReconSpider.zip
python3 ReconSpider.py <URL> && cat results.json
# !!! CHECK "results.json" !!!

---

# /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Directory brute-force with a common wordlist
gobuster dir --quiet --threads 64 --output gobuster_dir_common --follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --url http://<TARGET>

# w/ file extensions
gobuster dir --quiet --threads 64 --output gobuster_dir_medium ---follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --extensions php,html,txt,bak,zip --url http://<TARGET>

### ⚡ FEROXBUSTER: faster and recursive
feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 2 -o feroxbuster_dir_common --scan-dir-listings -u http://<TARGET>

---

# AUTOMATED Recon
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
chmod +x ./finalrecon.py
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
./finalrecon.py -nb -r -cd final_recon_scan -w /usr/share/wordlists/dirb/common.txt --headers --crawl --ps --dns --sub --dir --url http://<URL>
```
