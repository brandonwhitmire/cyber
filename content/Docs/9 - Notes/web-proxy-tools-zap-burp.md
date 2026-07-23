+++
title = "Web proxy tools (OWASP ZAP & Burp Suite)"
+++

**WIP: currently this is AI slop distilled from handouts** 

---

## Quick reference: hotkeys

Same action, side by side for both tools.

| Action | OWASP ZAP | Burp Suite |
|--------|-----------|------------|
| Toggle request intercept | **Ctrl+B** | — |
| Forward intercepted request | — | — |
| Intercept response | — | — |
| Open Replacer / Match and Replace | **Ctrl+R** | — |
| Send to Repeater | — | **Ctrl+R** (send); **Ctrl+Shift+R** (go to tab) |
| Send to Intruder | — | **Ctrl+I** (send); **Ctrl+Shift+I** (go to tab) |
| URL-encode selection | — (auto on send) | **Ctrl+U** |
| Open Decoder / Encoder | **Ctrl+E** | — |

---

## Tool-agnostic overview

## Setting up

**Concept (tool-agnostic):**  
Both tools run on Windows, macOS, and Linux. They are pre-installed on common PT distros (e.g. Parrot, Kali) and on PwnBox (dock or top bar). Both require a **Java Runtime Environment (JRE)**; installers usually bundle it. For custom VMs you can use installers or the cross-platform JAR and run with `java -jar <path/to/tool.jar>`. Choose a **temporary** project/session for short engagements; use a **saved** project/session when you need to persist progress (e.g. large apps or long-running scans).

**Burp Suite**

- **Download:** [Burp Download Page](https://portswigger.net/burp/communitydownload) — installers for Windows, Linux, macOS, or JAR for any OS with JRE.
- **Launch:** From terminal run `burpsuite`, or from the application menu. JAR: `java -jar </path/to/burpsuite.jar>` (or double-click).
- **First run:** Create a project → choose **Temporary project** (Community Edition only supports temporary; Pro/Enterprise can save to disk or open existing). Then choose **Use Burp Defaults** (or load a config file if you have one) → **Start Burp**.
- **Dark theme:** **Burp → Settings → User interface → Display** → set **Theme** to *Dark*.

**OWASP ZAP**

- **Download:** [ZAP Download Page](https://www.zaproxy.org/download/) — installers per OS or cross-platform JAR.
- **Launch:** From terminal run `zaproxy`, or from the application menu. JAR: `java -jar <path/to/zap.jar>` (or double-click).
- **First run:** When asked about persisting the session, choose **not to persist** for a temporary session (or pick timestamp/name if you need to save). Then continue to proxy setup.
- **Dark theme:** **Tools → Options → Display** → set **Look and Feel** to *Flat Dark*.

---

## Proxy setup

**Concept (tool-agnostic):**  
Use the tool as a **web proxy** so all browser (or app) traffic goes through it. You can inspect requests/responses, intercept and modify them, and replay them with changes to see how the app behaves. Either use the tool’s **pre-configured browser** (proxy + CA cert already set) or configure your own browser (e.g. Firefox) to use the proxy and install the tool’s **CA certificate** so HTTPS works without repeated “accept” prompts.

### Pre-configured browser

Fastest option: proxy and CA are already set; traffic is routed automatically.

**Burp Suite**  
**Proxy → Intercept** → click **Open browser**. Burp’s embedded browser opens with traffic routed through Burp.

**OWASP ZAP**  
Click the **Firefox icon** at the end of the top bar. Opens the browser chosen in the Quick Start tab, pre-configured to proxy through ZAP.

### Manual proxy (e.g. Firefox)

Both tools listen on **port 8080** by default. Use the same port in the browser. If the port is in use, the proxy will not start (you’ll see an error).

- **Change listening port:**  
  - **Burp:** **Proxy → Proxy settings → Proxy listeners**  
  - **ZAP:** **Tools → Options → Network → Local Servers/Proxies**
- **Firefox:** Set proxy in **Preferences** to `127.0.0.1` and the chosen port, or use **FoxyProxy** (e.g. on PwnBox it’s pre-installed): FoxyProxy icon → **Options** → **Add** → IP `127.0.0.1`, port `8080`, name e.g. *Burp* or *ZAP* → **Save**. Then use the FoxyProxy icon to switch to Burp/ZAP. ([FoxyProxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) can be installed from the Firefox add-ons page.)

### Installing the CA certificate

Required for HTTPS to work cleanly through the proxy (otherwise traffic may fail or you’ll have to accept warnings repeatedly).

**Burp Suite**  
With Burp set as the proxy in the browser, go to **http://burp** and click **CA Certificate** to download it.

**OWASP ZAP**  
**Tools → Options → Network → Server Certificates** → **Save** to export the CA cert (or **Generate** to create a new one), then use the saved file.

**Firefox (install cert):**  
Open **about:preferences#privacy** → scroll down → **View Certificates** → **Authorities** tab → **Import** → select the downloaded CA file → check **Trust this CA to identify websites** and **Trust this CA to identify email users** → **OK**.

After proxy + CA are set, all Firefox traffic will go through the web proxy.

---

## Intercepting and manipulating web requests

**Concept (tool-agnostic):**  
With the proxy running, you can **intercept** HTTP requests so they pause in the tool instead of going straight to the server. You can **inspect and edit** the request (headers, parameters, body), then **forward** it. The server sees your modified request; the response helps you test for issues the UI might block (e.g. front-end validation). Use this for testing SQL injection, command injection, upload bypass, authentication bypass, XSS, XXE, error handling, deserialization, and similar web vulnerabilities.  
*Example:* A form may only allow digits in an "IP" field via JavaScript. By intercepting the `POST`, you can change e.g. `ip=1` to `ip=;ls;` and forward to test for command injection if the backend doesn't validate.

### Intercepting requests

**Burp Suite**  
**Proxy → Intercept**. Intercept is **on** by default (button shows "Intercept is on"). Click the button to toggle on/off. With intercept on, open the pre-configured browser and load the target; the request appears in Burp. Use **Forward** to send it. If multiple requests are queued (e.g. other Firefox traffic), keep clicking **Forward** until you reach the target request.

**OWASP ZAP**  
Intercept is **off** by default (toolbar button is **green** = traffic passes). Click the button to toggle, or use **Ctrl+B**. With intercept on, load the target in the pre-configured browser; the request appears in the top-right pane. Click **Step** (next to the red break button) to forward one request.  
**HUD (Heads Up Display):** Click the **HUD** button at the end of the top menu bar to enable in-browser controls. In the HUD's left pane, the **second button from the top** turns request interception on. When a request is intercepted, use **Step** (one request, then break again) or **Continue** (forward this and let the rest through). Step is for inspecting each request; Continue when you only care about one. *Note:* Some browser versions may not support the HUD well. First-time ZAP browser use may show a HUD tutorial (or **configuration → Take the HUD tutorial**).

### Manipulating then forwarding

Edit the intercepted request in the request pane (method, URL, headers, body). Change parameters, add payloads, etc. Then **Forward** (Burp) or **Step** / **Continue** (ZAP) to send it. Check the response in the browser or in the tool to see how the app handled your input.

---

## Intercepting responses

**Concept (tool-agnostic):**  
You can intercept **HTTP responses** before they reach the browser and edit the HTML/headers. Use this to change how the page looks or behaves: enable disabled fields, show hidden fields, change `type="number"` to `type="text"`, increase `maxlength`, etc. That can let you test from the browser without having to send every payload via an intercepted request. For simple cases (just enable disabled or unhide hidden form fields), both tools can do it automatically so you don’t have to intercept and edit by hand.

### Enabling response interception

**Burp Suite**  
**Proxy → Proxy settings** → under **Response interception rules** enable **Intercept Response** (and **Update Content-Length** if needed). With request intercept on, do a **full refresh** in the browser (e.g. **Ctrl+Shift+R**); forward the request in Burp, then the response is intercepted. Edit the response (e.g. change `type="number"` to `type="text"`, `maxlength="3"` to `maxlength="100"`), then **Forward**. The browser receives your modified response.  
**Automatic unhide:** **Proxy → Proxy settings → Response modification rules** → enable e.g. **Unhide hidden form fields** so hidden/disabled fields are shown without manually intercepting.

**OWASP ZAP**  
With request intercept on, click **Step** to send the request; ZAP then intercepts the **response**. Edit the response in the pane, then **Continue** to send it to the browser.  
**HUD — enable/show without intercepting:** In the HUD left pane, the **third button** (light bulb) is **Show/Enable**: it enables disabled inputs and shows hidden fields in the current page without intercepting the response or refreshing. Use it when you only need to unlock fields, not edit HTML by hand.  
**HUD — HTML comments:** In the HUD left pane click **+** → **Comments** to add the Comments control. It shows indicators where HTML comments are; hover to see the comment content (useful for dev notes or hidden hints).

*Tip:* Use a full page refresh (**Ctrl+Shift+R** in the browser) when testing so you get a clean request/response cycle.

---

## Automatic modification

**Concept (tool-agnostic):**  
Define **match/replace rules** so the proxy automatically changes **all** outgoing requests or **all** incoming responses without intercepting each one. Use for: replacing headers (e.g. User-Agent to bypass filters), changing response HTML on every load (e.g. `type="number"` → `type="text"`, `maxlength="3"` → `maxlength="100"`), or injecting payloads in request bodies. Rules can use plain text or regex; you choose request header/body or response header/body.

### Automatic request modification

**Example:** Replace the `User-Agent` header with a custom value (e.g. to bypass User-Agent filters).

**Burp Suite**  
**Proxy → Proxy settings → Match and Replace** (or **HTTP match and replace rules**) → **Add**.  
- **Type:** Request header  
- **Match:** `^User-Agent.*$` (regex for the whole User-Agent line)  
- **Replace:** `User-Agent: HackTheBox Agent 1.0`  
- **Regex match:** True  

Rule is applied to all requests. Verify by intercepting a request and checking the header.

**OWASP ZAP**  
Open **Replacer**: **Ctrl+R** or **Tools → Options → Replacer** (or Replacer in the options menu). **Add** a rule:  
- **Description:** e.g. HTB User-Agent  
- **Match Type:** Request Header (will add if not present) — or **Request Header String** for regex  
- **Match String:** `User-Agent` (or pick from dropdown; use regex in the string if Match Type is Request Header String)  
- **Replacement String:** `HackTheBox Agent 1.0`  
- **Enable:** True  

**Initiators** tab: choose where the rule applies (default: all HTTP(S) messages). Verify with **Ctrl+B** (intercept on), then visit a page and check the request.

### Automatic response modification

**Example:** Always change `type="number"` to `type="text"` and `maxlength="3"` to `maxlength="100"` in responses so the change persists across refreshes without manually intercepting.

**Burp Suite**  
**Proxy → Proxy settings → Match and Replace** → **Add**.  
- **Type:** Response body  
- **Match:** `type="number"`  
- **Replace:** `type="text"`  
- **Regex match:** False  

Add a second rule: Match `maxlength="3"`, Replace `maxlength="100"`, Regex false. Full refresh (**Ctrl+Shift+R**) in the browser to see the updated page; the field now accepts any input on every load.

**OWASP ZAP**  
**Replacer** (**Ctrl+R**) → **Add** two rules:  
1. **Match Type:** Response Body String. **Match Regex:** False. **Match String:** `type="number"`. **Replacement String:** `type="text"`. **Enable:** True.  
2. **Match Type:** Response Body String. **Match Regex:** False. **Match String:** `maxlength="3"`. **Replacement String:** `maxlength="100"`. **Enable:** True.  

Refresh the page to verify. You can also add request-body rules (e.g. replace a parameter value with a payload like `;ls;` when submitting a specific form) by matching the request body and setting the replacement; use **Initiators** in ZAP to limit which messages get the rule if needed.

---

## Repeating requests

**Concept (tool-agnostic):**  
**Request repeating** lets you resend any request that has already gone through the proxy. You edit it (e.g. change a parameter or payload), send it from the tool, and see the response there—no need to intercept again. Use this for repetitive testing (e.g. trying many commands or payloads). Both tools keep a **history** of requests; you pick one, send it to a **repeater / request editor**, modify, and **Send**.

### Proxy / HTTP history

**Burp Suite**  
**Proxy → HTTP History**. Lists all requests that passed through the proxy; use filters and sorting to find the one you want. Click a request to see full request and response. If the request was edited during intercept, the pane header shows **Original Request**; switch to **Edited Request** to see what was actually sent.  
*Note:* **Proxy → WebSockets history** for WebSocket traffic (advanced use).

**OWASP ZAP**  
**History** tab at the bottom (main UI), or in the HUD the **bottom History pane**. Filters and sorting available. Click a request to view details. ZAP shows the **final/modified** request only (no separate original vs edited view like Burp).  
*Note:* WebSockets history is available for async/WebSocket connections.

### Repeating (Repeater / Request Editor)

**Burp Suite**  
With the request selected in HTTP History (or elsewhere), **Ctrl+R** sends it to the **Repeater** tab. **Ctrl+Shift+R** switches to the Repeater tab. In Repeater: edit the request (headers, body, etc.), click **Send**; the response appears in the response pane. Right-click the request → **Change Request Method** to switch between POST/GET without rewriting the whole request.

**OWASP ZAP**  
Right-click the request in History → **Open/Resend with Request Editor**. The **Request Editor** window opens; edit the request, then click **Send** to get the response in the same window. Use the **Method** dropdown to change HTTP method. Use the display/layout buttons to arrange request and response (tabs vs side-by-side, etc.).  
**HUD:** In the pre-configured browser, click the request in the **bottom History pane** → Request Editor appears. **Replay in Console** shows the response in the HUD; **Replay in Browser** renders it in the browser. In all cases (Burp Repeater, ZAP Request Editor, ZAP HUD) you can edit then **Send** to resend with changes.

*Tip:* Request bodies are often **URL-encoded**; keep encoding in mind when editing (e.g. `%3B` for `;`). The next section covers this in more detail.

---

## Encoding / decoding

**Concept (tool-agnostic):**  
When you modify and send custom HTTP requests, encoding and decoding matter. **URL encoding** ensures the server parses data correctly: characters like spaces (can end request data), `&` (parameter delimiter), and `#` (fragment) must be encoded. Applications also use other encodings (HTML, Unicode, Base64, ASCII hex); you need to **decode** to inspect data (e.g. cookies, tokens) and **encode** payloads in the format the server expects. Both tools have built-in encoders/decoders so you can work quickly without leaving the proxy.

### URL encoding

**Burp Suite (Repeater):** Select the text → right-click → **Convert Selection → URL → URL-encode key characters**, or **Ctrl+U**. You can enable **URL-encode as you type** via right-click so input is encoded automatically. Other options: **Full URL-encoding**, **Unicode URL encoding** (for many special characters).

**OWASP ZAP:** Request data is **automatically URL-encoded** before send (you may not see it in the editor). For manual control or other encodings, use the Encoder/Decoder/Hash tool (see below).

### Decoder / Encoder tool

**Burp Suite**  
**Decoder** tab: enter text, choose **Decode as** or **Encode as** (e.g. Base64, HTML, Unicode, ASCII hex). The **output pane** can be passed through another encoder/decoder—select the method in the output area to chain. **Burp Inspector** (in Proxy, Repeater, etc.) also does encoding/decoding inline on requests and responses.

**OWASP ZAP**  
**Encoder/Decoder/Hash:** **Ctrl+E**. **Decode** tab: paste input; ZAP can try multiple decoders. **Encode** (or same tool): choose encoding, get output. Use **Add New Tab** to build custom tabs with multiple encoders/decoders. To chain (e.g. decode then encode with another method), copy the output and paste into the input field.

*Example:* Base64 cookie `eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=` decodes to `{"username":"guest", "is_admin":false}`. Edit to `admin` / `true`, re-encode as Base64, then paste the new string into the request in Repeater or Request Editor to test privilege changes. Same idea applies to any encoding (HTML, Unicode, etc.) for inspection and payload crafting.

---

## Proxying other tools

**Concept (tool-agnostic):**  
You can route **command-line tools** and **thick clients** through the web proxy so their HTTP(S) traffic is visible and editable. Configure each tool to use the proxy (e.g. `http://127.0.0.1:8080`); methods vary by tool. Then you get full proxy features: intercept, history, repeat, modify. Use this when you need to see or change what a script or app is sending. *Note:* Proxying usually slows tools down—only enable it when you need to inspect or manipulate their requests.

### Proxychains (Linux)

**Proxychains** sends traffic from any CLI tool through a proxy. Easiest way to proxy arbitrary commands.

1. Edit **`/etc/proxychains.conf`**: comment out the default proxy line (e.g. `#socks4 127.0.0.1 9050`) and add:
   ```text
   http 127.0.0.1 8080
   ```
2. Run the command via proxychains. Use **`-q`** for quiet mode (less console noise):
   ```bash
   proxychains -q curl http://SERVER_IP:PORT
   ```
   The request appears in the web proxy (Burp or ZAP) like browser traffic. Works with any HTTP(S)-using CLI tool.

### Metasploit

In **msfconsole**, set the proxy for modules with **`set PROXIES`**:

```bash
msfconsole
msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080
msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP
msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT
msf6 auxiliary(scanner/http/robots_txt) > run
```

Requests from the module go through the proxy; check **Proxy → HTTP History** (Burp) or **History** (ZAP) to inspect them. Same approach for other scanners, exploits, and modules that make HTTP requests.

### Other tools and thick clients

For other tools, scripts, or GUI apps: find how to set an HTTP proxy (often an option, env var, or config file) and point it at your proxy (e.g. `127.0.0.1:8080`). Then you can examine, repeat, and modify their requests from the proxy as with browser traffic.

---

## Web fuzzers

**Concept (tool-agnostic):**  
Built-in **web fuzzers** handle fuzzing, enumeration, and brute-forcing (directories, subdomains, parameters, parameter values, etc.) and can replace or complement CLI tools (e.g. ffuf, gobuster, wfuzz, dirbuster). You send a request to the fuzzer, mark one or more **payload positions**, choose a **wordlist** and options, then run the attack and inspect results (status, length, grep matches). Use for directory discovery, login brute-force, parameter fuzzing, password spraying (e.g. AD, OWA, VPN portals), and similar tasks.

### Burp Intruder

Burp’s fuzzer is **Intruder**. Community edition is **throttled** (about 1 request/second); use for short wordlists. Pro has no throttle and more features. [Intruder docs](https://portswigger.net/burp/documentation/desktop/tools/intruder); [payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/payloads/types).

**Send request to Intruder:** From Proxy history (or elsewhere), right-click the request → **Send to Intruder**, or **Ctrl+I**. Switch to **Intruder** tab: **Ctrl+Shift+I**. The **Target** box shows host/port from the request.

**Positions:** Define where the wordlist is inserted. Wrap the placeholder with **§** (e.g. `§DIRECTORY§`) or select text and click **Add §**. Example for directory fuzzing: `GET /§DIRECTORY§/` — existing paths return 200, others 404. Leave the two blank lines at the end of the request. **Attack type** (e.g. Sniper = one position, Cluster bomb = multiple positions) affects how many payload sets you get.

**Payloads tab:**

1. **Payload set & type:** Choose which position (1, 2, …). **Payload type:** e.g. **Simple list** (wordlist, one line per payload), **Runtime file** (load wordlist line-by-line, better for huge lists), **Character substitution**, or others. For directory fuzzing, **Simple list** is typical.
2. **Payload configuration:** For Simple list: **Load** a file (e.g. `/usr/share/seclists/Discovery/Web-Content/common.txt`) or **Add** items. You can combine multiple lists. Pro: **Add from list** for built-in wordlists. *Tip:* Very large wordlists → use **Runtime file** to avoid loading everything into memory.
3. **Payload processing:** Add rules (e.g. add suffix, **Skip if matches regex**). Example: skip lines starting with `.` using regex `^\..*$`.
4. **Payload encoding:** Usually leave **URL-encode** enabled so special characters are encoded.

**Payload options (Intruder):** [Payload types reference](https://portswigger.net/burp/documentation/desktop/tools/intruder/payloads/types).

**Settings tab:** Configure **Grep - Match** to flag responses containing a string (e.g. `200 OK`). **Clear** existing rules, **Add** `200 OK`, and disable **Exclude HTTP headers** if you want to match the status line. **Grep - Extract** can pull specific parts of responses. Set **Number of retries** / **Pause before retry** if needed. **Resource pool** (right-hand bar) controls how much network Intruder uses for large attacks.

**Attack:** Click **Start attack**. Results table: sort by the grep column (e.g. 200 OK), **Status**, or **Length** to find hits (e.g. `/admin/` with 200). Use Intruder for directory fuzzing, parameter/value fuzzing, brute-force, and password spraying against AD-authenticated apps (OWA, VPN, RDS, Citrix, etc.). ZAP’s fuzzer (below) has no speed throttle.

### ZAP Fuzzer

**ZAP Fuzzer** is ZAP’s built-in fuzzer. It has fewer features than Burp Intruder but **does not throttle** request speed, so it is often better than free Burp Intruder for large wordlists. Use it for directory fuzzing, parameter fuzzing, and similar attacks.

**Start a fuzz:** Capture a request (e.g. visit `http://SERVER_IP:PORT/test/` so the path contains the placeholder). In **History**, right-click the request → **Attack → Fuzz**. The **Fuzzer** window opens with the request on the left and **Fuzz Locations** on the right.

**Locations:** Like Intruder payload positions. Select the word you want to replace (e.g. `test` in the path) and click **Add**. A green marker is placed and the **Payloads** configuration opens. You can add multiple locations.

**Payloads:** Click **Add** and choose a **payload type**. Examples:
- **File** — load a wordlist from a file.
- **File Fuzzers** — use built-in wordlists (e.g. **dirbuster** → **directory-list-1.0.txt**). More lists available via ZAP Marketplace.
- **Numberzz** — generate number sequences with custom step.

**Processors:** Optional processing for each payload. **Add** a processor; types include **Base64 Decode/Encode**, **MD5**, **Prefix String**, **Postfix String**, **SHA-1/256/512**, **URL Decode/Encode**, **Script** (custom). For directory fuzzing, add **URL Encode** so special characters don’t break the request. Use **Generate Preview** to see the final payload in context, then **Add** and **Ok**.

**Options:** Set **Concurrent Scanning Threads per Scan** (e.g. 20) for speed; balance with CPU and server load. **Depth first** — try all payloads at one position before moving to the next (e.g. all words for one user). **Breadth first** — try the first word on all positions, then the next word (e.g. one password for all users). Configure retries, max errors, redirects as needed.

**Start:** Click **Start Fuzzer**. In the results table, sort by **Response code** (e.g. 200) to find hits. Click a row to view request/response. **Size Resp. Body** can indicate different pages; **RTT** (round-trip time) matters for time-based attacks (e.g. time-based SQLi).

---

## Web scanners

**Concept (tool-agnostic):**  
Web proxy tools often include **scanners** that combine a **crawler** (follow links and forms to map the site), **passive scanning** (analyze already-seen traffic for issues without sending new requests), and **active scanning** (send probes to confirm and find vulnerabilities). Define **scope** (in/out of scope) so the scanner only targets allowed URLs. Use scan results and **reports** as supporting evidence; never substitute a raw tool report for a proper client deliverable.

### Burp Scanner (Pro only)

**Burp Scanner** is a **Pro-only** feature (not in Community edition). It uses a **Crawler** to build the site structure and **Scanner** for passive and active vulnerability checks.

**Target scope**

- **Start a scan:** (1) From **Proxy → HTTP History**: right-click a request → **Scan** (configure) or **Passive scan** / **Active scan** (defaults). (2) **Dashboard** → **New Scan** for custom target set. (3) Use **scope** so only in-scope items are scanned.
- **Scope:** **Target → Site map** lists everything Burp has seen. Right-click an item → **Add to scope** (or **Remove from scope**). **Target → Scope** shows include/exclude rules; use **Use advanced scope control** for regex. You can restrict Burp to in-scope only to save resources. When you add the first scope item, Burp may ask whether to limit features to in-scope only.

**Crawler**

- **Dashboard → New Scan**. Two modes: **Crawl** (map only) or **Crawl and Audit** (crawl then scan). Crawler follows links and forms; it does **not** discover unreferenced paths (use Intruder or Content Discovery, then add to scope).
- **Scan configuration:** **New** for custom (speed, limits, login behaviour) or **Select from library** (e.g. **Crawl strategy - fastest**). **Application login**: add credentials and/or **record** a manual login in the built-in browser so the crawler can stay authenticated. **Ok** to start. Progress under **Dashboard → Tasks**; **View details** or the gear icon to adjust. When finished, **Target → Site map** shows the updated map.

**Passive scanner**

- Analyzes **existing** requests/responses only (no new requests). Flags possible issues (e.g. missing security headers, DOM XSS). Each finding has a **confidence** (e.g. Certain, Firm). Right-click target in Site map or a request in Proxy history → **Do passive scan** / **Passively scan this target**. Task appears in Dashboard. **View details → Issue activity** (or the Issue activity pane on Dashboard) to see findings. Prioritise **High** severity and **Certain**/Firm confidence; for sensitive apps, review all severities.

**Active scanner**

- **Crawl and Audit** in New Scan runs: (1) Crawl + discovery (like a fuzzer) for pages, (2) Passive scan on discovered content, (3) Active checks to **verify** passive findings, (4) JavaScript analysis, (5) Fuzzing of parameters for XSS, command injection, SQLi, etc. Frequently updated by PortSwigger.
- Start: right-click request → **Do active scan**, or **New Scan** → **Crawl and Audit**. Set **Crawl** config (as above) and **Audit** config: what to check, insertion points; **Select from library** e.g. **Audit checks - critical issues only**. Add login if needed. **Ok** to run. Progress in **Dashboard → Tasks**; **Logger** tab shows requests made by the scanner. When done, filter **Issue activity** by severity (e.g. **High**) and confidence (e.g. **Certain**/Firm). Click an issue for the advisory, request/response, and remediation notes.

**Reporting**

- **Target → Site map** → right-click the host → **Issue → Report issues for this host**. Choose export format and what to include. The report summarizes by severity/confidence and can include PoC and remediation. Use as **appendix or supplementary data**, not as the final client report; always produce a proper written deliverable and use tool output as support.

### ZAP Scanner

ZAP includes **Spider**, **passive scanning**, and **active scanning**; all run in the free version. **Scope** defines which URLs are included in scans and can be customized for multiple sites.

**Spider**

- **Start:** In **History**, right-click a request → **Attack → Spider**. Or in the **HUD** (pre-configured browser): open the target page, then click the **second button on the right pane** (Spider Start) and confirm. If the site is not in scope, ZAP may ask to add it (choose Yes). Scope is the set of URLs ZAP will crawl/scan; you can add multiple targets. *Note:* Some browser versions may not support the HUD fully.
- Spider follows links and validates them (similar to Burp Crawler). Progress: HUD Spider button or main ZAP UI (often switches to the Spider tab). When finished: **Sites** tab in the main UI, or HUD **first button on the right pane** (Sites Tree) for an expandable tree of discovered URLs and directories.
- **Ajax Spider:** **Third button on the right pane**. Discovers links loaded via JavaScript/AJAX. Run after the normal Spider for better coverage; it can find more URLs but takes longer.

**Passive scanner**

- Runs **automatically** on every response (e.g. while Spider runs or as you browse). Identifies potential issues from source (e.g. missing security headers, DOM-based XSS). Alerts can appear before you run an Active Scan. In the HUD: **left pane** = alerts for the current page, **right pane** = all alerts for the application. In the main UI: **Alerts** tab lists all findings; click an alert for details and the URLs where it was seen.

**Active scanner**

- Click **Active Scan** on the right pane (or equivalent in main UI). Scans all URLs in the site tree. If you have not run the Spider yet, ZAP runs it first to build the tree. Progress is shown in the HUD and in the main ZAP UI; alerts increase as the scan runs. The Active Scanner sends many probes against pages and parameters (XSS, command injection, SQLi, etc.) and takes longer. When done: filter by severity (e.g. **High** for issues that may lead to compromise). Click an alert for description, attack example, and evidence; click the URL to see the request/response and use **Replay in Console** or **Replay in Browser** to reproduce.

**Reporting**

- **Report → Generate HTML Report** (top bar). Choose save location; reports can also be exported as XML or Markdown. Open in a browser to review. Use as a **log or supplement** for engagements, not as the sole client deliverable.

---

## Extensions / add-ons

**Concept (tool-agnostic):**  
Both tools support **extensions** (Burp) or **add-ons** (ZAP) from the community. They can act on captured requests, add features (e.g. decoding, beautifying, new scan checks), or provide extra wordlists and payloads. Install only what you need; some extensions have dependencies (e.g. Jython) that must be installed on your system first.

### Burp: BApp Store

- **Extender** tab → **BApp Store** sub-tab. Browse extensions; sort by **Popularity**. Some are Pro-only; most are available to all users.
- Click an extension to install it. After install, a new tab or menu item may appear. Use the extension’s **documentation** in the BApp Store or its **GitHub** page for usage. Some extensions require **Jython** (or other runtimes) to be installed on your machine (Linux/macOS/Windows) before they can run.
- **Example:** **Decoder Improved** — adds a tab with more encoders/decoders and hashing (e.g. **Hash With → MD5**). Use like the built-in Decoder with extra options.
- **Examples of useful extensions:** .NET Beautifier, J2EEScan, Software Version Reporter, Active Scan++, AWS Security Checks, Backslash Powered Scanner, Wsdler, Java Deserialization Scanner, C02 (cloud storage tester), CMS Scanner, Error Message Checks, Detect Dynamic JS, Headers Analyzer, HTML5 Auditor, PHP Object Injection Check, JavaScript Security, Retire.JS, CSP Auditor, Random IP Address Header, Autorize, CSRF Scanner, JS Link Finder. Browse the store for more.

### ZAP: Marketplace

- Click **Manage Add-ons** (toolbar) → **Marketplace** tab. Add-ons can be **Release** (stable) or **Beta/Alpha** (may be unstable).
- Install add-ons to add features or data. **Example:** **FuzzDB Files** and **FuzzDB Offensive** add wordlists for the ZAP Fuzzer. In the Fuzzer, choose payload type **File Fuzzers** → e.g. **fuzzdb → attack → os-cmd-execution** (e.g. `command_execution-unix.txt`) for command-injection payloads. Run the fuzzer to test with many payloads (e.g. `;id`, `/usr/bin/id`); useful when testing WAF-protected or strict applications. Try other Marketplace add-ons for scanners, scripts, and extra payloads.

---

