+++
title = "Information Gathering"
+++

- Ports:
    - https://www.stationx.net/common-ports-cheat-sheet/
    - https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf
    - https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/
- OS Identification via:
    - TTL: https://subinsb.com/default-device-ttl-values/

# Enumeration

Primary source of information will be:
- scoping document (in-scope assets)
- passive OSINT

| **No.** | **Principle**                                                          |
| ------- | ---------------------------------------------------------------------- |
| 1.      | There is more than meets the eye. Consider all points of view.         |
| 2.      | Distinguish between what **we see** and what **we do not see**.        |
| 3.      | There are always ways to gain more information. Understand the target. |

| Layer | Name                    | Goal / Purpose                                                                                                                      |
| :---- | :---------------------- | :---------------------------------------------------------------------------------------------------------------------------------- |
| **1** | **Internet Presence**   | **Discover Assets:** Identify all public-facing domains, subdomains, IPs, and netblocks.                                            |
| **2** | **Gateway**             | **Analyze the Perimeter:** Understand the target's external interfaces and protection mechanisms (e.g., WAF, firewall).             |
| **3** | **Accessible Services** | **Enumerate Services:** Identify and understand the function of every open port and running service on the discovered assets.       |
| **4** | **Processes**           | **Understand Functionality:** Analyze how data is processed by services and identify dependencies between inputs and outputs.       |
| **5** | **Privileges**          | **Identify Permissions:** Determine the privileges of each service's user account and look for overlooked or excessive permissions. |
| **6** | **OS Setup**            | **Internal Recon:** After gaining access, gather information on the OS configuration, security posture, and admin practices.        |

# External Recon (Passive OSINT)

| **Data Point**       | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IP Space`           | Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc.                                                                                                                                                                                                                                                                              |
| `Domain Information` | Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.)                                                                                                                        |
| `Schema Format`      | Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc.                                                                                                                                                                  |
| `Data Disclosures`   | For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain `intranet` site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.) |
| `Breach Data`        | Any publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold.                                                                                                                                                                                                                                                                                                                            |

And where to find that above information...

| **Resource**                     | **Examples**                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ASN / IP registrars`            | [IANA](https://www.iana.org/), [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/)                                                                                                                                                                                                                                                       |
| `Domain Registrars & DNS`        | [Domaintools](https://www.domaintools.com/), [PTRArchive](http://ptrarchive.com/), [ICANN](https://lookup.icann.org/lookup), manual DNS record requests against the domain in question or against well known DNS servers, such as `8.8.8.8`.                                                                                                                                                                                             |
| `Social Media`                   | Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization.                                                                                                                                                                                                                                                                                 |
| `Public-Facing Company Websites` | Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines.                                                                                                                                                                                                                                                       |
| `Cloud & Dev Storage Spaces`     | [GitHub](https://github.com/), [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Google searches using "Dorks"](https://www.exploit-db.com/google-hacking-database)                                                                                                                                                                                                                                        |
| `Breach Data Sources`            | [HaveIBeenPwned](https://haveibeenpwned.com/) to determine if any corporate email accounts appear in public breach data, [Dehashed](https://www.dehashed.com/) to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication. |

## via DNS

Great to validate and discover new information, especially from IP and ASN searches.

- https://whois.domaintools.com/
    - Check ASN
- https://viewdns.info/
    - DNS (Local Namerservers): https://viewdns.info/dnsreport
    - All Records: https://viewdns.info/dnsrecord

## via Search Engine Dorking

- {{< embed-section page="Docs/3 - Info Gathering/search-engine-dorking" header="examples" >}}

- {{< embed-section page="Docs/6 - Post-Exploitation/active-directory" header="user-enumeration-kerbrute" >}}

## via Social Media

Check various sites, especially for different types of IT admins, to skim information about hardware, software, or services used:

- LinkedIn.com
- Indeed.com
- Glassdoor.com

## via other Services

- Leaked Creds: https://dehashed.com/
    - https://github.com/sm00v/Dehashed
    - `curl 'https://api.dehashed.com/search?query=domain:target.com&size=1000' -u <EMAIL>:<API_KEY> -H 'Accept: application/json' > dehashed_results.json`
- Leaked Creds: https://github.com/trufflesecurity/truffleHog
- Public (Data) Buckets: https://buckets.grayhatwarfare.com/

# Internal Recon (Passive)

Passively, sampling the traffic can be a great way to understand the network insofar as hosts, services, and maybe even sometimes credentials!

{{< embed-section page="Docs/5 - Exploitation/protocol-poisoners" header="responder-linux" >}}

```bash
# Sample the network traffic
sudo tcpdump -i <INTERFACE> -w <OUTPUT_FILE>
```