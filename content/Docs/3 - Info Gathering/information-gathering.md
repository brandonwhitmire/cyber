+++
title = "Information Gathering"
+++

- Ports:
    - https://www.stationx.net/common-ports-cheat-sheet/
    - https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf
    - https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/
- OS Identification via:
    - TTL: https://subinsb.com/default-device-ttl-values/

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
