+++
title = "Pre-Engagement"
+++

# Baseline Tracking of Technological Assets

Diagrams.net: https://app.diagrams.net/

- DNS records, network device backups, and DHCP configurations
- Full and current application inventory
- A list of all enterprise hosts and their location
- Users who have elevated permissions
- A list of any dual-homed hosts (2+ network interfaces)
- Keeping a visual network diagram of your environment

# People, Processes, and Technology

## Processes

- Proper policies and procedures for asset monitoring and management
    - Host audits, the use of asset tags, and periodic asset inventories can help ensure hosts are not lost
- Access control policies (user account provisioning/de-provisioning), multi-factor authentication mechanisms
- Processes for provisioning and decommissioning hosts (i.e., baseline security hardening guideline, gold images)
- Change management processes to formally document who did what and when they did it

### Perimeter First

- What exactly are we protecting?
- What are the most valuable assets the organization owns that need securing?
- What can be considered the perimeter of our network?
- What devices & services can be accessed from the Internet? (Public-facing)
- How can we detect & prevent when an attacker is attempting an attack?
- How can we make sure the right person &/or team receives alerts as soon as something isn't right?
- Who on our team is responsible for monitoring alerts and any actions our technical controls flag as potentially malicious?
- Do we have any external trusts with outside partners?
- What types of authentication mechanisms are we using?
- Do we require Out-of-Band (OOB) management for our infrastructure. If so, who has access permissions?
- Do we have a Disaster Recovery plan?

### Internal Considerations

- Are any hosts that require exposure to the internet properly hardened and placed in a DMZ network?
- Are we using Intrusion Detection and Prevention systems within our environment?
- How are our networks configured? Are different teams confined to their own network segments?
- Do we have separate networks for production and management networks?
- How are we tracking approved employees who have remote access to admin/management networks?
- How are we correlating the data we are receiving from our infrastructure defenses and end-points?
- Are we utilizing host-based IDS, IPS, and event logs?

# 3rd-parties-infrastructure

- AWS: https://aws.amazon.com/es/security/penetration-testing/

# Sensitive Data Regulations

- UK: https://www.gov.uk/data-protection
- US:
    - General: https://www.ftc.gov/business-guidance/privacy-security
    - Financial: https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act
    - Health: https://www.hhs.gov/hipaa/index.html