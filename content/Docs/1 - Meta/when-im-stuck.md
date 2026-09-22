+++
title = "When I'm Stuck"
+++

# When I'm Stuck and How to Unf\*ck It

> Stuck = missing enumeration: **Go wider before you go harder**
> Timebox every lead for 30 min -> write in TRIED, move to next NOT-YET-TRIED

## Per-box

```markdown
- [ ] **FACTS**: hosts, OS, versions, plugins/extensions, creds, findings
- [ ] **ATTACK SURFACE**: every service/port/param/app
- [ ] **TRIED**: dead leads and dead ends
- [ ] **NOT-YET-TRIED**: your next-step list when lost
```

---

## Fatigue Ruke

- 45-90 min blocks
- Then physically leave (walk/gym/food)
- The answer arrives on the walk

---

## 0. Universal 1st Move

- [ ] Full TCP scan `-p-` (not just top-1000), then UDP top-100
- [ ] Re-run enumeration **authenticated** every time you get ANY credential (new creds = new surface)
- [ ] Web dirs: run in order, stop when you get hits:
  1. `raft-medium-directories.txt`
  2. `directory-list-2.3-medium.txt`
  3. tech-specific (CMS list, or add `-x php,txt,bak` etc.)
- [ ] Subdomains + vhosts (a vhost is invisible to a port scan):
  - subs: `subdomains-top1million-5000.txt` -> `subdomains-top1million-110000.txt`
  - vhost: `ffuf -H "Host: FUZZ.<DOMAIN>" ...`

## 1. Stuck on... Foothold

- [ ] Get ALL versions: OS, service, web tech, plugin, extension
- [ ] Default + reused creds: **spray every cred against every service AND every host** (assume valid everywhere until proven otherwise)
- [ ] Misconfigurations: non-standard files, services, open shares, dir listing
- [ ] **Read everything you can already access**: configs, page source + HTML comments, scripts, backups, `.bash_history`. The next step is often in a file you can already read.
- [ ] **Go manual when automated finds nothing**: browse the app by hand, watch every request in Burp, test params yourself (logic flaws don't show in nuclei/nikto)
- [ ] Only now: `searchsploit` with the correlated version numbers from above

## 2. Stuck on... Privesc

- [ ] `whoami /priv` (Win) / `sudo -l` (Lin): FIRST move, highest hit rate
  - Win: `SeImpersonate`/`SeAssignPrimaryToken` -> Potato -> SYSTEM
- [ ] **Internal-only listening ports** (`ss -tlnp` / `netstat -ano`): a service bound to `127.0.0.1` is a huge tell (pivot or privesc)
- [ ] SUID / writable services / cron / scheduled tasks
- [ ] Running processes (`pspy` on Linux for hidden `cron`)
- [ ] Cred hunting in files + history; re-run winPEAS/linpeas and actually read the "interesting" section
- [ ] *Last resort*: Kernel/OS build -> exploit lookup

## 3. Stuck on... Active Directory

- [ ] BloodHound: shortest path to DA from owned principal
- [ ] Kerberoast + AS-REP roast (w/ creds)
- [ ] Cred reuse across the domain (`nxcblast` every user, every host)
- [ ] Re-check what your CURRENT user can already reach that you haven't touched
