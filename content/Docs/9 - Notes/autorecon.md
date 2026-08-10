+++
title = "AutoRecon"
+++

- [GitHub](https://github.com/Tib3rius/AutoRecon)
- [README / Docs](https://github.com/Tib3rius/AutoRecon/blob/master/README.md)

Multi-threaded enumeration orchestrator that runs baseline enumeration across all services/targets in parallel and organizes output into per-target directories.

**OSCP:** Stock AutoRecon is exam-allowed (enumeration wrapper, not an auto-exploiter) — don't add plugins that invoke banned scanners, and use it to parallelize the baseline, then dig manually.

```bash
autorecon <TARGET>                             # single target
autorecon <TARGET> <TARGET> <TARGET>           # multiple targets, parallel
autorecon --max-scans 10 <TARGET>              # cap concurrency (tune down for exam VPN stability)
```
