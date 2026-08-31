+++
title = "AutoRecon"
+++

- [GitHub](https://github.com/Tib3rius/AutoRecon)
    - [README / Docs](https://github.com/Tib3rius/AutoRecon/blob/master/README.md)

Multi-threaded enumeration orchestrator that runs baseline enumeration across all services/targets in parallel and organizes output into per-target directories.

**OSCP NOTE:** Stock AutoRecon is exam-allowed (enumeration wrapper, not an auto-exploiter); but do **NOT** add plugins that invoke banned scanners, and use it to parallelize the baseline, then dig manually

```bash
sudo apt install -y autorecon
```

```bash
autorecon -vv <TARGET>
```

```bash
# Includes top 100 UDP ports scan
sudo autorecon -vv <TARGET>
```
