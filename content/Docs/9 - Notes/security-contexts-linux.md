+++
title = "Security Contexts: Linux"
+++

## Capabilities

- https://www.man7.org/linux/man-pages/man7/capabilities.7.html

The following especially can lead to `root`:

|**Capability**|**Description**|
|---|---|
|`cap_setuid`|Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the `root` user.|
|`cap_setgid`|Allows to set its effective group ID, which can be used to gain the privileges of another group, including the `root` group.|
|`cap_sys_admin`|This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the `root` user, such as modifying system settings and mounting and unmounting file systems.|
|`cap_dac_override`|Allows bypassing of file read, write, and execute permission checks.|

## File Permissions

Standard Permission Bits

| Permission | Octal | Symbol | Meaning on File | Meaning on Directory |
| :--- | :--- | :--- | :--- | :--- |
| **Read** | `4` | `r` | Can read file contents (`cat`). | Can list contents (`ls`). |
| **Write** | `2` | `w` | Can modify file contents. | Can add/delete files inside. |
| **Execute** | `1` | `x` | Can run the file as a process. | Can enter the directory (`cd`). |

Special Permission Bits

| Special Bit             | Octal  | Symbol    | Location             | Offensive Value (PrivEsc / Persistence)                                                                                                  |
| :---------------------- | :----- | :-------- | :------------------- | :--------------------------------------------------------------------------------------------------------------------------------------- |
| **SUID** (Set-User-ID)  | `4000` | `s` / `S` | Owner (`-rwS------`) | **High:** Process runs with the privileges of the file *Owner* (usually root), regardless of who launched it.                            |
| **SGID** (Set-Group-ID) | `2000` | `s` / `S` | Group (`----rws---`) | **Medium:** Process runs with privileges of the file *Group*. Used for lateral movement (e.g., accessing `adm` or `shadow` group files). |
| **Sticky Bit**          | `1000` | `t` / `T` | Other (`-------rwt`) | **None:** Prevents users from deleting other users' files in shared directories (like `/tmp`).                                           |

**NOTE:**

The Lowercase `s` vs. Uppercase `S`
*   **Lowercase `s` (Active):** The SUID bit is set **AND** the underlying execute (`x`) bit is set. The file will execute properly.
*   **Uppercase `S` (Broken):** The SUID bit is set, **BUT** the underlying execute (`x`) bit is missing. The file cannot be executed. The admin made a mistake.

The Linux Kernel natively **ignores SUID/SGID bits on interpreted scripts** (`.sh`, `.py`, `.pl`). 
*   If you find `-rwsr-xr-x root root backup.sh`, running `./backup.sh` will execute as **YOUR** user, not root.
*   **The Exception:** SUID only works automatically on **Compiled ELF Binaries** (C, C++, Go, Rust).

## Groups

Certain groups for a user's `id` output could give greater access:

- `disk`: can mount any disk with `debugfs` to read the file system
- `adm`: reads logs in `/var/log/`
- `docker`: [priv esc](https://gtfobins.org/gtfobins/docker/)
- `lxd`/`lxc`: can mount filesystems in LXC containers
- `shadow`: allows read access of password hashes
- `staff`: grants perms to `/usr/local/bin/` and `/usr/local/sbin/`
- `wireshark`/`pcap`: capture network traffic (creds sniffing)
- `video`: can screenshot user's desktop
- `wheel`: Red Hat/CentOS equivalent to `sudo`
