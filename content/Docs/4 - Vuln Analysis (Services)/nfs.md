+++
title = "NFS"
+++

Similiar to SMB.

- `TCP/UDP 111`: NFSv2/v3
    - and various dynamic ports using `rpcbind` and `portmapper`
- `TCP 2049`: NFSv4
- Server Config: `/etc/exports`
    - https://manpages.ubuntu.com/manpages/trusty/man5/exports.5.html

{{% details "Dangerous Options" %}}

| **Dangerous Option** | **Description**                                                                                                      |
| -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `rw`                 | Read and write permissions.                                                                                          |
| `insecure`           | Ports above 1024 will be used.                                                                                       |
| `nohide`             | If another file system was mounted below an exported directory, this directory is exported by its own exports entry. |
| `no_root_squash`     | All files created by root are kept with the UID/GID 0.                                                               |
{{% /details %}}

```bash
# Show shared dirs
exportfs -sv
# Show NFS Shares on server
showmount -e <TARGET>

# Mount NFS
mkdir target-NFS
sudo mount -t nfs -o nolock <TARGET>:/ ./target-NFS
sudo umount ./target-NFS

# Enumerate
sudo nmap -n -Pn -p111,2049 -sV -sC <TARGET>
sudo nmap -n -Pn -p111,2049 -sV --script 'nfs*' <TARGET>
```
