+++
title = "🌐 NFS: TCP/UDP 111, TCP 2049"
+++

- `TCP/UDP 111`: NFSv2/v3
    - and various dynamic ports using `rpcbind` and `portmapper`
- `TCP 2049`: NFSv4
- Server Config: `/etc/exports`
    - https://manpages.ubuntu.com/manpages/trusty/man5/exports.5.html

```bash
# Show NFS Shares on server
showmount -e <TARGET>

# Mount NFS
mkdir target-NFS
sudo mount -t nfs -o nolock <TARGET>:/ ./target-NFS
#sudo umount ./target-NFS

# Show shared dirs
df
exportfs -sv
```
