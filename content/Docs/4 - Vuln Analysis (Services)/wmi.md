+++
title = "Win: WMI"
+++

- `TCP 135`: first, initialization
- `TCP <RHP>`: afterwards, comms

```bash
# Run interactive shell
impacket-wmiexec <USER>:"<PASSWORD>"@<TARGET>
# Run remote command
impacket-wmiexec <USER>:"<PASSWORD>"@<TARGET> "<COMMAND>"
```
