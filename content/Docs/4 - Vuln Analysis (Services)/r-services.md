+++
title = "Nix: R-services"
+++

- `TCP 512/513/514`: `rexecd`, `rlogind`, `rshd`
- `UDP 513`: `rwhod`
- https://en.wikipedia.org/wiki/Berkeley_r-commands
- Server Config
    - `/etc/hosts.equiv`: allowed hosts for `rlogin`
    - `~/{.rlogin, .rhosts}`: allowed hosts

Suite of obsolete remote management tools. All communication is unencrypted including its authentication.

```bash
# Enum via nmap
sudo nmap -sV -p 512,513,514 <TARGET>

# Remote copy; does not confirm remote overwriting of files
rcp
# Remote shell
rsh
# Remote command
rexec
# Remote login (telnet-like)
rlogin <TARGET> -l <USER>
# Show authenticated users
rwho
rusers -al <TARGET>
```
