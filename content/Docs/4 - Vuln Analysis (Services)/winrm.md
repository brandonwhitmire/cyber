+++
title = "Win: WinRM"
+++

- `TCP 5985/5986`: via HTTP/HTTPS respectively

```bash
# Enum via nmap
sudo nmap --disable-arp-ping -n -Pn -sV -sC -p5985,5986 <TARGET>

# Connect via WinRM
# https://github.com/Hackplayers/evil-winrm
evil-winrm -u <USER> -p <PASSWORD> -i <HOST>
evil-winrm -u <USER> -H <PASS_HASH> -i <HOST>
```

### PowerShell Remoting

*Requires valid Kerberos Ticket (PtT) or active NTLM Injection (PtH) in the current session.*

**Ports**
*   TCP/5985 (HTTP)
*   TCP/5986 (HTTPS)

**Requirements**
*   Administrative permissions **OR**
*   Member of "Remote Management Users" **OR**
*   Explicit PSSession configuration

```powershell
# PowerShell
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("<DOMAIN>\<USER>", $password)
Enter-PSSession -Credential $cred -ComputerName <TARGET_HOSTNAME>
```