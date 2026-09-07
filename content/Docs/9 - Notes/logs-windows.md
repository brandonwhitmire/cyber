+++
title = "Logs - Windows"
+++

## References

- Privilege constants (`SeDebugPrivilege`, etc.): https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
- ACLs overview: https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
    - ACE strings reference: https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings?redirectedfrom=MSDN
    - Understanding SDDL Syntax: https://uwconnect.uw.edu/it?id=kb_article_view&sysparm_article=KB0034194
- Event Tracing for Windows: https://web.archive.org/web/20230222121234/https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw
- Threat Hunting on Event Log IDs: https://github.com/webpro255/Windows-Sysmon-Threat-Hunting-Guide

## Advanced XML Query (in Windows Event Viewer)

- https://techcommunity.microsoft.com/blog/askds/advanced-xml-filtering-in-the-windows-event-viewer/399761

Replacing `<QUERY>` to better fine-tune log filtering:
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[<QUERY>]</Select>
  </Query>
</QueryList>
```

Local Time -> UTC: Click an Event > Details > XML View > check a tag like `<TimeCreated SystemTime>`

Here's an example filter using a Logon ID and after time frame in UTC (**after converting from the Local Time**):
```xml
EventData[Data[@Name='SubjectLogonId']='0x3E7']] and *[System[TimeCreated[@SystemTime&gt;='2022-08-03T17:23:25.000Z']]
```

## Logs

### System

| Event ID                                                                                               | Name                         | Cybersecurity Relevance                                                      |
| ------------------------------------------------------------------------------------------------------ | ---------------------------- | ---------------------------------------------------------------------------- |
| [1074](https://serverfault.com/questions/885601/windows-event-codes-for-startup-shutdown-lock-unlock)  | System Shutdown/Restart      | Unexpected reboots can indicate malware or unauthorized access               |
| [6005](https://superuser.com/questions/1137371/how-to-find-out-if-windows-was-running-at-a-given-time) | Event Log service started    | Marks boot-up; baseline for incident timeline; can flag unauthorized reboots |
| [6006](https://learn.microsoft.com/en-us/answers/questions/235563/server-issue)                        | Event Log service stopped    | Abnormal occurrence outside shutdown = possible log-disruption attempt       |
| [6013](https://serverfault.com/questions/885601/windows-event-codes-for-startup-shutdown-lock-unlock)  | Windows uptime (daily)       | Shorter-than-expected uptime flags unexpected reboot                         |
| [7040](https://www.slideshare.net/Hackerhurricane/finding-attacks-with-these-6-events)                 | Service startup type changed | Manual↔Automatic on a critical service = possible tampering                  |

### Security

| Event ID                                                                                                                                                                                            | Name                                         | Cybersecurity Relevance                                              |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------- |
| [1102](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=1102)                                                                                                    | Audit log cleared                            | Classic anti-forensics / evidence removal indicator                  |
| [1116](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide)                                                    | Defender malware detected                    | Spike = targeted attack or wide infection                            |
| [1118](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide)                                                    | Defender remediation started                 | Track through to 1119/1120 for outcome                               |
| [1119](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide)                                                    | Defender remediation succeeded               | Confirms threat neutralized                                          |
| [1120](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide)                                                    | Defender remediation failed                  | Requires immediate follow-up                                         |
| [4624](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624)                                                                                                    | Successful logon                             | Baseline normal behavior; Logon Type + Logon ID are the pivot fields |
| [4625](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625)                                                                                                    | Failed logon                                 | Volume spikes = brute force                                          |
| [4648](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4648)                                                                                                    | Logon with explicit credentials              | Common lateral movement indicator                                    |
| [4656](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4656)                                                                                                    | Handle to object requested                   | Access attempt on sensitive resource (file/registry/process)         |
| [4672](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4672)                                                                                                    | Special privileges assigned to new logon     | Confirms superuser-level logon; watch for abuse                      |
| [4698](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4698)                                                                                                    | Scheduled task created                       | Classic persistence mechanism                                        |
| [4700](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4700) / [4701](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4701) | Scheduled task enabled/disabled              | Persistence manipulation                                             |
| [4702](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4702)                                                                                                    | Scheduled task updated                       | Same persistence-tampering relevance as 4698                         |
| [4719](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4719)                                                                                                    | Audit policy changed                         | Attacker disabling/altering what gets logged                         |
| [4738](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4738)                                                                                                    | User account changed                         | Privilege/group/setting changes — account takeover indicator         |
| [4771](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4771)                                                                                                    | Kerberos pre-auth failed                     | Kerberos-equivalent of 4625; volume = brute force against Kerberos   |
| [4776](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4776)                                                                                                    | DC credential validation attempt             | Multiple failures = brute force against DC                           |
| [4907](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4907)                                                                | SACL changed                                 | Changing file, service, registry key, object, etc. permissions       |
| [5001](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide)                                                    | Defender real-time protection config changed | Unauthorized change = EDR/AV tampering attempt                       |
| [5140](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5140)                                                                                                    | Network share accessed                       | Unauthorized share access detection                                  |
| [5142](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5142)                                                                                                    | Network share added                          | New share = potential exfil/malware-spread vector                    |
| [5145](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5145)                                                                                                    | Share access permission check                | Repeated checks = share-mapping/recon behavior                       |
| [5157](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5157)                                                                                                    | WFP blocked a connection                     | Surfaces blocked malicious traffic                                   |
| [7045](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=7045)                                                                                                    | Service installed                            | Sudden unknown service = common malware persistence pattern          |

## Enumeration

```powershell
# List all logs
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize

# List all logging providers
Get-WinEvent -ListProvider * | Format-Table -AutoSize
```

**Examples**
```powershell
Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -Oldest -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

$startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
$endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

### Filtering events with FilterHashtable & XML

- Sysmon Event ID
    - 3 - Network connection: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003
    - 7 - Image loaded: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90007

**Suspicious network connection to a particular IP (`52.113.194.132`)**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} |
`ForEach-Object {
$xml = [xml]$_.ToXml()
$eventData = $xml.Event.EventData.Data
New-Object PSObject -Property @{
    SourceIP = $eventData | Where-Object {$_.Name -eq "SourceIp"} | Select-Object -ExpandProperty '#text'
    DestinationIP = $eventData | Where-Object {$_.Name -eq "DestinationIp"} | Select-Object -ExpandProperty '#text'
    ProcessGuid = $eventData | Where-Object {$_.Name -eq "ProcessGuid"} | Select-Object -ExpandProperty '#text'
    ProcessId = $eventData | Where-Object {$_.Name -eq "ProcessId"} | Select-Object -ExpandProperty '#text'
}
}  | Where-Object {$_.DestinationIP -eq "52.113.194.132"}

# OR
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='52.113.194.132']]"
```

**Looking for anomalous `clr.dll` and `mscoree.dll` loading activity**
```powershell
$Query = @"
    <QueryList>
        <Query Id="0">
            <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=7)]] and *[EventData[Data='mscoree.dll']] or *[EventData[Data='clr.dll']]
            </Select>
        </Query>
    </QueryList>
"@
Get-WinEvent -FilterXml $Query | ForEach-Object {Write-Host $_.Message `n}
```

**Filtering events with FilterXPath**
```powershell
# See when the Accept EULA for Sysinternals was added to Registry
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[EventData[Data[@Name='Image']='C:\Windows\System32\reg.exe']] and *[EventData[Data[@Name='CommandLine']='`"C:\Windows\system32\reg.exe`" ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f']]" | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

### Filtering events based on property values

```powershell
# Show available, filterable Properties for an Event Type
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 1 | Select-Object -Property *
```

**Filter Event ID 1 (new process) with Command Line containing `-enc`**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Properties[21].Value -like "*-enc*"} | Format-List
```

**Search in folder of saved event log for string `\\*\PRINT` in Message Property**
```powershell
Get-WinEvent -Path "C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement\*" | Where-Object { $_.Message -match '\\\\\*\\PRINT' } | fl
```

## Sysmon

- Event IDs: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events
- Sysmon Configurations:
    - https://github.com/SwiftOnSecurity/sysmon-config
    - https://github.com/olafhartong/sysmon-modular

```powershell
wget https://download.sysinternals.com/files/Sysmon.zip

# Install Sysmon
sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n

# Load configuration file
sysmon.exe -c <XML_CONFIG>

# Verify Sysmon is running config
sysmon.exe -c
(Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1).TimeCreated
```

### DLL Hijacks

- DLL Hijacking Techniques: https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows

In [`sysmon-config`](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml), change `<ImageLoad onmatch="include">` to `<ImageLoad onmatch="exclude">` to collect all DLL hijacking events.

The the events can be view in Event Viewer:
- "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon"

**Search for Image Loaded events where the DLL is NOT signed**
```powershell
Get-WinEvent -Path 'C:\Logs\DLLHijack\DLLHijack.evtx' | Where-Object {$_.Id -eq 7} | Where-Object {$_.Properties[12].Value -like "false"} | Format-List
```

### Unmanaged Code

Search for processes that load `clr.dll`, `clrjit.dll`, and `mscoree.dll` that ordinarily wouldn't require them.

```powershell
Get-WinEvent -Path 'C:\Logs\PowershellExec\PowershellExec.evtx' -FilterXPath "*[System[EventID=7]]" |
Where-Object { $_.Message -match 'clr\.dll|mscoree\.dll|clrjit\.dll' } |
ForEach-Object {
    $x = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time   = $_.TimeCreated
        Proc   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        Loaded = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'ImageLoaded'}).'#text'
        PID    = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
    }
} | Format-List
```

### Process Injection

- Sysmon Event ID 8:
    - Create New Thread (usually Process Injection): https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008

```powershell
Get-WinEvent -Path 'C:\Logs\PowershellExec\PowershellExec.evtx' | Where-Object {$_.Properties[5].Value -like "*clr.dll*"} | Format-List
```

```powershell
Get-WinEvent -Path 'C:\Logs\PowershellExec\PowershellExec.evtx' -FilterXPath "*[System[EventID=8]]" |
ForEach-Object {
    $x = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        SourceImage = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceImage'}).'#text'
        SourcePID   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceProcessId'}).'#text'
        TargetImage = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetImage'}).'#text'
        TargetPID   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetProcessId'}).'#text'
    }
} | Format-List
```

### LSASS Dump

- Sysmon Event ID 10:
    - ProcessAccess (usually LSASS Dump): https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010
- Access Granted Mask: https://www.eventpeeker.com/event-id/10
    - `0x1010`: Mimikatz (sekurlsa::logonpasswords)
    - `0x1410`: ProcDump / Task Manager full dump
    - `0x1fffff`: PROCESS_ALL_ACCESS (e.g. ProcessHacker)

```powershell
Get-WinEvent -Path 'C:\Logs\Dump\*' -FilterXPath "*[System[EventID=10]]" |
Where-Object {
    ([xml]$_.ToXml()).Event.EventData.Data |
    Where-Object { $_.Name -eq 'TargetImage' -and $_.'#text' -like '*lsass.exe*' }
} |
ForEach-Object {
    $x = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time          = $_.TimeCreated
        SourceImage   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceImage'}).'#text'
        SourcePID     = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceProcessId'}).'#text'
        TargetImage   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetImage'}).'#text'
        GrantedAccess = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'GrantedAccess'}).'#text'
    }
} |
Where-Object { $_.GrantedAccess -in @('0x1010','0x1410','0x143a','0x1fffff') } |
Format-List
```

#### Logon Events After Time

This can be useful to see if after LSASS dump, if any unusual user has logged on.

```powershell
Get-WinEvent -Path 'C:\Logs\Dump\*' -FilterXPath "*[System[EventID=4624]]" |
Where-Object { $_.TimeCreated -ge (Get-Date '4/27/2022 7:08:56 PM') } |
ForEach-Object {
    $x = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        TargetUser  = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        LogonType   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
        SourceIP    = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        LogonProc   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonProcessName'}).'#text'
    }
} | Format-List
```

### Code Execution/Terminal Usage from Strange Process

- 

- Sysmon Event ID 1:
    - Process Creation (but of `cmd.exe` or PowerShell): https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001

```powershell
Get-WinEvent -Path 'C:\Logs\StrangePPID\*' -FilterXPath "*[System[EventID=1]]" |
Where-Object {
    ([xml]$_.ToXml()).Event.EventData.Data |
    Where-Object { $_.Name -eq 'Image' -and $_.'#text' -match 'cmd\.exe|powershell\.exe' }
} |
ForEach-Object {
    $x = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Process     = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        PID         = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
        Parent      = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'ParentImage'}).'#text'
        ParentPID   = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'ParentProcessId'}).'#text'
        CommandLine = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
    }
} | Format-List
```

