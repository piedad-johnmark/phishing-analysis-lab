# BlueSky Ransomware — Full Attack Chain Analysis

**Platform:** CyberDefender  
**Lab:** BlueSky Ransomware  
**Classification:** Ransomware Investigation  
**Analyst:** [John Mark]  
**Date:** [3/27/2026]  
**Reference:** [Unit42 BlueSky Ransomware Report](https://unit42.paloaltonetworks.com/bluesky-ransomware/)

---

## Summary

A complete ransomware attack chain was reconstructed using PCAP network traffic and Windows EVTX event logs. The attacker began with active port scanning to identify an exposed MSSQL server, then authenticated using valid credentials. Post-access, they enabled `xp_cmdshell` for remote command execution, injected into `winlogon.exe` for privilege escalation, downloaded malicious PowerShell scripts to disable Windows Defender, established persistence via a scheduled task, dumped credentials using `Invoke-PowerDump.ps1`, performed network discovery, and finally deployed the **BlueSky ransomware** payload (`javaw.exe`), resulting in file encryption and ransom note creation.

---

## Artifacts Analyzed

| Artifact | Type | Tool Used |
|---|---|---|
| Network capture | PCAP | Wireshark |
| Windows event logs | EVTX | Event Log Viewer |
| Ransomware payload | EXE (external) | ANY.RUN sandbox |
| Encoded commands | Base64 | CyberChef |

---

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Attacker C2 server | 87.96.21.84 | Payload delivery server |
| Malicious script | hxxp://87.96.21.84/checking.ps1 | Privilege check + Defender disable |
| Malicious script | hxxp://87.96.21.84/del.ps1 | Defense evasion |
| Ransomware payload | hxxp://87.96.21.84/javaw.exe | BlueSky ransomware binary |
| Credential dump output | hashes.txt | Dumped via Invoke-PowerDump.ps1 |
| Host discovery output | extracted_hosts.txt | Network reconnaissance results |
| Scheduled task | \Microsoft\Windows\MUI\LPUpdate | Persistence mechanism |
| Injected process | winlogon.exe | Privilege escalation + C2 |

---

## Attack Chain Reconstruction

### 1. Reconnaissance — Port Scanning

Using Wireshark with the filter `tcp.flags.syn == 1`, I identified a suspicious external IP performing TCP SYN requests against multiple ports — a clear **port scan** to identify exposed services on the target network.

**Protocol Hierarchy** analysis revealed the presence of **Tabular Data Stream (TDS)** traffic, indicating the attacker had identified and was targeting an **MSSQL server**.

### 2. Initial Access — MSSQL Credential Abuse

Applying the `tds` filter in Wireshark, I located a **TDS7 login packet** containing the credentials successfully used by the attacker to authenticate to the MSSQL server. The login was successful, confirming **valid account abuse** as the initial access vector.

### 3. Execution — Enabling xp_cmdshell

After gaining MSSQL access, the attacker executed the following SQL configuration commands:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

Enabling `xp_cmdshell` allows operating system commands to be executed directly from SQL Server — effectively turning the database into a remote code execution engine. These commands were confirmed in both the PCAP and the **EVTX event logs**, providing dual-source validation.

### 4. Privilege Escalation — Process Injection into winlogon.exe

PowerShell-related EVTX log entries revealed that the attacker performed **process injection into `winlogon.exe`**. This is a high-value target for injection because `winlogon.exe` runs as SYSTEM and is always present — giving the attacker SYSTEM-level privileges and a persistent C2 channel that blends in with legitimate processes.

### 5. Defense Evasion — Disabling Windows Defender

Using the filter `http.request.method == "GET"`, I identified the first malicious download:

```
http://87.96.21.84/checking.ps1
```

Following the HTTP stream revealed this script:
- Checked the host's **Group SID** to verify privilege level
- Modified **registry keys to disable Windows Defender** functionalities

A second script was also downloaded:

```
http://87.96.21.84/del.ps1
```

This script's primary purpose was additional **defense evasion (MITRE TA0005)**, further crippling the host's security controls.

### 6. Persistence — Scheduled Task Creation

Applying the Wireshark filter `http contains "schtasks"` revealed a packet related to scheduled task creation. Following the TCP stream confirmed the full task name:

```
\Microsoft\Windows\MUI\LPUpdate
```

This scheduled task ensures the attacker maintains persistent access to the compromised system across reboots, disguised under a legitimate-looking Windows path.

### 7. Credential Access — Invoke-PowerDump

Stream analysis identified the use of **`Invoke-PowerDump.ps1`** — a well-known credential dumping tool. Applying the filter `http contains "Invoke-PowerDump.ps1"` revealed multiple associated packets.

An **EncodedCommand** was found in the HTTP stream. I decoded it using **CyberChef** (Base64 decode) and identified the output file:

```
hashes.txt
```

This file contained the dumped credential hashes from the compromised host.

### 8. Discovery — Network Host Enumeration

Continued stream analysis revealed another output file:

```
extracted_hosts.txt
```

This file contained a list of discovered systems in the network, indicating the attacker was **mapping the internal network** in preparation for lateral movement.

### 9. Lateral Movement — Inferred

Based on the credential dump (`hashes.txt`) and host discovery (`extracted_hosts.txt`), lateral movement was inferred as the next logical step in the attack chain, though direct evidence was not captured in the provided artifacts.

### 10. Impact — BlueSky Ransomware Deployment

Using the filter `http contains ".exe"`, I identified the ransomware payload download:

```
http://87.96.21.84/javaw.exe
```

Initial checks on VirusTotal and Cisco Talos returned no detections — a reminder that newly deployed ransomware samples can evade signature-based detection. Further analysis on **ANY.RUN sandbox** confirmed the file's association with the **BlueSky ransomware family**, revealing:

- File encryption behavior
- Creation of a **ransom note** on the infected system

---

## Full Attack Flow

```
Port scan → MSSQL server identified
        ↓
TDS7 login with valid credentials (Initial Access)
        ↓
xp_cmdshell enabled → Remote command execution via SQL
        ↓
Process injection into winlogon.exe (Privilege Escalation)
        ↓
checking.ps1 downloaded → Windows Defender disabled
        ↓
del.ps1 downloaded → Further defense evasion
        ↓
Scheduled task created: \Microsoft\Windows\MUI\LPUpdate (Persistence)
        ↓
Invoke-PowerDump.ps1 → hashes.txt (Credential Dumping)
        ↓
extracted_hosts.txt → Internal network mapped (Discovery)
        ↓
javaw.exe downloaded → BlueSky ransomware deployed (Impact)
        ↓
Files encrypted + ransom note created
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Evidence |
|---|---|---|
| T1595 | Active Scanning | TCP SYN port scan in PCAP |
| T1078 | Valid Accounts | MSSQL TDS7 login with valid credentials |
| T1059.001 | PowerShell | checking.ps1 and del.ps1 execution |
| T1055 | Process Injection | Injection into winlogon.exe |
| T1562.001 | Disable Security Tools | Registry changes disabling Windows Defender |
| T1053.005 | Scheduled Task | \Microsoft\Windows\MUI\LPUpdate |
| T1003 | OS Credential Dumping | Invoke-PowerDump.ps1 → hashes.txt |
| T1018 | Remote System Discovery | extracted_hosts.txt |
| T1071.001 | Web Protocols | HTTP C2 communication with 87.96.21.84 |
| T1021 | Remote Services | Inferred from credential use + host discovery |
| T1486 | Data Encrypted for Impact | BlueSky ransomware file encryption + ransom note |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Wireshark | PCAP analysis — network traffic, filters, stream following |
| Windows Event Viewer | EVTX log analysis — SQL and PowerShell events |
| CyberChef | Base64 decoding of encoded PowerShell commands |
| VirusTotal | Payload and URL reputation analysis |
| Cisco Talos | Threat intelligence cross-reference |
| ANY.RUN | Dynamic sandbox analysis of javaw.exe |
| Kali Linux | Analysis environment |

---

## Key Learnings

- **PCAP + EVTX correlation is powerful.** The same SQL commands appeared in both network traffic and event logs — dual-source confirmation removes all doubt and is a strong evidence-building technique.
- **xp_cmdshell is a critical MSSQL hardening target.** Enabling this feature turns a database into a full command execution platform. It should always be disabled in production environments.
- **Threat intelligence can miss new samples.** `javaw.exe` returned clean on VirusTotal and Cisco Talos initially — only sandbox analysis on ANY.RUN confirmed it as BlueSky ransomware. Never rely on a single clean verdict for executable files.
- **Wireshark filters are essential for efficiency.** Filters like `tcp.flags.syn == 1`, `tds`, `http.request.method == "GET"`, and `http contains "schtasks"` dramatically narrowed down relevant traffic in a large PCAP.
- **Attackers use legitimate tools to blend in.** `winlogon.exe`, `schtasks`, `PowerShell`, and `regsvr32` are all built-in Windows tools. Detecting abuse requires behavioral context, not just process name monitoring.
- **Base64 encoding is a common obfuscation technique.** Decoding attacker commands with CyberChef is a fundamental skill for uncovering what malicious scripts are actually doing.
- **Reconstructing the full attack chain matters.** Understanding how each stage connects — from port scan to ransomware — is what separates reactive alert handling from proactive incident response.
