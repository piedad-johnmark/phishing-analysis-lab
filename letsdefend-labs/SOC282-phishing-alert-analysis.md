# SOC282 — Phishing Alert: Deceptive Mail Detected

**Platform:** LetsDefend  
**Alert ID:** SOC282  
**Severity:** High  
**Classification:** True Positive — Confirmed Compromise  
**Analyst:** [John Mark]  
**Date:** [3/26/2026]

---

## Summary

A phishing email with the subject **"Free Coffee Voucher"** was delivered to user `Felix@letsdefend.io` (host: `172.16.20.151`). The email contained a malicious ZIP attachment that, when executed, deployed **Trojan.AsyncRAT/MSIL** and established communication with a command-and-control (C2) server in Romania. The host was confirmed compromised and was subsequently contained via EDR.

---

## Alert Details

| Field | Value |
|---|---|
| Recipient | Felix@letsdefend.io |
| Recipient Host IP | 172.16.20.151 |
| Sender | free@coffeeshooop.com |
| SMTP Address | 103.80.134.63 |
| Subject | Free Coffee Voucher |
| Device Action | Allowed (email delivered) |
| Attachment | free-coffee.zip |

---

## Indicators of Compromise (IOCs)

| Type | Value | Verdict |
|---|---|---|
| Sender domain | coffeeshooop.com | Malicious (typosquatted) |
| SMTP IP | 103.80.134.63 | Suspicious (flagged on VirusTotal) |
| ZIP hash (SHA256) | `6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389` | Malicious |
| EXE hash (SHA256) | `cd903ad2211cf7d166646d75e57fb866000f4a3b870b5ec759929be2fd81d334` | Malicious |
| Executable | coffee.exe | Trojan.AsyncRAT/MSIL |
| C2 IP | 37.120.233.226 | Malicious (Romania) |
| Download URL | `hxxps://files[-]ld[.]s3.us-east-2.amazonaws.com/.../free-coffee.zip` | Malicious |

---

## Investigation Walkthrough

### 1. Initial Alert Review

I began by taking ownership of the alert and reviewing all key metadata: event time, SMTP address, sender email, recipient, subject line, and device action. The subject "Free Coffee Voucher" immediately raised suspicion — using a free reward theme is a well-known social engineering technique to lure users into opening attachments.

The device action was marked as **Allowed**, meaning the email bypassed email security controls and reached the user's mailbox.

### 2. Email & Attachment Analysis

I moved to the Email Security section and confirmed the email contained an attachment named **free-coffee.zip**. The filename and context were immediately suspicious.

I checked the reputation of the SMTP address (`103.80.134.63`) on **VirusTotal**, which returned a suspicious verdict — increasing the probability of a phishing attempt.

I then performed static analysis on the attachment and found existing reports on **Hybrid Analysis** confirming prior malicious activity associated with this file.

Hash verification on VirusTotal confirmed the ZIP file as **malicious**.

### 3. Payload Analysis

Deeper analysis of the ZIP contents revealed:

- An embedded executable: **coffee.exe**
- A hardcoded C2 address: **37.120.233.226**
- Malware family identified as **Trojan.AsyncRAT/MSIL** (Remote Access Trojan)

The malware was designed to establish a persistent backdoor and communicate with the attacker's C2 server.

### 4. Email Delivery Confirmation

The device action was confirmed as **Allowed** — meaning the user had direct access to the malicious attachment and the email was not quarantined or blocked.

**Immediate action taken:** Deleted the malicious email from the user's mailbox to prevent further interaction.

### 5. Network Log Analysis

I filtered network logs using the affected host IP (`172.16.20.151`) and observed **outbound connections to `37.120.233.226`**, confirming active C2 communication from the compromised host.

Log review also revealed the download URL that was used to retrieve the malicious payload.

### 6. EDR & Endpoint Analysis

EDR telemetry on the affected host confirmed:

- Network activity connecting to the malicious C2 IP
- Browser history showing the malicious URL had been accessed (user interaction confirmed)
- **coffee.exe was executed** on the system — malware successfully ran

The combination of email delivery, malicious file execution, and confirmed C2 communication led to the conclusion that the host was **fully compromised**.

### 7. Containment

I immediately **contained the affected host via EDR** to:
- Stop ongoing C2 communication
- Prevent potential lateral movement within the network

### 8. Artifact Documentation

All relevant artifacts were added for documentation and future threat intelligence reference:

- Malicious IP: `37.120.233.226`
- SMTP address: `103.80.134.63`
- Sender email: `free@coffeeshooop.com`
- File hashes (ZIP + EXE)
- Download URL

---

## Attack Flow

```
Phishing email delivered (free@coffeeshooop.com)
        ↓
User receives "Free Coffee Voucher" email — device action: Allowed
        ↓
User downloads free-coffee.zip from embedded URL
        ↓
User extracts and executes coffee.exe
        ↓
Trojan.AsyncRAT/MSIL establishes C2 communication
        ↓
Outbound connection to 37.120.233.226 (Romania) confirmed in logs
        ↓
Host contained via EDR
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Description |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Malicious ZIP delivered via email |
| T1204.002 | User Execution: Malicious File | User executed coffee.exe |
| T1105 | Ingress Tool Transfer | Payload downloaded from S3 URL |
| T1071 | Application Layer Protocol | C2 communication over standard protocol |
| T1059 | Command and Scripting Interpreter | AsyncRAT command execution behavior |

---

## Verdict

**True Positive — Confirmed Compromise**

The phishing email successfully delivered a malicious payload (Trojan.AsyncRAT/MSIL), which was executed by the user and established active communication with a C2 server. Full endpoint compromise was confirmed via EDR telemetry and network logs.

---

## Recommendations

- [ ] Block C2 IP `37.120.233.226` on firewall and EDR
- [ ] Block sender domain `coffeeshooop.com` in email gateway
- [ ] Remove all malicious files (`free-coffee.zip`, `coffee.exe`) from the system
- [ ] Reset credentials of affected user `Felix@letsdefend.io`
- [ ] Perform full endpoint forensics to identify persistence mechanisms
- [ ] Monitor network logs for lateral movement indicators
- [ ] Conduct phishing awareness training for all users

---

## Tools Used

| Tool | Purpose |
|---|---|
| VirusTotal | Hash and IP reputation analysis |
| Hybrid Analysis | Static/dynamic malware analysis |
| LetsDefend SIEM | Log analysis and alert investigation |
| LetsDefend EDR | Endpoint telemetry and containment |
| LetsDefend Email Security | Email header and attachment analysis |

---

## Key Learnings

- A phishing attack can escalate from a simple email to full system compromise quickly — analyzing the **entire attack chain** matters more than focusing on a single indicator.
- Validating file hashes across **multiple threat intelligence platforms** (VirusTotal + Hybrid Analysis) provides stronger confidence in verdicts.
- **Log correlation** across email security, EDR, and network logs is essential to confirm compromise — no single data source tells the full story.
- Even with email security controls in place, a **device action of "Allowed"** means the user is the last line of defense — phishing awareness training is critical.
- Recognizing **AsyncRAT behaviors** (C2 beaconing, remote access capability) helps prioritize and accelerate incident response.
- Knowing **when to contain** a host — and doing it quickly — is key to preventing lateral movement and further damage.
