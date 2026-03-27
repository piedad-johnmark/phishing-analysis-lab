# SOC326 — Impersonating Domain MX Record Change Detected

**Platform:** LetsDefend  
**Alert ID:** SOC326  
**Severity:** High  
**Classification:** True Positive — Confirmed Malicious Activity  
**Analyst:** [Your Name]  
**Date:** [Date Completed]

---

## Summary

An alert was triggered by a suspicious MX record change on the typosquatted domain `letsdefwnd[.]io`, impersonating the legitimate `letsdefend.io`. A phishing email from `voucher@letsdefwnd[.]io` was delivered to `mateo@letsdefend.io` containing a link to the fake domain. The user clicked the link via Chrome, and log analysis confirmed active communication between host `172.16.17.162` and the malicious IP `45.33.23.183`. Despite the URL initially appearing clean on some platforms, AbuseIPDB confirmed 84 abuse reports on the IP. The phishing email was deleted and the host was contained via EDR.

---

## Alert Details

| Field | Value |
|---|---|
| Alert type | Impersonating Domain MX Record Change |
| Suspicious domain | letsdefwnd[.]io (typosquat of letsdefend.io) |
| Affected user | mateo@letsdefend.io |
| Affected host IP | 172.16.17.162 |
| Sender email | voucher@letsdefwnd[.]io |
| Malicious URL | hxxps[://]letsdefwnd[.]io |
| Active C2 IP | 45.33.23.183 |
| Device action | Allowed (email delivered) |

---

## Indicators of Compromise (IOCs)

| Type | Value | Verdict |
|---|---|---|
| Typosquatted domain | letsdefwnd[.]io | Malicious |
| Sender email | voucher@letsdefwnd[.]io | Malicious |
| Malicious URL | hxxps[://]letsdefwnd[.]io | Malicious |
| C2 IP | 45.33.23.183 | Malicious — 84 AbuseIPDB reports |

---

## Investigation Walkthrough

### 1. Initial Alert Review

I took ownership of the alert and noted the key details: suspicious domain `letsdefwnd[.]io`, associated IP addresses, affected user, and timestamp. The domain was immediately recognizable as a **typosquatted** version of `letsdefend.io` — swapping `e` for `w` to visually deceive users.

### 2. IP Reputation Analysis

The alert report listed multiple IP addresses tied to the suspicious domain. I checked each one on **VirusTotal** — all were flagged as malicious. LetsDefend TI returned no entries for the same IPs, highlighting that no single platform catches everything.

### 3. Log Analysis — Active Communication Identified

I filtered logs by each malicious IP and confirmed that **`45.33.23.183` had successfully communicated with host `172.16.17.162`** (`mateo@letsdefend.io`). This was the key finding that elevated the alert from suspicious to confirmed active threat.

### 4. Email Security Review

Email security logs confirmed a phishing email was delivered to `mateo@letsdefend.io`:

- **Sender:** `voucher@letsdefwnd[.]io`
- **Payload:** Link to `hxxps[://]letsdefwnd[.]io`
- **Device action:** Allowed — the email reached the user's inbox unblocked

### 5. URL Reputation — Clean Result Was Misleading

I checked the URL on VirusTotal, Cisco Talos, and LetsDefend TI. All three returned **clean results**. However, I did not close the alert on this basis alone — the associated IPs were already confirmed malicious, and newly registered phishing domains often evade reputation tools initially. I continued investigating.

### 6. AbuseIPDB — Confirmed Malicious

Checking `45.33.23.183` on **AbuseIPDB** returned **84 community abuse reports**, firmly confirming the IP as malicious and overriding the earlier clean URL verdict.

### 7. EDR Analysis

EDR telemetry on the affected host confirmed:

- **Network connections** to `45.33.23.183`
- **Browser activity** (Chrome) accessing `hxxps[://]letsdefwnd[.]io`
- No suspicious processes identified at the time of review

The browser activity confirmed the user **clicked the phishing link**, directly exposing the host to attacker-controlled infrastructure.

### 8. Containment

- **Deleted the phishing email** from the email security system
- **Isolated host `172.16.17.162`** via EDR to stop further communication with the malicious domain and IP

---

## Attack Flow

```
Attacker registers typosquatted domain: letsdefwnd[.]io
        ↓
MX record changed — domain configured to send phishing email
        ↓
Phishing email sent: voucher@letsdefwnd[.]io → mateo@letsdefend.io
        ↓
Email delivered — device action: Allowed
        ↓
User clicks link → Chrome opens hxxps[://]letsdefwnd[.]io
        ↓
Host 172.16.17.162 communicates with 45.33.23.183
(confirmed in logs + EDR)
        ↓
Phishing email deleted + host contained via EDR
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Description |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | Phishing email with malicious URL delivered to user |
| T1583.001 | Acquire Infrastructure: Domains | Attacker registered typosquatted domain letsdefwnd[.]io |
| T1071.001 | Application Layer Protocol: Web Protocols | Browser communication with C2 over HTTPS |

---

## Verdict

**True Positive — Confirmed Malicious Activity**

The typosquatted domain `letsdefwnd[.]io` was used to deliver a phishing email to `mateo@letsdefend.io`. The user clicked the malicious link, and the host communicated with confirmed malicious IP `45.33.23.183`. The URL appeared clean on initial checks, but IP reputation (AbuseIPDB: 84 reports) and EDR-confirmed network and browser activity proved the activity was malicious.

---

## Recommendations

- [ ] Block IP `45.33.23.183` at the firewall
- [ ] Block domain `letsdefwnd[.]io` in email gateway and DNS filter
- [ ] Remove all emails from `voucher@letsdefwnd[.]io` across all mailboxes
- [ ] Reset credentials for `mateo@letsdefend.io` in case of credential harvesting
- [ ] Implement DNS filtering to catch typosquatted domain variations
- [ ] Add email gateway rules to flag domains with single-character variations of trusted domains
- [ ] Conduct phishing awareness training on domain spoofing and typosquatting

---

## Tools Used

| Tool | Purpose |
|---|---|
| VirusTotal | IP and URL reputation analysis |
| AbuseIPDB | IP abuse history — 84 confirmed reports |
| Cisco Talos | URL reputation cross-check |
| LetsDefend TI | Threat intelligence cross-reference |
| LetsDefend Email Security | Email delivery and sender review |
| LetsDefend SIEM | Log filtering and IP communication confirmation |
| LetsDefend EDR | Browser/network activity confirmation + containment |

---

## Key Learnings

- **A clean URL verdict is not the final word.** VirusTotal, Cisco Talos, and LetsDefend TI all returned clean for the URL — but AbuseIPDB and EDR told a different story. Always correlate across multiple sources before closing an alert.
- **Typosquatting is subtle but detectable.** `letsdefwnd[.]io` vs `letsdefend.io` is a single character swap. Inspecting domain names character by character is an essential SOC habit.
- **MX record changes on lookalike domains are a strong early warning signal.** When a domain resembling a trusted brand configures mail exchange records, it almost always signals an impending phishing campaign.
- **AbuseIPDB fills gaps that other platforms miss.** Different TI platforms index different data — using AbuseIPDB alongside VirusTotal significantly improves detection accuracy.
- **Correlating email, logs, and EDR together confirms the full picture.** The email showed delivery, logs confirmed the IP communication, and EDR confirmed the user clicked — no single source alone would have been conclusive.
