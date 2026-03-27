# SOC176 — RDP Brute Force Detected

**Platform:** LetsDefend  
**Alert ID:** SOC176  
**Severity:** High  
**Classification:** True Positive — Confirmed Unauthorized Access  
**Analyst:** [John Mark]  
**Date:** [3/24/2026]

---

## Summary

An external IP address (`218.92.0.56`) launched a brute force attack against the RDP service (port 3389) of internal host `Matthew` (`172.16.17.148`). The attacker made **14 consecutive failed login attempts** across multiple usernames before successfully authenticating as user `matthew`. The firewall permitted the traffic throughout, allowing the attack to succeed. The host was immediately isolated via EDR upon confirmation of unauthorized access.

---

## Alert Details

| Field | Value |
|---|---|
| Hostname | Matthew |
| Destination IP | 172.16.17.148 |
| Source IP | 218.92.0.56 |
| Protocol / Port | RDP / TCP 3389 |
| Alert Timestamp | Mar 07, 2024, 11:44 AM |
| Firewall Action | Allowed |
| Failed Login Attempts | 14 (Event ID 4625) |
| Successful Logins | 1 (Event ID 4624) |
| Compromised Account | matthew |

---

## Indicators of Compromise (IOCs)

| Type | Value | Verdict |
|---|---|---|
| Source IP | 218.92.0.56 | Malicious |
| Target port | TCP 3389 (RDP) | Brute forced |
| Compromised account | matthew | Credential guessed |

---

## Threat Intelligence Results

| Platform | Verdict |
|---|---|
| VirusTotal | Flagged as malicious |
| AbuseIPDB | Confirmed malicious — known attack source |
| LetsDefend TI | Confirmed malicious |

All three threat intelligence platforms independently flagged `218.92.0.56` as a known malicious IP, confirming the external origin and malicious intent of the traffic.

---

## Investigation Walkthrough

### 1. Initial Alert Review

I began by taking ownership of the alert and documenting all key metadata: hostname (`Matthew`), source IP (`218.92.0.56`), destination IP (`172.16.17.148`), protocol (RDP / port 3389), and timestamp (Mar 07, 2024, 11:44 AM). The use of RDP from an external IP immediately raised suspicion of a brute force attempt.

### 2. Source IP Enrichment

I checked the reputation of `218.92.0.56` across three threat intelligence platforms — VirusTotal, AbuseIPDB, and LetsDefend TI. All three returned malicious verdicts, confirming the source IP as a known attack origin. The traffic was classified as **external**, originating from outside the network perimeter.

### 3. Log Analysis — Authentication Events

I filtered authentication logs using both the source IP (`218.92.0.56`) and destination IP (`172.16.17.148`) and identified a clear brute force pattern:

**Targeted usernames:**
- `matthew`
- `sysadmin`
- `admin`
- `guest`

**Authentication event summary:**

| Event ID | Event Type | Count |
|---|---|---|
| 4625 | Failed logon | 14 |
| 4624 | Successful logon | 1 |

The pattern of 14 failed attempts followed by 1 successful login on user `matthew` is a textbook brute force attack — the attacker systematically tried credentials until they found a working combination.

### 4. Scope Assessment

I checked whether the same source IP targeted other internal hosts. Log analysis confirmed that **only host `Matthew` was affected** — indicating a targeted attack against a specific endpoint rather than a broad network scan.

### 5. RDP Service Exposure Confirmed

The logs confirmed the attacker was consistently targeting **port 3389 (RDP)**. The firewall action was marked as **Allowed** throughout the entire attack, meaning no network-level controls blocked the brute force traffic — giving the attacker unrestricted access to repeatedly attempt authentication.

### 6. Successful Login Confirmed

Event ID **4624** confirmed a successful logon for user `matthew` from the external IP `218.92.0.56`. This indicated the attacker successfully guessed the credentials and gained unauthorized interactive access to the host via RDP.

### 7. Containment

Upon confirming the successful unauthorized login, I immediately **isolated host `Matthew` via EDR** to:
- Terminate any active attacker RDP session
- Prevent lateral movement within the internal network
- Stop any post-exploitation activity

### 8. Artifact Documentation

The malicious source IP `218.92.0.56` was logged as the primary indicator of compromise for detection rules and future threat intelligence reference.

---

## Attack Flow

```
External attacker (218.92.0.56)
        ↓
RDP brute force against port 3389 on 172.16.17.148
        ↓
14 failed login attempts (Event ID 4625)
Targets: matthew, sysadmin, admin, guest
        ↓
Firewall action: Allowed (traffic not blocked)
        ↓
1 successful login — user: matthew (Event ID 4624)
        ↓
Unauthorized RDP access confirmed
        ↓
Host isolated via EDR
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Description |
|---|---|---|
| T1110 | Brute Force | 14 repeated failed login attempts over RDP |
| T1110.001 | Password Guessing | Attacker guessed credentials for user matthew |
| T1021.001 | Remote Services: Remote Desktop Protocol | RDP used as the access vector |
| T1078 | Valid Accounts | Successful login using guessed valid credentials |

---

## Verdict

**True Positive — Confirmed Unauthorized Access**

The attacker successfully brute-forced the RDP credentials of user `matthew` after 14 failed attempts. The firewall permitted all traffic throughout the attack. A successful logon (Event ID 4624) from the external malicious IP confirmed unauthorized access. The host was isolated immediately upon confirmation.

---

## Recommendations

- [ ] Immediately reset password for user `matthew`
- [ ] Terminate all active RDP sessions on host `Matthew`
- [ ] Block source IP `218.92.0.56` at the firewall and perimeter
- [ ] Disable public-facing RDP — use a VPN or jump server instead
- [ ] Enforce strong password policy — minimum 12 characters, complexity required
- [ ] Enable Multi-Factor Authentication (MFA) for all RDP access
- [ ] Implement account lockout policy after 5 failed attempts (Event ID 4625)
- [ ] Enable geo-blocking or IP allowlisting for RDP if remote access is required
- [ ] Monitor for Event ID 4625 spikes as an early brute force detection signal
- [ ] Review all accounts targeted (sysadmin, admin, guest) for compromise

---

## Tools Used

| Tool | Purpose |
|---|---|
| VirusTotal | Source IP reputation analysis |
| AbuseIPDB | IP abuse history and classification |
| LetsDefend TI | Threat intelligence verification |
| LetsDefend SIEM | Authentication log analysis (Event IDs 4624/4625) |
| LetsDefend EDR | Host isolation and containment |

---

## Key Learnings

- **Brute force attacks are patient.** 14 failed attempts before success shows attackers don't give up — weak or common passwords will eventually be guessed given enough time and attempts.
- **Windows Event IDs are essential for RDP investigation.** Event ID `4625` (failed logon) and `4624` (successful logon) are the primary signals for detecting brute force attacks. Knowing these by heart is fundamental for SOC work.
- **Log correlation reveals the full attack pattern.** Filtering by both source and destination IP exposed the complete sequence of attempts across multiple usernames — no single log entry tells the full story alone.
- **Exposed RDP is a critical risk.** Allowing RDP directly from the internet without IP restrictions, MFA, or account lockout policies creates an easily exploitable attack surface. VPN-gated RDP is always preferable.
- **Multi-source threat intelligence builds confidence.** Confirming the IP across VirusTotal, AbuseIPDB, and LetsDefend TI removed any doubt about malicious intent and accelerated the triage decision.
- **Speed of containment matters.** Once a successful login was confirmed, immediate host isolation was the correct response — every minute of delay increases the risk of lateral movement or data exfiltration.
