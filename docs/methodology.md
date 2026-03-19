# Vulnerability Management Methodology

**Project:** vuln-management  
**Author:** Reinhard (github.com/Reinhard1268)  
**Standard:** NIST SP 800-40 r4 aligned

---

## 1. Vulnerability Management Lifecycle
```
┌─────────────────────────────────────────────────────────────────┐
│                 Vulnerability Management Lifecycle               │
│                                                                  │
│  1. DISCOVER    2. PRIORITISE    3. REMEDIATE    4. VERIFY      │
│  ┌─────────┐   ┌─────────────┐  ┌───────────┐  ┌──────────┐   │
│  │OpenVAS  │→  │CVSS + EPSS  │→ │Patch /    │→ │Rescan +  │   │
│  │Trivy    │   │+ Business   │  │Workaround │  │Confirm   │   │
│  │(daily)  │   │Context      │  │(SLA-based)│  │Fixed     │   │
│  └─────────┘   └─────────────┘  └───────────┘  └──────────┘   │
│       │               │                │               │         │
│       └───────────────┴────────────────┴───────────────┘        │
│                    Dashboard + TheHive + Reports                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Why EPSS + CVSS Beats CVSS Alone

### The Problem with CVSS-Only Prioritisation

CVSS measures the *theoretical maximum damage* if a vulnerability were exploited under ideal conditions. It does not measure:
- Whether anyone is actually exploiting it
- Whether exploit code exists
- Whether attackers are targeting it in the wild

Research from FIRST.org shows that **over 80% of CVSS Critical and High vulnerabilities are never exploited in practice.** Using CVSS alone means security teams spend most of their time patching theoretical risks while ignoring vulnerabilities being actively exploited.

### How EPSS Solves This

EPSS (Exploit Prediction Scoring System) models the probability of a CVE being exploited within the next 30 days, based on:
- CVSS characteristics (serves as a prior)
- NVD metadata
- Observed exploitation data from threat intelligence feeds
- Social media and researcher activity signals
- Public exploit code availability

EPSS is updated daily by FIRST.org and is freely available.

### The Composite Score Model Used in This Project
```
Composite Score = CVSS Component  (0–40 pts)
               + EPSS Component   (0–35 pts)
               + Business Context (0–25 pts)
               = Total            (0–100)
```

**CVSS Component (40 pts max):**
```
cvss_pts = (cvss_score / 10.0) × 40
```

**EPSS Component (35 pts max):**
```
epss_pts = epss_probability × 35
```

**Business Context (25 pts max):**
```
asset_value = f(criticality, data_sensitivity)
biz_pts     = asset_value × 25 × exposure_multiplier
```

Exposure multipliers:
- Internet-facing: ×1.5
- Contains PII:    ×1.4
- Production:      ×1.3
- Dev/test:        ×0.7

### Practical Example

| CVE            | CVSS | EPSS  | Asset        | CVSS pts | EPSS pts | Biz pts | Total |
|----------------|------|-------|--------------|----------|----------|---------|-------|
| CVE-2021-44228 | 10.0 | 0.975 | web-server   | 40.0     | 34.1     | 22.5    | 96.6  |
| CVE-2022-XXXX  | 9.5  | 0.003 | dev-server   | 38.0     | 0.1      | 5.0     | 43.1  |
| CVE-2023-44487 | 7.5  | 0.882 | docker-host  | 30.0     | 30.9     | 18.7    | 79.6  |

CVE-2022-XXXX scores only 43.1 despite CVSS 9.5 — nobody is exploiting it.
CVE-2023-44487 scores 79.6 — it was actively exploited at scale. Fix it first.

---

## 3. Business Risk Context Importance

A CVSS 9.8 on a dev laptop with no internet exposure should not be treated the same as a CVSS 7.5 on an internet-facing server storing PII. The business context layer considers:

| Factor           | High Risk Value               | Low Risk Value        |
|------------------|-------------------------------|----------------------|
| Criticality      | Critical system (SIEM, DB)    | Developer workstation |
| Exposure         | Internet-facing               | Air-gapped / isolated |
| Data sensitivity | PII, financial data           | Public data           |
| Environment      | Production                    | Development/test      |

Asset profiles are defined in `prioritization/business-risk-model/assets.json` and are fully extensible.

---

## 4. SLA Framework Rationale

| Severity | SLA      | Rationale                                                   |
|----------|----------|-------------------------------------------------------------|
| Critical | 24 hours | Active exploits exist; exposure window must be minimal      |
| High     | 72 hours | High exploitation probability; patch before the weekend     |
| Medium   | 30 days  | Standard patch cycle; batch with OS/app updates             |
| Low      | 90 days  | Minimal real-world risk; quarterly patch cycle acceptable   |

**EPSS Override:** Any vulnerability with EPSS ≥ 0.50 is escalated to Critical SLA regardless of CVSS score, because the data shows active exploitation in the wild.

---

## 5. Remediation Prioritisation Decision Tree
```
Vulnerability detected
         │
         ├─ EPSS ≥ 0.50? ───────────────────→ Fix within 24h (Critical SLA)
         │
         ├─ Composite score ≥ 80? ──────────→ Fix within 24h
         │
         ├─ Composite score ≥ 60? ──────────→ Fix within 72h
         │
         ├─ Composite score ≥ 40? ──────────→ Fix within 30 days
         │
         ├─ Asset is internet-facing AND
         │  CVSS ≥ 7.0? ────────────────────→ Upgrade to next severity tier
         │
         ├─ No patch available?
         │    ├─ Compensating control possible? → Document + review in 30 days
         │    └─ Cannot mitigate? → Accept risk, document, escalate if Critical
         │
         └─ All others ─────────────────────→ Fix within 90 days
```

---

## 6. Integration with Projects 1–8

### Project 1 — HomeSOC (Wazuh + Elastic + TheHive + Shuffle)
- Wazuh agents on lab hosts feed active exploitation attempts back into context.
- Elastic stores scan results for long-term trending and correlation.
- TheHive cases are auto-created by `thehive-ticket-creator.py` for Critical/High findings.
- **Pipeline:** Scan → EPSS score → TheHive case → Wazuh alert if exploit attempted → SOAR escalation.

### Project 2 — Detection Engineering (Sigma Rules)
- Sigma rules can target exploitation signatures for CVEs in the open findings list.
- Example: CVE-2021-44228 open on host → Sigma rule detecting JNDI lookup → Wazuh alert → SOAR escalates if vuln still open in dashboard.

### Project 3 — SOAR Automation (Shuffle + FastAPI)
- SOAR playbooks poll `GET /api/vulnerabilities?severity=Critical&status=open` for new findings.
- Workflow: New Critical CVE → SOAR fetches EPSS → If EPSS > 0.5 → Create TheHive case → Slack → Trigger targeted rescan.

### Project 4 — Threat Hunting (Sysmon + KQL)
- Hunting queries target TTPs associated with high-EPSS CVEs.
- Example: New CVE with EPSS ≥ 0.7 → Write Sysmon KQL query targeting the exploit technique → Hunt all assets with that CVE open.

### Project 5 — Zeek NSM
- Zeek beaconing and DGA detection can identify compromised assets.
- Alert correlator queries `GET /api/vulnerabilities?host={ip}` to check if the beaconing host has open CVEs — connecting network anomaly to unpatched vulnerability.

### Project 7 — Malware Analysis Pipeline (YARA + Cuckoo)
- YARA rules from Project 7 often target the same CVEs that have high EPSS scores.
- IOCs from malware analysis can update asset criticality in `assets.json` when a host is involved in an incident.
- Combined vuln + threat TheHive cases link scan findings with malware analysis reports.

### Project 8 — Phishing Simulation
- Phishing campaigns reveal which users click links — those workstations become higher-priority remediation targets.
- Asset criticality for workstations of users who clicked can be elevated in `assets.json`, raising their composite risk score.

---

## 7. The Standout Feature: Business Risk Model

The business risk model is what differentiates this project from standard scanner output. This project adds the executive layer:

> "CVE-2021-3156 (Sudo PrivEsc) is CVSS 7.8.
> On a dev server — composite score 43.1 (Medium).
> On the PII database server — composite score 67.3 (High).
> On an internet-facing web server — composite score 74.8 (High).
> Same CVE. Three different business decisions."


