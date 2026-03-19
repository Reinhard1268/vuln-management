# Vulnerability Management Automation Dashboard

**Portfolio Project 9 of 10 | Reinhard | github.com/Reinhard1268**  
**Certification:** EC-Council CCT  
**Role:** Junior Security Analyst / Junior Penetration Tester  
**Platform:** Kali Linux · Docker  
**Integrates with:** Projects 01–08 (HomeSOC, Detection Engineering, SOAR, Threat Hunting, Zeek NSM, Cloud SOC, Malware Analysis, Phishing Simulation)

---

## What This Project Does

This project builds a **full vulnerability management programme** from scratch — automated scanning, intelligent prioritisation, remediation tracking, TheHive integration, and executive reporting — all running locally on Kali Linux.

The standout feature is the **composite risk scoring engine** that combines CVSS, EPSS (real-world exploitation probability), and business context into a single 0–100 priority score. This moves beyond raw scanner output and into the kind of risk-based decision making that employers expect from security analysts.

---

## Architecture
```
┌──────────────────────────────────────────────────────────────────┐
│                    Vulnerability Management Platform              │
│                                                                    │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────┐  │
│  │  SCANNERS   │    │  PRIORITISATION  │    │   DASHBOARD    │  │
│  │             │    │                  │    │                │  │
│  │  OpenVAS    │───▶│  CVSS (0-40 pts) │───▶│  Flask API     │  │
│  │  (network)  │    │  EPSS (0-35 pts) │    │  SQLite DB     │  │
│  │             │    │  Biz  (0-25 pts) │    │  HTML Frontend │  │
│  │  Trivy      │───▶│  = Score /100    │    │  Charts.js     │  │
│  │  (containers│    │                  │    │                │  │
│  └─────────────┘    └──────────────────┘    └────────────────┘  │
│          │                   │                       │            │
│          ▼                   ▼                       ▼            │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────┐  │
│  │ scan-results│    │  TheHive Cases   │    │    REPORTS     │  │
│  │  JSON/XML   │    │  auto-created    │    │  Weekly PDF    │  │
│  │  (raw data) │    │  Critical + High │    │  Monthly PDF   │  │
│  └─────────────┘    └──────────────────┘    │  Executive MD  │  │
│                                              └────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure
```
09-vuln-management/
├── scanners/
│   ├── openvas-config/        # OpenVAS setup, scan runner, result parser
│   ├── trivy-config/          # Trivy setup and container scanner
│   └── scan-results/          # JSON scan output + sample data
├── dashboard/
│   ├── backend/               # Flask API, SQLite DB, risk scorer, scheduler
│   ├── frontend/              # HTML dashboard, CSS, Chart.js
│   └── api/                   # API documentation
├── prioritization/
│   ├── epss-scores/           # EPSS fetcher with caching
│   ├── cvss-calc/             # CVSS v3.1 calculator
│   └── business-risk-model/   # Asset inventory + composite scoring engine
├── thehive-integration/
│   ├── ticket-templates/      # Case templates (Critical/High/Batch)
│   └── auto-create-scripts/   # Deduplication-aware ticket creator
├── remediation/
│   ├── scripts/               # Linux + Docker remediation scripts
│   ├── playbooks/             # Critical vuln playbook + patch policy
│   └── tracking/              # Tracker JSON + SLA report
├── reports/
│   ├── weekly/                # Templates + sample weekly report
│   ├── monthly/               # Templates + sample monthly report
│   └── executive/             # Non-technical executive summary templates
├── scripts/
│   ├── vuln-pipeline.py       # Main orchestration pipeline
│   └── generate-report.py     # PDF + Markdown report generator
└── docs/
    ├── setup-guide.md         # Full setup instructions
    └── methodology.md         # EPSS + CVSS + business risk methodology
```

---

## Quick Start
```bash
# 1. Install dependencies
pip3 install -r requirements.txt --break-system-packages

# 2. Configure environment
cp .env.example .env && nano .env

# 3. Start dashboard (auto-seeds sample data)
python3 dashboard/backend/app.py

# 4. Open dashboard in browser
firefox dashboard/frontend/index.html

# 5. Run full pipeline
python3 scripts/vuln-pipeline.py --scan-type both --target 192.168.1.0/24

# 6. Generate weekly report
python3 scripts/generate-report.py --type weekly --format both
```

Full setup instructions: [`docs/setup-guide.md`](docs/setup-guide.md)

---

## Key Features

### Composite Risk Scoring Engine
The core differentiator. Every vulnerability receives a 0–100 score combining:
- **CVSS** (up to 40 pts) — theoretical severity
- **EPSS** (up to 35 pts) — real-world exploitation probability (FIRST.org, updated daily)
- **Business Context** (up to 25 pts) — asset criticality, exposure, data sensitivity

A CVSS 9.5 on a dev server scores 43. A CVSS 7.5 on an internet-facing PII database scores 79. Same scanner output — completely different business decision.

### Dashboard
- Dark-theme single-page app — no build tools required
- Live stats: Critical / High / Medium / Low counts
- Severity donut, top hosts bar, CVSS vs EPSS scatter chart
- Sortable, filterable vulnerability table with inline status updates
- CSV export
- Auto-refresh every 5 minutes

### Automated Pipeline
```bash
python3 scripts/vuln-pipeline.py --scan-type both
```
1. Run OpenVAS + Trivy
2. Parse and normalise results
3. Fetch EPSS scores (batched, cached)
4. Calculate composite risk scores
5. Update SQLite dashboard database
6. Create TheHive tickets for Critical/High findings
7. Generate weekly report (if Sunday)
8. Send Slack summary

### Remediation Tooling
- `linux-remediate.sh` — CVE-to-package mapping, auto-backup, rollback, audit log
- `docker-remediate.sh` — pull latest image, recreate container, Trivy re-scan
- `remediation-checker.py` — diff two scans, calculate MTTR, SLA compliance, auto-update TheHive tickets

### Reporting
- **Weekly** — new/fixed/open vulns, SLA compliance, top 5 priorities
- **Monthly** — trend analysis, MTTR, remediation velocity
- **Executive** — RAG status, plain-English risk narrative, no CVE numbers

---

## Scoring Model Detail

| Component      | Weight | Source                     | Formula                        |
|----------------|--------|----------------------------|--------------------------------|
| CVSS           | 40 pts | NVD                        | `(cvss / 10) × 40`             |
| EPSS           | 35 pts | FIRST.org API (daily)      | `epss_probability × 35`        |
| Business risk  | 25 pts | assets.json                | `asset_value × 25 × exposure`  |
| **Total**      | **100**|                            |                                |

Priority labels: `CRITICAL ≥ 80` · `HIGH ≥ 60` · `MEDIUM ≥ 40` · `LOW < 40`

---

## SLA Targets

| Severity | SLA      | EPSS Override              |
|----------|----------|----------------------------|
| Critical | 24 hours | EPSS ≥ 0.50 → Critical SLA |
| High     | 72 hours |                            |
| Medium   | 30 days  |                            |
| Low      | 90 days  |                            |

---

## Integration with the Full Portfolio

| Project | Integration Point |
|---------|------------------|
| 01 HomeSOC | TheHive auto-cases · Elastic scan storage · Wazuh exploit detection |
| 02 Detection Engineering | Sigma rules targeting CVEs with EPSS ≥ 0.50 |
| 03 SOAR | Pipeline API polled by Shuffle · auto-remediation triggers |
| 04 Threat Hunting | Sysmon KQL hunts scoped to open high-EPSS CVEs |
| 05 Zeek NSM | Alert correlator queries `/api/vulnerabilities?host={ip}` |
| 07 Malware Analysis | YARA rules correlate with high-EPSS CVEs · IOCs elevate asset criticality |
| 08 Phishing Sim | Click-rate data elevates workstation priority in assets.json |

---

## Tech Stack

| Layer        | Technology                                      |
|--------------|-------------------------------------------------|
| Scanners     | OpenVAS / GVM · Trivy · python-gvm              |
| Backend API  | Flask · Flask-CORS · SQLite                     |
| Risk Scoring | EPSS API (FIRST.org) · CVSS v3.1 · Pandas/NumPy |
| Frontend     | Vanilla HTML/CSS/JS · Chart.js                  |
| Reporting    | ReportLab (PDF) · Matplotlib · Jinja2           |
| Automation   | Schedule · Subprocess · SMTP · Slack Webhooks   |
| Integration  | TheHive 5 REST API · Wazuh · Elasticsearch      |


## Author

**Reinhard**  
EC-Council Trained CCT  
Junior Security Analyst / Junior Penetration Tester  
GitHub: [github.com/Reinhard1268](https://github.com/Reinhard1268)
