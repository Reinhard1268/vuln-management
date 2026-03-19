# Setup Guide — vuln-management

**Project:** Vulnerability Management Automation Dashboard  
**Author:** Reinhard (github.com/Reinhard1268)  
**Platform:** Kali Linux, Docker  
**Requires:** Projects 01 (HomeSOC) running — Wazuh, Elastic, TheHive, Shuffle

---

## Prerequisites
```bash
# Verify Python 3.10+
python3 --version

# Verify Docker
docker --version

# Verify your Project 1 stack is running
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
curl -s http://localhost:9000/api/status
```

---

## Step 1 — Clone and Configure
```bash
cd ~/
git clone https://github.com/Reinhard1268/vuln-management.git
cd vuln-management

# Install Python dependencies
pip3 install -r requirements.txt --break-system-packages

# Configure environment
cp .env.example .env
nano .env  # Fill in your credentials
```

Fill in your `.env` file with real values from your Project 1 setup:
- `OPENVAS_PASSWORD` — from `openvas-setup.sh` output
- `ELASTIC_PASSWORD` — from your Project 1 `.env`
- `THEHIVE_API_KEY` — from TheHive → Settings → API Keys
- `SLACK_WEBHOOK_URL` — from your Slack app (optional)

---

## Step 2 — Install OpenVAS on Kali Linux
```bash
# Run as root
sudo bash scanners/openvas-config/openvas-setup.sh
```

This script will:
- Install GVM/OpenVAS via apt
- Run `gvm-setup` (takes 10–20 minutes)
- Create scan targets for your lab network
- Output the admin password and target IDs

After setup:
- **Web UI:** https://localhost:9392
- **Credentials:** admin / Admin@OpenVAS2024!

### Running Your First OpenVAS Scan
```bash
python3 scanners/openvas-config/run-openvas-scan.py \
    --target 192.168.1.0/24 \
    --scan-config full \
    --output-dir scanners/scan-results/
```

Output will be saved to `scanners/scan-results/openvas-*.json`

---

## Step 3 — Install Trivy
```bash
sudo bash scanners/trivy-config/trivy-setup.sh
```

Verify:
```bash
trivy --version
trivy image --help
```

### Scanning Docker Containers with Trivy
```bash
# Scan all Project 1 lab containers
python3 scanners/trivy-config/trivy-scan.py --all-lab

# Scan a specific image
python3 scanners/trivy-config/trivy-scan.py \
    --target wazuh/wazuh-manager:latest \
    --type image
```

---

## Step 4 — Set Up Flask Dashboard

### Install and Initialise
```bash
# Database and sample data are auto-initialised on first run
python3 dashboard/backend/app.py
```

You should see:
```
* Running on http://0.0.0.0:5000
```

### Load Sample Scan Results (No Scanner Required)

The database auto-seeds from:
- `scanners/scan-results/openvas-sample-results.json`
- `scanners/scan-results/trivy-sample-results.json`

### Open the Frontend Dashboard
```bash
xdg-open dashboard/frontend/index.html
# OR
firefox dashboard/frontend/index.html
```

The dashboard fetches from `http://localhost:5000`.

---

## Step 5 — Verify API is Working
```bash
# Stats
curl http://localhost:5000/api/stats | python3 -m json.tool

# Top priority vulnerabilities with risk scores
curl http://localhost:5000/api/risk-scores | python3 -m json.tool

# Vulnerabilities — filter by severity
curl "http://localhost:5000/api/vulnerabilities?severity=Critical"
```

---

## Step 6 — Set Up TheHive Integration

### Get Your TheHive API Key

1. Log in to TheHive at http://localhost:9000
2. Click your username → Settings → API Keys
3. Create new key, copy it to `.env` as `THEHIVE_API_KEY`

### Test Ticket Creation
```bash
# Dry run first — no tickets actually created
python3 thehive-integration/auto-create-scripts/thehive-ticket-creator.py \
    --findings scanners/scan-results/openvas-sample-results.json \
    --severity-threshold high \
    --dry-run

# Create real tickets
python3 thehive-integration/auto-create-scripts/thehive-ticket-creator.py \
    --findings scanners/scan-results/openvas-sample-results.json \
    --severity-threshold high
```

---

## Step 7 — Run Full Pipeline
```bash
# Both scanners, full mode
python3 scripts/vuln-pipeline.py \
    --scan-type both \
    --target 192.168.1.0/24 \
    --mode full

# OpenVAS only, quick scan
python3 scripts/vuln-pipeline.py \
    --scan-type openvas \
    --target 127.0.0.1 \
    --mode quick

# Trivy only (container scan)
python3 scripts/vuln-pipeline.py --scan-type trivy
```

---

## Step 8 — Generate Your First Report
```bash
# Weekly report (markdown + PDF)
python3 scripts/generate-report.py --type weekly --format both

# Monthly report
python3 scripts/generate-report.py --type monthly --format both

# Executive summary
python3 scripts/generate-report.py --type executive --format pdf

# Email report (requires SMTP in .env)
python3 scripts/generate-report.py --type weekly --format pdf --send
```

Reports are saved to:
- `reports/weekly/`
- `reports/monthly/`
- `reports/executive/`

---

## Step 9 — Schedule Automated Scans
```bash
# Start scheduler in background
nohup python3 dashboard/backend/scheduler.py > /tmp/vuln-scheduler.log 2>&1 &
echo "Scheduler PID: $!"

# Or run in a screen session
screen -S vuln-scheduler
python3 dashboard/backend/scheduler.py
# Ctrl+A, D to detach
```

Default schedule (configurable in `.env`):
- OpenVAS: daily at 02:00
- Trivy: daily at 03:00
- Full scan: Sunday at 01:00

---

## Step 10 — EPSS and CVSS Utilities
```bash
# Fetch EPSS scores for specific CVEs
python3 prioritization/epss-scores/epss_fetcher.py \
    --cves CVE-2021-44228 CVE-2023-44487 \
    --output both \
    --threshold 0.1

# Calculate CVSS score from vector string
python3 prioritization/cvss-calc/cvss_calculator.py \
    AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

# Business risk model scoring
python3 -c "
import json, sys
sys.path.insert(0, 'prioritization/business-risk-model')
from business_risk_model import AssetInventory, BusinessRiskCalculator
data = json.loads(open('scanners/scan-results/openvas-sample-results.json').read())
calc = BusinessRiskCalculator()
scored = calc.batch_score(data['findings'])
calc.print_scores(scored)
"
```

---

## Step 11 — Remediation Workflow
```bash
# Patch a Linux package by CVE
sudo bash remediation/scripts/linux-remediate.sh --cve CVE-2021-3156

# Patch a Docker container
sudo bash remediation/scripts/docker-remediate.sh \
    --container elasticsearch \
    --cve CVE-2023-44487

# Compare two scans and calculate remediation progress
python3 remediation/scripts/remediation-checker.py \
    --previous scanners/scan-results/openvas-sample-results.json \
    --current  scanners/scan-results/openvas-latest.json
```

---

## Troubleshooting

### OpenVAS won't start
```bash
sudo gvm-check-setup
sudo systemctl status gvmd ospd-openvas
sudo journalctl -u gvmd -n 50
```

### Trivy database issues
```bash
trivy image --download-db-only
trivy image --reset
```

### Flask API not responding
```bash
ss -tlnp | grep 5000
python3 dashboard/backend/app.py 2>&1 | head -50
```

### TheHive connection refused
```bash
curl http://localhost:9000/api/status
docker ps | grep thehive
docker logs thehive
```

### Database reset (start fresh)
```bash
rm dashboard/backend/vulndb.sqlite
python3 dashboard/backend/app.py  # Re-seeds automatically
