# Critical Vulnerability Response Playbook

**Applies to:** CVSS ≥ 9.0 OR Composite Risk Score ≥ 80  
**SLA:** 24 hours from detection to patch verified  
**Owner:** Reinhard (Security Analyst)

---

## Phase 1 — Immediate Notification (0–15 minutes)

**Trigger:** Critical vulnerability detected by OpenVAS or Trivy, or TheHive case auto-opened.

1. Confirm the alert is not a false positive:
   - Cross-reference CVE in NVD: `https://nvd.nist.gov/vuln/detail/{CVE}`
   - Check EPSS score:
```bash
     python3 prioritization/epss-scores/epss_fetcher.py --cves {CVE}
```
   - Verify host exists in asset inventory: `prioritization/business-risk-model/assets.json`

2. Check if a public exploit exists:
   - Exploit-DB: `https://www.exploit-db.com/search?cve={CVE}`
   - Metasploit: `msfconsole -q -x "search {CVE}; exit"`

3. Notify asset owner immediately via Slack or email.

4. Open or update TheHive case if not auto-created:
```bash
   python3 thehive-integration/auto-create-scripts/thehive-ticket-creator.py \
       --findings scanners/scan-results/latest.json \
       --severity-threshold critical
```

**Decision gate:** If exploit is publicly available AND asset is internet-facing → skip to Phase 3 immediately.

---

## Phase 2 — Risk Assessment (15–60 minutes)

1. Identify all affected hosts:
```bash
   grep -l "{CVE}" scanners/scan-results/*.json
```

2. Assess blast radius:
   - What data could be exfiltrated?
   - What lateral movement paths exist?
   - Is the asset internet-facing or isolated?

3. Check asset criticality and composite score in dashboard:
```bash
   curl "http://localhost:5000/api/vulnerabilities?severity=Critical&status=open"
```

4. Apply interim mitigation if patch will take > 4 hours:
   - Firewall rule to block exploitable port
   - WAF rule if web-facing
   - Disable vulnerable service (if non-critical to operations)
   - Document interim control in TheHive case.

---

## Phase 3 — Patch Identification and Testing (1–4 hours)

1. Identify the correct patch from the `solution` field in scan results.

2. Test patch in dev environment first:
```bash
   # On dev-server
   sudo bash remediation/scripts/linux-remediate.sh --cve {CVE}
```

3. Validate service still functions after patch (minimum 30 minutes observation).

4. Document patch version and test result in TheHive task #2.

---

## Phase 4 — Emergency Patching (4–20 hours)

### Linux System Patch
```bash
sudo bash remediation/scripts/linux-remediate.sh --cve {CVE}
```

### Docker Container Patch
```bash
sudo bash remediation/scripts/docker-remediate.sh \
    --container {container_name} \
    --cve {CVE}
```

### Manual Patch Steps (if script does not cover the CVE)
```bash
# 1. Backup config
cp -r /etc/{service}/ /tmp/backup-pre-patch-$(date +%Y%m%d)/

# 2. Apply patch
apt-get update && apt-get install --only-upgrade {package}

# 3. Confirm version
dpkg -l {package}

# 4. Restart service
systemctl restart {service}

# 5. Confirm healthy
systemctl status {service}
```

---

## Phase 5 — Validation (20–24 hours)

1. Re-run targeted OpenVAS scan:
```bash
   python3 scanners/openvas-config/run-openvas-scan.py \
       --target {host_ip} \
       --scan-config quick \
       --output-dir scanners/scan-results/
```

2. Re-run Trivy for containers:
```bash
   trivy image --severity CRITICAL,HIGH {image_name}
```

3. Confirm CVE no longer appears in output.

4. If CVE is still present — patch was not applied correctly. Re-escalate and retry Phase 4.

5. Run remediation-checker to generate progress report:
```bash
   python3 remediation/scripts/remediation-checker.py \
       --previous scanners/scan-results/{old_scan}.json \
       --current  scanners/scan-results/{new_scan}.json
```

---

## Phase 6 — Rollback Procedure

If the patch causes service disruption:

### Linux Rollback
```bash
# Identify previous version from audit log
cat remediation/tracking/linux-remediation-*.log | grep "Version before"

# Downgrade
apt-get install {package}={previous_version}
systemctl restart {service}
```

### Docker Rollback
```bash
# Stop broken container
docker stop {container_name} && docker rm {container_name}

# Restart from previous image ID (from audit log)
docker run -d --name {container_name} {restart_flags} {previous_image_id}
```

All rollback actions must be logged in `remediation/tracking/` and recorded in TheHive.

---

## Phase 7 — Documentation and Closure (within 24h SLA)

1. Update vulnerability status in dashboard to `resolved`:
```bash
   curl -X POST "http://localhost:5000/api/vulnerabilities/{id}/status" \
       -H "Content-Type: application/json" \
       -d '{"status": "resolved"}'
```

2. Mark all TheHive tasks complete.

3. Write incident timeline in TheHive description:
   - Detection time
   - Notification time
   - Interim mitigation time (if applied)
   - Patch applied time
   - Validation time
   - Total elapsed (must be ≤ 24h for SLA compliance)

4. Update `remediation/tracking/remediation-tracker.json` with `patched_at` and `sla_met` fields.

---

## Phase 8 — Post-Patch Monitoring (24–72 hours)

- Monitor Wazuh dashboard for exploitation attempts against previously-vulnerable host.
- Check Kibana for unusual traffic patterns to the patched host.
- Schedule follow-up OpenVAS scan at 72-hour mark to confirm no regression.
- If EPSS score for this CVE was > 0.50: run a Sysmon-based threat hunt (Project 4) to confirm no prior compromise occurred before patching.
