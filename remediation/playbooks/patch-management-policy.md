````markdown
# File: remediation/playbooks/patch-management-policy.md

# Patch Management Policy — Lab Environment

**Author:** Reinhard  
**Version:** 2.0  
**Last Updated:** March 2026

---

## 1. Purpose

This policy defines how vulnerabilities discovered through automated scanning (OpenVAS, Trivy) are tracked, prioritised, and remediated in the lab environment. It demonstrates a professional patch management programme consistent with industry standards (NIST SP 800-40, CIS Controls).

---

## 2. SLA Targets by Severity

| Severity | CVSS Range | Composite Score | Patch SLA       | Escalation If Missed     |
|----------|------------|-----------------|-----------------|--------------------------|
| Critical | 9.0–10.0   | 80–100          | 24 hours        | Immediate escalation     |
| High     | 7.0–8.9    | 60–79           | 72 hours        | Manager notification     |
| Medium   | 4.0–6.9    | 40–59           | 30 days         | Weekly review flagged    |
| Low      | 0.1–3.9    | 0–39            | 90 days         | Monthly review           |
| Info     | 0.0        | —               | Best effort     | No escalation            |

**EPSS Override:** Any vulnerability with EPSS ≥ 0.50 is treated as Critical regardless of CVSS score, due to active exploitation risk.

---

## 3. Patching Windows

| System Type      | Patching Window                    | Notes                                  |
|------------------|------------------------------------|----------------------------------------|
| Internet-facing  | Immediately (no change window)     | Security overrides availability        |
| Production       | Tuesday/Thursday 02:00–04:00 UTC   | Minimise business disruption           |
| Docker containers | Daily 03:00–05:00 UTC              | Automated via scheduler.py             |
| Dev/test systems | Any time                           | No change window required              |

---

## 4. Testing Requirements

### Before Patching Production Systems

1. **Dev test first:** Apply patch to dev-server and verify functionality (minimum 30 minutes observation).
2. **Rollback plan documented** before any production change.
3. **Backup configs** (automated via linux-remediate.sh).
4. **Verify patch version** matches vendor advisory.

### After Patching

1. Re-scan with Trivy or OpenVAS within 2 hours.
2. Confirm CVE no longer appears in results.
3. Monitor service health for 24 hours.

---

## 5. Exception Process

If a patch cannot be applied within SLA (e.g., patch unavailable, compatibility issue, operational risk):

1. Implement compensating control (WAF rule, firewall rule, service disable).
2. Document exception in TheHive case:
   - Reason for exception
   - Compensating control applied
   - Risk accepted by: (asset owner)
   - Review date: (no more than 30 days out)
3. Mark vulnerability status as `accepted` in dashboard with justification note.
4. Review exception at next monthly review.

---

## 6. Metrics and Reporting

### Weekly Metrics (every Monday)

- New vulnerabilities this week
- Patched this week
- SLA compliance rate
- Outstanding overdue items

### Monthly Metrics (first Monday of month)

- Mean Time to Remediate (MTTR) by severity
- SLA compliance trend (3-month)
- Vulnerability inventory trend
- Top 5 persistent vulnerabilities (not yet patched)

### Report Generation
```bash
# Weekly report
python3 scripts/generate-report.py --type weekly --format both

# Monthly report
python3 scripts/generate-report.py --type monthly --format both
```

---

## 7. Roles and Responsibilities

| Role              | Responsibility                                              |
|-------------------|-------------------------------------------------------------|
| Security Analyst  | Run scans, triage findings, create TheHive tickets          |
| Asset Owner       | Approve and apply patches, report exceptions               |
| SOC Lead          | Review weekly reports, approve exceptions > 7 days         |

In this lab environment, I literally fill all three roles.
