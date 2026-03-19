# EPSS — Exploit Prediction Scoring System

## What Is EPSS?

EPSS (Exploit Prediction Scoring System) is a data-driven model developed by FIRST.org that estimates the **probability that a CVE will be exploited in the wild within the next 30 days**. It is expressed as a value between 0 and 1 (i.e., 0% to 100% probability).

EPSS is updated daily and is freely available at: `https://api.first.org/data/v1/epss`

---

## EPSS vs CVSS — Key Differences

| Dimension      | CVSS                                     | EPSS                                          |
|----------------|------------------------------------------|-----------------------------------------------|
| Measures       | Theoretical severity of a vulnerability  | Real-world exploitation probability            |
| Updates        | Set at disclosure, rarely changes        | Updated daily based on observed threat data   |
| Scale          | 0–10                                     | 0–1 (probability)                             |
| Source         | NVD analysts                             | Observed exploitation, threat intel feeds     |
| Best use       | Understanding impact IF exploited        | Prioritising WHICH vulns to fix first          |

---

## How to Interpret EPSS Scores

| EPSS Score     | Meaning                                                     |
|----------------|-------------------------------------------------------------|
| 0.90 – 1.00    | Being actively exploited; fix within hours                 |
| 0.50 – 0.89    | Very high exploitation risk; fix within 24 hours           |
| 0.10 – 0.49    | Elevated risk; fix within standard SLA for severity        |
| 0.01 – 0.09    | Some risk; monitor and fix per policy                      |
| 0.00 – 0.009   | Low exploitation risk; deprioritise vs higher EPSS vulns   |

---

## The CVSS Trap — Why EPSS Changes the Game

Consider these two real vulnerabilities:

**Scenario A:**
- CVE-2021-44228 (Log4Shell): CVSS 10.0 | EPSS 0.975
- Both CVSS and EPSS say: fix immediately. Easy decision.

**Scenario B:**
- CVE-X: CVSS 9.5 | EPSS 0.003
- CVE-Y: CVSS 5.5 | EPSS 0.780

Using CVSS alone, you would fix CVE-X first. Using EPSS, you should fix CVE-Y first — it has a 78% chance of being exploited in the next 30 days vs. a 0.3% chance for CVE-X.

**Studies show that over 80% of CVSS Critical/High vulnerabilities are never exploited in the wild.** EPSS lets you cut through the noise.

---

## How This Project Uses EPSS

The composite risk score in this project combines:
```
Composite Score = CVSS Component (0-40)
               + EPSS Component  (0-35)
               + Business Context (0-25)
               = Total (0-100)
```

The EPSS component contributes up to 35 points — the second largest weight after CVSS. This intentionally reflects the value of exploitation likelihood over raw severity.

### Example Scoring:

| CVE               | CVSS | EPSS  | CVSS pts | EPSS pts | Biz pts | Total |
|-------------------|------|-------|----------|----------|---------|-------|
| CVE-2021-44228    | 10.0 | 0.975 | 40       | 34.1     | 22.5    | 96.6  |
| CVE-2022-99999    | 9.8  | 0.003 | 39.2     | 0.1      | 12.5    | 51.8  |
| CVE-2023-44487    | 7.5  | 0.750 | 30       | 26.3     | 17.5    | 73.8  |

CVE-2022-99999 scores only 51.8 despite a near-perfect CVSS — because nobody is exploiting it. CVE-2023-44487 (HTTP/2 Rapid Reset) scores 73.8 because it was being actively exploited at scale.

---

## Practical Prioritisation Decision Tree
```
CVE discovered
     │
     ├── EPSS ≥ 0.50? ──→ Fix immediately (regardless of CVSS)
     │
     ├── CVSS ≥ 9.0 AND EPSS ≥ 0.10? ──→ Fix within 24 hours
     │
     ├── CVSS ≥ 7.0 AND EPSS ≥ 0.05? ──→ Fix within 72 hours
     │
     ├── CVSS ≥ 4.0 OR EPSS ≥ 0.01? ──→ Fix within 30 days
     │
     └── All others ──→ Log and review quarterly
```

---

## Integration with Projects 1–8

- **Project 1 (HomeSOC):** Wazuh alerts can surface CVEs from active exploit attempts, feeding EPSS context into triage.
- **Project 3 (SOAR):** EPSS scores are fetched automatically during alert enrichment playbooks.
- **Project 7 (Malware Analysis):** YARA rules derived from active exploits correlate with high-EPSS CVEs.
