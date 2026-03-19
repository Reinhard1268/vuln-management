````markdown
# Security Posture Summary — {{MONTH}} {{YEAR}}

**Prepared for:** Leadership  
**Prepared by:** Security Team  
**Date:** {{REPORT_DATE}}

---

## Overall Security Posture

### Status: {{RAG_STATUS}} — {{RAG_LABEL}}

> {{RAG_SUMMARY}}

*🟢 Green = On track | 🟡 Amber = Needs attention | 🔴 Red = Immediate action required*

---

## Risk Trend
````
{{RISK_SCORE_THIS_MONTH}} / 100  {{RISK_ARROW}} {{RISK_SCORE_LAST_MONTH}} / 100 last month
````

{{RISK_TREND_NARRATIVE}}

---

## Top 3 Risks (Plain English)

### Risk 1: {{RISK_1_TITLE}}
**Severity:** {{RISK_1_SEVERITY}}  
{{RISK_1_DESCRIPTION}}

**What we are doing:** {{RISK_1_ACTION}}  
**Expected resolution:** {{RISK_1_ETA}}

---

### Risk 2: {{RISK_2_TITLE}}
**Severity:** {{RISK_2_SEVERITY}}  
{{RISK_2_DESCRIPTION}}

**What we are doing:** {{RISK_2_ACTION}}  
**Expected resolution:** {{RISK_2_ETA}}

---

### Risk 3: {{RISK_3_TITLE}}
**Severity:** {{RISK_3_SEVERITY}}  
{{RISK_3_DESCRIPTION}}

**What we are doing:** {{RISK_3_ACTION}}  
**Expected resolution:** {{RISK_3_ETA}}

---

## Remediation Progress

| {{METRIC_LABEL_1}} | {{METRIC_LABEL_2}} | {{METRIC_LABEL_3}} |
|--------------------|--------------------|--------------------|
| {{METRIC_VAL_1}}   | {{METRIC_VAL_2}}   | {{METRIC_VAL_3}}   |

{{REMEDIATION_NARRATIVE}}

---

## Actions Requiring Leadership Decision

{{LEADERSHIP_ACTIONS}}

---

*This report is intentionally non-technical. For detailed findings, see the weekly technical report.*
