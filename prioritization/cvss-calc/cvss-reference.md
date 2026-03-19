# cvss-reference.md

# CVSS v3.1 Quick Reference Guide

## Score Ranges and Severity Labels

| Score Range | Severity | Colour  | Recommended SLA       |
|-------------|----------|---------|-----------------------|
| 0.0         | None     | Grey    | No action required    |
| 0.1 – 3.9  | Low      | Blue    | 90 days               |
| 4.0 – 6.9  | Medium   | Yellow  | 30 days               |
| 7.0 – 8.9  | High     | Orange  | 72 hours              |
| 9.0 – 10.0 | Critical | Red     | 24 hours              |

---

## How to Read a CVSS Vector String

Format: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

Each segment is `MetricCode:Value`. The prefix `CVSS:3.1` is optional in calculations.

---

## Base Metrics (Required)

### Attack Vector (AV)
How the vulnerability is exploited from a network perspective.

| Value | Label         | Weight | Meaning                                          |
|-------|---------------|--------|--------------------------------------------------|
| N     | Network       | 0.85   | Exploitable remotely without physical access     |
| A     | Adjacent      | 0.62   | Requires local network access (LAN/Bluetooth)   |
| L     | Local         | 0.55   | Requires local system access (login/terminal)   |
| P     | Physical      | 0.20   | Requires physical access to the device           |

### Attack Complexity (AC)
Conditions beyond attacker control required for exploitation.

| Value | Label | Weight | Meaning                                         |
|-------|-------|--------|-------------------------------------------------|
| L     | Low   | 0.77   | No special conditions; reliably exploitable     |
| H     | High  | 0.44   | Requires specific conditions or timing          |

### Privileges Required (PR)
Level of privileges the attacker must have before exploiting.

| Value | Label  | Weight (Unchanged) | Weight (Changed) |
|-------|--------|--------------------|-----------------|
| N     | None   | 0.85               | 0.85            |
| L     | Low    | 0.62               | 0.68            |
| H     | High   | 0.27               | 0.50            |

### User Interaction (UI)
Whether exploitation requires action from a user other than the attacker.

| Value | Label     | Weight | Meaning                                      |
|-------|-----------|--------|----------------------------------------------|
| N     | None      | 0.85   | No user interaction required                 |
| R     | Required  | 0.62   | A user must take a specific action           |

### Scope (S)
Whether a vulnerability in one component impacts resources beyond its security scope.

| Value | Label     | Meaning                                                   |
|-------|-----------|-----------------------------------------------------------|
| U     | Unchanged | Exploited component and impacted component are the same   |
| C     | Changed   | Exploit can affect other components (e.g., hypervisor)   |

### Confidentiality Impact (C), Integrity Impact (I), Availability Impact (A)

| Value | Label  | Weight | Meaning                                         |
|-------|--------|--------|-------------------------------------------------|
| N     | None   | 0.00   | No impact on this property                      |
| L     | Low    | 0.22   | Limited disclosure, modification, or disruption |
| H     | High   | 0.56   | Total loss of confidentiality/integrity/availability |

---

## Temporal Metrics (Optional)

### Exploit Code Maturity (E)
| Value | Meaning                                      |
|-------|----------------------------------------------|
| X     | Not defined (ignored)                        |
| U     | Unproven — theoretical only                  |
| P     | Proof-of-concept code available              |
| F     | Functional exploit publicly available        |
| H     | High — automated exploitation kits exist     |

### Remediation Level (RL)
| Value | Meaning                                          |
|-------|--------------------------------------------------|
| X     | Not defined                                      |
| O     | Official fix available from vendor               |
| T     | Temporary fix or workaround available            |
| W     | Workaround suggested (no official fix)           |
| U     | Unavailable — no fix or workaround               |

### Report Confidence (RC)
| Value | Meaning                                          |
|-------|--------------------------------------------------|
| X     | Not defined                                      |
| U     | Unknown — unconfirmed reports                    |
| R     | Reasonable — multiple independent sources        |
| C     | Confirmed — vendor or author acknowledges it     |

---

## Common Vulnerability Score Examples

| Vulnerability           | Vector                                    | Score | Severity |
|-------------------------|-------------------------------------------|-------|----------|
| Log4Shell (RCE)         | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H      | 10.0  | Critical |
| EternalBlue (SMB RCE)   | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H      | 9.8   | Critical |
| Heartbleed              | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N      | 7.5   | High     |
| Sudo PrivEsc            | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H      | 7.8   | High     |
| XSS (reflected)         | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N      | 6.1   | Medium   |
| SSRF (internal only)    | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N      | 4.3   | Medium   |
| Info disclosure (HTTP)  | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N      | 3.7   | Low      |

---

## Quick Score Formula

**ISS (Impact Sub-Score):**
```
ISS = 1 − (1−C) × (1−I) × (1−A)
```

**Scope Unchanged:**
```
Impact        = 6.42 × ISS
Exploitability = 8.22 × AV × AC × PR × UI
Base Score    = Roundup(min(Impact + Exploitability, 10))
```

**Scope Changed:**
```
Impact        = 7.52×(ISS−0.029) − 3.25×(ISS−0.02)^15
Base Score    = Roundup(min(1.08×(Impact + Exploitability), 10))
```
