
# Vulnerability Management API — Documentation v1.0

Base URL: `http://localhost:5000`

---

## Authentication
No authentication required for local lab use.
For production deployments, add a Bearer token header:
`Authorization: Bearer <your_token>`

## Rate Limiting
No rate limiting in local mode.

---

## Endpoints

### GET /api/vulnerabilities
Returns a paginated list of vulnerabilities with optional filters.

**Query Parameters:**

| Parameter | Type   | Description                                  |
|-----------|--------|----------------------------------------------|
| severity  | string | Filter by severity: Critical, High, Medium, Low |
| host      | string | Filter by host IP                            |
| source    | string | Filter by source: openvas, trivy             |
| status    | string | Filter by status: open, in-progress, resolved, accepted |
| limit     | int    | Results per page (default: 50)               |
| offset    | int    | Pagination offset (default: 0)               |

**Example Request:**
```bash
curl "http://localhost:5000/api/vulnerabilities?severity=Critical&status=open&limit=10"
```

**Example Response:**
```json
{
  "total": 3,
  "limit": 10,
  "offset": 0,
  "data": [
    {
      "id": "ov-001",
      "name": "Apache Log4j Remote Code Execution (Log4Shell)",
      "cve": "CVE-2021-44228",
      "cvss_score": 10.0,
      "severity": "Critical",
      "host": "192.168.1.10",
      "port": "8080/tcp",
      "source": "openvas",
      "status": "open",
      "created_at": "2024-06-10T02:15:00Z"
    }
  ]
}
```

**Error Codes:**
- `400` Bad request (invalid filter value)
- `500` Internal server error

---

### GET /api/vulnerabilities/{id}
Returns a single vulnerability with full details.

**Example Request:**
```bash
curl "http://localhost:5000/api/vulnerabilities/ov-001"
```

**Example Response:**
```json
{
  "id": "ov-001",
  "name": "Apache Log4j Remote Code Execution (Log4Shell)",
  "cve": "CVE-2021-44228",
  "cvss_score": 10.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "severity": "Critical",
  "host": "192.168.1.10",
  "hostname": "web-server-01",
  "port": "8080/tcp",
  "description": "Apache Log4j2 JNDI lookup vulnerability...",
  "solution": "Upgrade Apache Log4j2 to version 2.17.1 or later.",
  "references": "[\"https://nvd.nist.gov/vuln/detail/CVE-2021-44228\"]",
  "source": "openvas",
  "status": "open",
  "risk_score": 0,
  "epss_score": 0,
  "created_at": "2024-06-10T02:15:00Z",
  "updated_at": "2024-06-10T02:15:00Z"
}
```

**Error Codes:**
- `404` Vulnerability not found

---

### POST /api/vulnerabilities/{id}/status
Updates the status of a vulnerability.

**Request Body:**
```json
{ "status": "in-progress" }
```

Valid status values: `open`, `in-progress`, `resolved`, `accepted`

**Example Request:**
```bash
curl -X POST "http://localhost:5000/api/vulnerabilities/ov-001/status" \
  -H "Content-Type: application/json" \
  -d '{"status": "in-progress"}'
```

**Example Response:**
```json
{
  "id": "ov-001",
  "status": "in-progress",
  "updated_at": "2024-06-15T10:30:00Z"
}
```

---

### GET /api/stats
Returns aggregated vulnerability statistics.

**Example Request:**
```bash
curl "http://localhost:5000/api/stats"
```

**Example Response:**
```json
{
  "total": 35,
  "open": 28,
  "by_severity": {
    "Critical": 5,
    "High": 9,
    "Medium": 13,
    "Low": 8
  },
  "by_host": [
    { "host": "192.168.1.10", "cnt": 12 },
    { "host": "192.168.1.30", "cnt": 8 }
  ],
  "by_source": {
    "openvas": 20,
    "trivy": 15
  }
}
```

---

### GET /api/risk-scores
Returns vulnerabilities sorted by composite risk score (CVSS + EPSS + business context).

**Query Parameters:**

| Parameter | Type | Description               |
|-----------|------|---------------------------|
| limit     | int  | Number of results (default: 50) |

**Example Request:**
```bash
curl "http://localhost:5000/api/risk-scores?limit=10"
```

**Example Response:**
```json
{
  "total": 10,
  "data": [
    {
      "id": "ov-001",
      "name": "Apache Log4j RCE",
      "cvss_score": 10.0,
      "epss_score": 0.97548,
      "risk_score": 97.5,
      "priority_label": "CRITICAL"
    }
  ]
}
```

---

### GET /api/reports/summary
Returns data for the executive summary report.

**Example Request:**
```bash
curl "http://localhost:5000/api/reports/summary"
```

---

### GET /api/thehive/tickets
Returns TheHive case tickets linked to vulnerabilities.

**Example Request:**
```bash
curl "http://localhost:5000/api/thehive/tickets"
```

---

### GET /api/scans
Returns scan history.

**Example Request:**
```bash
curl "http://localhost:5000/api/scans"
```

---

### GET /api/docs
Returns this API documentation as JSON.

**Example Request:**
```bash
curl "http://localhost:5000/api/docs"
```
