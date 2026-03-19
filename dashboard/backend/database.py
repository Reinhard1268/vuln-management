# File: dashboard/backend/database.py

import json
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path


class Database:
    SCHEMA_VERSION = 1

    def __init__(self, db_path: str = "dashboard/backend/vulndb.sqlite"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_db(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id            TEXT PRIMARY KEY,
                    name          TEXT NOT NULL,
                    cve           TEXT,
                    cvss_score    REAL DEFAULT 0,
                    cvss_vector   TEXT,
                    severity      TEXT NOT NULL,
                    host          TEXT,
                    hostname      TEXT,
                    port          TEXT,
                    description   TEXT,
                    solution      TEXT,
                    references    TEXT,
                    source        TEXT,
                    status        TEXT DEFAULT 'open',
                    risk_score    REAL DEFAULT 0,
                    epss_score    REAL DEFAULT 0,
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id            TEXT PRIMARY KEY,
                    scan_type     TEXT NOT NULL,
                    target        TEXT,
                    status        TEXT,
                    started_at    TEXT,
                    completed_at  TEXT,
                    finding_count INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count    INTEGER DEFAULT 0,
                    medium_count  INTEGER DEFAULT 0,
                    low_count     INTEGER DEFAULT 0,
                    report_path   TEXT
                );

                CREATE TABLE IF NOT EXISTS remediation_tracking (
                    id            TEXT PRIMARY KEY,
                    vuln_id       TEXT NOT NULL REFERENCES vulnerabilities(id),
                    assigned_to   TEXT,
                    status        TEXT DEFAULT 'open',
                    due_date      TEXT,
                    completed_at  TEXT,
                    notes         TEXT,
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS risk_scores (
                    id            TEXT PRIMARY KEY,
                    vuln_id       TEXT NOT NULL REFERENCES vulnerabilities(id),
                    cvss_component  REAL DEFAULT 0,
                    epss_component  REAL DEFAULT 0,
                    business_component REAL DEFAULT 0,
                    composite_score REAL DEFAULT 0,
                    priority_label  TEXT,
                    scored_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS thehive_tickets (
                    id            TEXT PRIMARY KEY,
                    vuln_id       TEXT REFERENCES vulnerabilities(id),
                    case_id       TEXT,
                    case_number   INTEGER,
                    title         TEXT,
                    severity      TEXT,
                    status        TEXT,
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
                CREATE INDEX IF NOT EXISTS idx_vulns_host     ON vulnerabilities(host);
                CREATE INDEX IF NOT EXISTS idx_vulns_status   ON vulnerabilities(status);
                CREATE INDEX IF NOT EXISTS idx_vulns_source   ON vulnerabilities(source);
            """)
            existing = conn.execute("SELECT version FROM schema_version").fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (self.SCHEMA_VERSION, datetime.utcnow().isoformat())
                )

    def _make_id(self, *parts) -> str:
        return hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()[:16]

    # ── Vulnerabilities ────────────────────────────────────────────────────────

    def upsert_vulnerability(self, finding: dict):
        vid = finding.get("id") or self._make_id(
            finding.get("name", ""), finding.get("host", ""), finding.get("port", "")
        )
        now  = datetime.utcnow().isoformat()
        cves = finding.get("cves", [])
        cve  = cves[0] if cves else finding.get("cve", "")
        refs = json.dumps(finding.get("references", []))

        with self._conn() as conn:
            conn.execute("""
                INSERT INTO vulnerabilities
                    (id, name, cve, cvss_score, cvss_vector, severity, host, hostname,
                     port, description, solution, references, source, status,
                     risk_score, epss_score, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    cvss_score  = excluded.cvss_score,
                    severity    = excluded.severity,
                    status      = CASE WHEN vulnerabilities.status = 'resolved'
                                       THEN 'open' ELSE vulnerabilities.status END,
                    updated_at  = excluded.updated_at
            """, (
                vid,
                finding.get("name", ""),
                cve,
                finding.get("cvss_score", 0),
                finding.get("cvss_vector", ""),
                finding.get("severity", "Info"),
                finding.get("host", ""),
                finding.get("hostname", ""),
                finding.get("port", ""),
                finding.get("description", ""),
                finding.get("solution", ""),
                refs,
                finding.get("source", "unknown"),
                "open",
                0,
                0,
                now,
                now,
            ))

    def get_vulnerabilities(self, filters: dict = None, limit: int = 50, offset: int = 0) -> list:
        query  = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
        for k, v in (filters or {}).items():
            query  += f" AND {k} = ?"
            params.append(v)
        query += " ORDER BY cvss_score DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_vulnerability_by_id(self, vuln_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
        return dict(row) if row else None

    def count_vulnerabilities(self, filters: dict = None) -> int:
        query  = "SELECT COUNT(*) FROM vulnerabilities WHERE 1=1"
        params = []
        for k, v in (filters or {}).items():
            query  += f" AND {k} = ?"
            params.append(v)
        with self._conn() as conn:
            return conn.execute(query, params).fetchone()[0]

    def update_vulnerability_status(self, vuln_id: str, status: str):
        with self._conn() as conn:
            conn.execute(
                "UPDATE vulnerabilities SET status = ?, updated_at = ? WHERE id = ?",
                (status, datetime.utcnow().isoformat(), vuln_id)
            )

    # ── Stats ──────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        with self._conn() as conn:
            by_severity = {
                r["severity"]: r["cnt"]
                for r in conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity"
                ).fetchall()
            }
            by_host = [
                dict(r) for r in conn.execute(
                    "SELECT host, COUNT(*) as cnt FROM vulnerabilities "
                    "WHERE status != 'resolved' GROUP BY host ORDER BY cnt DESC LIMIT 10"
                ).fetchall()
            ]
            by_source = {
                r["source"]: r["cnt"]
                for r in conn.execute(
                    "SELECT source, COUNT(*) as cnt FROM vulnerabilities GROUP BY source"
                ).fetchall()
            }
            total_open = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open'"
            ).fetchone()[0]
            total_all = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

        return {
            "total":       total_all,
            "open":        total_open,
            "by_severity": by_severity,
            "by_host":     by_host,
            "by_source":   by_source,
        }

    # ── Scan History ───────────────────────────────────────────────────────────

    def insert_scan(self, scan: dict):
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scan_history
                    (id, scan_type, target, status, started_at, completed_at,
                     finding_count, critical_count, high_count, medium_count, low_count, report_path)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                scan.get("id", self._make_id(scan.get("scan_type", ""), scan.get("started_at", ""))),
                scan.get("scan_type", ""),
                scan.get("target", ""),
                scan.get("status", ""),
                scan.get("started_at", ""),
                scan.get("completed_at", ""),
                scan.get("finding_count", 0),
                scan.get("critical_count", 0),
                scan.get("high_count", 0),
                scan.get("medium_count", 0),
                scan.get("low_count", 0),
                scan.get("report_path", ""),
            ))

    def get_scan_history(self) -> list:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM scan_history ORDER BY started_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ── TheHive ────────────────────────────────────────────────────────────────

    def insert_thehive_ticket(self, ticket: dict):
        with self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO thehive_tickets
                    (id, vuln_id, case_id, case_number, title, severity, status, created_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                ticket.get("id", self._make_id(ticket.get("vuln_id", ""), ticket.get("case_id", ""))),
                ticket.get("vuln_id", ""),
                ticket.get("case_id", ""),
                ticket.get("case_number", 0),
                ticket.get("title", ""),
                ticket.get("severity", ""),
                ticket.get("status", "New"),
                datetime.utcnow().isoformat(),
            ))

    def get_thehive_tickets(self) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT t.*, v.name as vuln_name, v.host "
                "FROM thehive_tickets t LEFT JOIN vulnerabilities v ON t.vuln_id = v.id "
                "ORDER BY t.created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Seed ───────────────────────────────────────────────────────────────────

    def seed_sample_data(self):
        if self.count_vulnerabilities() > 0:
            return
        sample_files = [
            Path("scanners/scan-results/openvas-sample-results.json"),
            Path("scanners/scan-results/trivy-sample-results.json"),
        ]
        for f in sample_files:
            if f.exists():
                import json
                data = json.loads(f.read_text())
                for finding in data.get("findings", []):
                    self.upsert_vulnerability(finding)
