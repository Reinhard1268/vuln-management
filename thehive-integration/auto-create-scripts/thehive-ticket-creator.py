# thehive-ticket-creator.py

import argparse
import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()
console = Console()

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_KEY = os.getenv("THEHIVE_API_KEY", "")
TRACKING_DIR = Path("remediation/tracking")

SEV_MAP = {
    "Critical": {"severity": 4, "sla_hours": 24},
    "High":     {"severity": 3, "sla_hours": 72},
    "Medium":   {"severity": 2, "sla_hours": 720},
    "Low":      {"severity": 1, "sla_hours": 2160},
}

THRESHOLD_ORDER = ["Critical", "High", "Medium", "Low"]


def parse_args():
    p = argparse.ArgumentParser(description="Create TheHive tickets from vulnerability findings")
    p.add_argument("--findings",           required=True, help="JSON file with findings")
    p.add_argument("--severity-threshold", default="high",
                   choices=["critical", "high", "medium", "low"])
    p.add_argument("--dry-run",            action="store_true")
    return p.parse_args()


def get_headers():
    return {
        "Authorization": f"Bearer {THEHIVE_KEY}",
        "Content-Type":  "application/json",
    }


def make_dedup_hash(cve: str, host: str) -> str:
    return hashlib.md5(f"{cve}|{host}".encode()).hexdigest()[:12]


def load_existing_hashes() -> set:
    mapping_file = TRACKING_DIR / "ticket-mapping.json"
    if mapping_file.exists():
        try:
            data = json.loads(mapping_file.read_text())
            return set(data.get("hashes", []))
        except Exception:
            return set()
    return set()


def save_hash(dedup_hash: str, case_id: str, ticket_info: dict):
    TRACKING_DIR.mkdir(parents=True, exist_ok=True)
    mapping_file = TRACKING_DIR / "ticket-mapping.json"
    try:
        existing = json.loads(mapping_file.read_text()) if mapping_file.exists() else {"hashes": [], "tickets": {}}
    except Exception:
        existing = {"hashes": [], "tickets": {}}

    if dedup_hash not in existing["hashes"]:
        existing["hashes"].append(dedup_hash)
    existing["tickets"][dedup_hash] = {
        "case_id":    case_id,
        "created_at": datetime.utcnow().isoformat(),
        **ticket_info,
    }
    mapping_file.write_text(json.dumps(existing, indent=2))


def sla_deadline(sla_hours: int) -> str:
    deadline = datetime.utcnow() + timedelta(hours=sla_hours)
    return deadline.isoformat()


def build_case_payload(vuln: dict) -> dict:
    cve      = vuln.get("cve") or (vuln.get("cves") or ["N/A"])[0]
    host     = vuln.get("host", "unknown")
    severity = vuln.get("severity", "Medium")
    sev_info = SEV_MAP.get(severity, SEV_MAP["Medium"])
    deadline = sla_deadline(sev_info["sla_hours"])

    title = f"{severity.upper()} Vuln: {cve} on {host}"

    description = (
        f"## {severity} Vulnerability Identified\n\n"
        f"**CVE:** {cve}  \n"
        f"**CVSS Score:** {vuln.get('cvss_score', 'N/A')}  \n"
        f"**EPSS Score:** {vuln.get('epss_score', 'N/A')}  \n"
        f"**Risk Score:** {vuln.get('risk_score', 'N/A')}/100  \n"
        f"**Affected Host:** {host} ({vuln.get('hostname', '')})  \n"
        f"**Affected Port:** {vuln.get('port', 'N/A')}  \n"
        f"**Source Scanner:** {vuln.get('source', 'N/A')}  \n"
        f"**Detected At:** {vuln.get('scanned_at', 'N/A')}  \n\n"
        f"---\n\n"
        f"### Description\n{vuln.get('description', 'N/A')}\n\n"
        f"### Solution\n{vuln.get('solution', 'N/A')}\n\n"
        f"**SLA Deadline:** {deadline}"
    )

    tasks = [
        {"title": "1. Verify vulnerability exists on host",   "flag": False, "order": 0},
        {"title": "2. Apply patch or workaround",             "flag": False, "order": 1},
        {"title": "3. Re-scan to validate fix",               "flag": False, "order": 2},
        {"title": "4. Update dashboard status to resolved",   "flag": False, "order": 3},
    ]

    observables = []
    if host and host != "unknown":
        observables.append({"dataType": "ip",       "data": host,      "message": "Affected host"})
    if cve and cve != "N/A":
        observables.append({"dataType": "other",    "data": cve,       "message": "CVE ID"})
    if vuln.get("hostname"):
        observables.append({"dataType": "hostname", "data": vuln["hostname"], "message": "Hostname"})

    return {
        "title":       title,
        "description": description,
        "severity":    sev_info["severity"],
        "tlp":         2,
        "pap":         2,
        "status":      "New",
        "tags":        ["vulnerability", severity.lower(), vuln.get("source", ""), "vuln-mgmt"],
        "tasks":       tasks,
        "observables": observables,
    }


def create_thehive_case(payload: dict, dry_run: bool) -> str:
    if dry_run:
        console.print(f"  [yellow][DRY RUN][/yellow] Would create: {payload['title']}")
        return "DRY-RUN-ID"

    try:
        resp = requests.post(
            f"{THEHIVE_URL}/api/v1/case",
            headers=get_headers(),
            json=payload,
            timeout=10,
        )
        if resp.status_code in (200, 201):
            case_id = resp.json().get("_id", "")
            console.print(f"  [green]Created:[/green] {payload['title']} — Case ID: {case_id}")
            return case_id
        else:
            console.print(f"  [red]Failed ({resp.status_code}):[/red] {resp.text[:200]}")
            return ""
    except requests.RequestException as e:
        console.print(f"  [red]Connection error:[/red] {e}")
        return ""


def should_include(severity: str, threshold: str) -> bool:
    threshold_cap = threshold.capitalize()
    try:
        t_idx = THRESHOLD_ORDER.index(threshold_cap)
        s_idx = THRESHOLD_ORDER.index(severity)
        return s_idx <= t_idx
    except ValueError:
        return False


def main():
    args     = parse_args()
    findings_path = Path(args.findings)

    if not findings_path.exists():
        console.print(f"[red]File not found: {findings_path}[/red]")
        return

    data     = json.loads(findings_path.read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data
    existing = load_existing_hashes()

    created   = 0
    skipped   = 0
    errors    = 0

    console.rule("[bold cyan]TheHive Ticket Creator")
    console.print(f"  Threshold : {args.severity_threshold.upper()}")
    console.print(f"  Findings  : {len(findings)}")
    console.print(f"  Dry Run   : {args.dry_run}\n")

    for vuln in findings:
        severity = vuln.get("severity", "Low")
        if not should_include(severity, args.severity_threshold):
            continue

        cve  = vuln.get("cve") or (vuln.get("cves") or ["N/A"])[0]
        host = vuln.get("host", "unknown")
        dh   = make_dedup_hash(cve, host)

        if dh in existing:
            console.print(f"  [dim]Skipped (duplicate): {cve} on {host}[/dim]")
            skipped += 1
            continue

        payload = build_case_payload(vuln)
        case_id = create_thehive_case(payload, args.dry_run)

        if case_id and not args.dry_run:
            save_hash(dh, case_id, {"cve": cve, "host": host, "severity": severity})
            existing.add(dh)
            created += 1
        elif case_id and args.dry_run:
            created += 1
        else:
            errors += 1

    table = Table(title="Ticket Creation Summary")
    table.add_column("Result")
    table.add_column("Count", justify="right")
    table.add_row("[green]Created[/green]", str(created))
    table.add_row("[yellow]Skipped (duplicate)[/yellow]", str(skipped))
    table.add_row("[red]Errors[/red]",   str(errors))
    console.print(table)


if __name__ == "__main__":
    main()
