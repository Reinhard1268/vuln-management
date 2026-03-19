# remediation-checker.py

import argparse
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
SLA = {
    "Critical": 24,
    "High":     72,
    "Medium":   720,
    "Low":      2160,
}


def parse_args():
    p = argparse.ArgumentParser(description="Compare scans and calculate remediation progress")
    p.add_argument("--current",  required=True, help="Current scan JSON results file")
    p.add_argument("--previous", required=True, help="Previous scan JSON results file")
    p.add_argument("--output",   default="",    help="Output report path (auto if omitted)")
    return p.parse_args()


def load_findings(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise SystemExit(1)
    data = json.loads(p.read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data
    return {_key(f): f for f in findings}


def _key(f: dict) -> str:
    cve  = f.get("cve") or (f.get("cves") or [""])[0] or f.get("name", "")
    host = f.get("host", "")
    return f"{cve}|{host}"


def compare(current: dict, previous: dict) -> dict:
    current_keys  = set(current.keys())
    previous_keys = set(previous.keys())

    new_vulns     = {k: current[k]  for k in current_keys  - previous_keys}
    fixed_vulns   = {k: previous[k] for k in previous_keys - current_keys}
    unchanged     = {k: current[k]  for k in current_keys  & previous_keys}

    return {
        "new":       new_vulns,
        "fixed":     fixed_vulns,
        "unchanged": unchanged,
    }


def sla_compliance(findings: dict) -> dict:
    now        = datetime.utcnow()
    compliant  = 0
    overdue    = []

    for key, f in findings.items():
        sev          = f.get("severity", "Low")
        sla_hours    = SLA.get(sev, 2160)
        scanned_at   = f.get("scanned_at") or f.get("created_at", "")
        try:
            detected = datetime.fromisoformat(scanned_at.replace("Z", "+00:00").replace("+00:00", ""))
            deadline = detected + timedelta(hours=sla_hours)
            age_hours = (now - detected).total_seconds() / 3600
            if now <= deadline:
                compliant += 1
            else:
                overdue.append({
                    "key":       key,
                    "severity":  sev,
                    "age_hours": round(age_hours, 1),
                    "sla_hours": sla_hours,
                    "overdue_hours": round(age_hours - sla_hours, 1),
                })
        except Exception:
            compliant += 1

    total = len(findings)
    return {
        "total":      total,
        "compliant":  compliant,
        "overdue":    overdue,
        "percentage": round(compliant / total * 100, 1) if total else 100.0,
    }


def update_thehive_tickets(fixed: dict):
    if not THEHIVE_KEY:
        return
    mapping_file = Path("remediation/tracking/ticket-mapping.json")
    if not mapping_file.exists():
        return

    import hashlib
    mapping = json.loads(mapping_file.read_text())
    tickets = mapping.get("tickets", {})

    for key in fixed:
        parts = key.split("|")
        cve   = parts[0] if parts else ""
        host  = parts[1] if len(parts) > 1 else ""
        dh    = hashlib.md5(f"{cve}|{host}".encode()).hexdigest()[:12]
        ticket_info = tickets.get(dh)
        if ticket_info:
            case_id = ticket_info.get("case_id", "")
            if case_id:
                try:
                    resp = requests.post(
                        f"{THEHIVE_URL}/api/v1/case/{case_id}/status",
                        headers={"Authorization": f"Bearer {THEHIVE_KEY}", "Content-Type": "application/json"},
                        json={"status": "Resolved"},
                        timeout=5,
                    )
                    if resp.status_code in (200, 204):
                        console.print(f"  [green]TheHive case {case_id} marked Resolved[/green]")
                except Exception as e:
                    console.print(f"  [yellow]TheHive update failed for {case_id}: {e}[/yellow]")


def remediation_rate(fixed: int, total_prev: int) -> float:
    if total_prev == 0:
        return 0.0
    return round(fixed / total_prev * 100, 1)


def main():
    args    = parse_args()
    current  = load_findings(args.current)
    previous = load_findings(args.previous)

    diff = compare(current, previous)
    sla  = sla_compliance(diff["unchanged"])

    fixed_count   = len(diff["fixed"])
    new_count     = len(diff["new"])
    total_prev    = len(previous)
    rem_rate      = remediation_rate(fixed_count, total_prev)

    console.rule("[bold cyan]Remediation Progress Report")
    console.print(f"  Previous scan  : {args.previous}")
    console.print(f"  Current scan   : {args.current}")
    console.print(f"  Report time    : {datetime.utcnow().isoformat()}\n")

    summary = Table(title="Summary")
    summary.add_column("Metric")
    summary.add_column("Value", justify="right")
    summary.add_row("Previous finding count",  str(total_prev))
    summary.add_row("Current finding count",   str(len(current)))
    summary.add_row("[green]Fixed / Resolved[/green]",  f"[green]{fixed_count}[/green]")
    summary.add_row("[red]New findings[/red]",           f"[red]{new_count}[/red]")
    summary.add_row("Unchanged",               str(len(diff["unchanged"])))
    summary.add_row("Remediation rate",        f"{rem_rate}%")
    console.print(summary)

    sla_table = Table(title="SLA Compliance (Unchanged Findings)")
    sla_table.add_column("Metric")
    sla_table.add_column("Value", justify="right")
    sla_table.add_row("Total unchanged",    str(sla["total"]))
    sla_table.add_row("[green]Within SLA[/green]", f"[green]{sla['compliant']}[/green]")
    sla_table.add_row("[red]Overdue[/red]",  f"[red]{len(sla['overdue'])}[/red]")
    sla_table.add_row("Compliance %",        f"{sla['percentage']}%")
    console.print(sla_table)

    if sla["overdue"]:
        od = Table(title="Overdue Items")
        od.add_column("CVE | Host")
        od.add_column("Severity")
        od.add_column("SLA (h)", justify="right")
        od.add_column("Overdue By (h)", justify="right")
        for item in sorted(sla["overdue"], key=lambda x: x["overdue_hours"], reverse=True)[:10]:
            od.add_row(item["key"], item["severity"], str(item["sla_hours"]), str(item["overdue_hours"]))
        console.print(od)

    if diff["fixed"]:
        console.print(f"\n[green]Updating TheHive tickets for {fixed_count} resolved findings...[/green]")
        update_thehive_tickets(diff["fixed"])

    report = {
        "generated_at":     datetime.utcnow().isoformat(),
        "previous_file":    args.previous,
        "current_file":     args.current,
        "new_count":        new_count,
        "fixed_count":      fixed_count,
        "unchanged_count":  len(diff["unchanged"]),
        "remediation_rate": rem_rate,
        "sla_compliance":   sla["percentage"],
        "overdue_items":    sla["overdue"],
        "new_findings":     list(diff["new"].values()),
        "fixed_findings":   list(diff["fixed"].values()),
    }

    out = Path(args.output) if args.output else Path("remediation/tracking") / f"remediation-report-{datetime.utcnow().strftime('%Y%m%d-%H%M')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    console.print(f"\n[green]Report saved:[/green] {out}")


if __name__ == "__main__":
    main()
