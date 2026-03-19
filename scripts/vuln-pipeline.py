````python
#scripts/vuln-pipeline.py

import argparse
import json
import smtplib
import subprocess
import sys
import time
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

import os
import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

load_dotenv()
console = Console()

RESULTS_DIR   = Path("scanners/scan-results")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASSWORD", "")
DB_PATH       = os.getenv("DATABASE_PATH", "dashboard/backend/vulndb.sqlite")


def parse_args():
    p = argparse.ArgumentParser(description="Vulnerability Management Pipeline")
    p.add_argument("--scan-type", choices=["openvas","trivy","both"], default="both")
    p.add_argument("--target",    default="192.168.1.0/24")
    p.add_argument("--mode",      choices=["quick","full"], default="full")
    return p.parse_args()


def step(title: str):
    console.rule(f"[bold cyan]{title}")


def run_step(name: str, cmd: list) -> tuple:
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = round(time.time() - start, 1)
    success = result.returncode in (0, 1)
    return success, elapsed, result.stdout, result.stderr


def run_openvas(target: str, mode: str) -> Path | None:
    step("Step 1 — OpenVAS Scan")
    cmd = [
        "python3", "scanners/openvas-config/run-openvas-scan.py",
        "--target", target,
        "--scan-config", mode,
        "--output-dir", str(RESULTS_DIR),
    ]
    ok, elapsed, stdout, stderr = run_step("OpenVAS", cmd)
    if ok:
        console.print(f"[green]✓ OpenVAS scan complete ({elapsed}s)[/green]")
        latest = sorted(RESULTS_DIR.glob("openvas-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        return latest[0] if latest else None
    else:
        console.print(f"[yellow]⚠ OpenVAS scan failed or unavailable — using sample data[/yellow]")
        sample = RESULTS_DIR / "openvas-sample-results.json"
        return sample if sample.exists() else None


def run_trivy() -> Path | None:
    step("Step 1b — Trivy Scan")
    cmd = ["python3", "scanners/trivy-config/trivy-scan.py", "--all-lab",
           "--output", str(RESULTS_DIR)]
    ok, elapsed, stdout, stderr = run_step("Trivy", cmd)
    if ok:
        console.print(f"[green]✓ Trivy scan complete ({elapsed}s)[/green]")
        latest = sorted(RESULTS_DIR.glob("trivy-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        return latest[0] if latest else None
    else:
        console.print(f"[yellow]⚠ Trivy scan failed — using sample data[/yellow]")
        sample = RESULTS_DIR / "trivy-sample-results.json"
        return sample if sample.exists() else None


def parse_results(results_file: Path) -> list:
    step("Step 2 — Parse Results")
    data     = json.loads(results_file.read_text())
    findings = data.get("findings", [])
    console.print(f"[green]✓ Parsed {len(findings)} findings from {results_file.name}[/green]")
    return findings


def fetch_epss(findings: list) -> list:
    step("Step 3 — Fetch EPSS Scores")
    cves = list({
        (f.get("cve") or (f.get("cves") or [""])[0])
        for f in findings
        if (f.get("cve") or (f.get("cves") or [""])[0]).startswith("CVE-")
    })
    console.print(f"  Fetching EPSS for {len(cves)} unique CVEs...")
    try:
        import sys; sys.path.insert(0, "dashboard/backend")
        from risk_scorer import RiskScorer
        scorer = RiskScorer()
        epss   = scorer.bulk_epss(cves)
        for f in findings:
            cve = f.get("cve") or (f.get("cves") or [""])[0]
            f["epss_score"] = epss.get(cve, 0.0)
        console.print(f"[green]✓ EPSS scores fetched[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠ EPSS fetch warning: {e}[/yellow]")
    return findings


def score_findings(findings: list) -> list:
    step("Step 4 — Calculate Composite Risk Scores")
    try:
        import sys; sys.path.insert(0, "dashboard/backend")
        from risk_scorer import RiskScorer
        scorer = RiskScorer()
        scored = scorer.batch_score(findings)
        console.print(f"[green]✓ Scored {len(scored)} findings[/green]")
        return scored
    except Exception as e:
        console.print(f"[yellow]⚠ Scoring warning: {e}[/yellow]")
        return findings


def update_dashboard(findings: list):
    step("Step 5 — Update Dashboard Database")
    try:
        import sys; sys.path.insert(0, "dashboard/backend")
        from database import Database
        db = Database(DB_PATH)
        db.init_db()
        for f in findings:
            db.upsert_vulnerability(f)
        console.print(f"[green]✓ Dashboard updated with {len(findings)} findings[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠ Dashboard update warning: {e}[/yellow]")


def create_tickets(results_file: Path):
    step("Step 6 — Create TheHive Tickets")
    cmd = [
        "python3", "thehive-integration/auto-create-scripts/thehive-ticket-creator.py",
        "--findings", str(results_file),
        "--severity-threshold", "high",
    ]
    ok, elapsed, _, stderr = run_step("TheHive", cmd)
    if ok:
        console.print(f"[green]✓ TheHive tickets processed ({elapsed}s)[/green]")
    else:
        console.print(f"[yellow]⚠ TheHive ticket creation warning (non-fatal)[/yellow]")


def generate_weekly_report():
    if datetime.utcnow().weekday() == 6:  # Sunday
        step("Step 7 — Generate Weekly Report")
        cmd = ["python3", "scripts/generate-report.py", "--type", "weekly", "--format", "markdown"]
        ok, elapsed, _, _ = run_step("Weekly Report", cmd)
        if ok:
            console.print(f"[green]✓ Weekly report generated[/green]")
    else:
        console.print("[dim]Step 7 — Skipped (weekly report runs on Sunday)[/dim]")


def send_slack_summary(findings: list, scan_type: str):
    step("Step 8 — Send Slack Summary")
    if not SLACK_WEBHOOK:
        console.print("[dim]Slack webhook not configured — skipping[/dim]")
        return
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1
    msg = {
        "text": (
            f":shield: *Vuln Pipeline Complete* — `{scan_type}`\n"
            f"*Critical:* {counts['Critical']}  *High:* {counts['High']}  "
            f"*Medium:* {counts['Medium']}  *Low:* {counts['Low']}\n"
            f"Dashboard: http://localhost:5000"
        )
    }
    try:
        requests.post(SLACK_WEBHOOK, json=msg, timeout=5)
        console.print("[green]✓ Slack notification sent[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠ Slack notification failed: {e}[/yellow]")


def print_final_summary(all_findings: list, timings: dict):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        sev = f.get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1

    table = Table(title="Pipeline Complete — Final Summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Total findings",        str(len(all_findings)))
    table.add_row("[red]Critical[/red]",   str(counts["Critical"]))
    table.add_row("[orange3]High[/orange3]", str(counts["High"]))
    table.add_row("[yellow]Medium[/yellow]", str(counts["Medium"]))
    table.add_row("[blue]Low[/blue]",      str(counts["Low"]))
    for step_name, elapsed in timings.items():
        table.add_row(f"  {step_name}", f"{elapsed}s")
    console.print(table)


def main():
    args = parse_args()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    console.rule("[bold cyan]Vulnerability Management Pipeline")
    console.print(f"  Scan type : {args.scan_type}")
    console.print(f"  Target    : {args.target}")
    console.print(f"  Mode      : {args.mode}")
    console.print(f"  Started   : {datetime.utcnow().isoformat()}\n")

    all_findings = []
    timings      = {}
    result_files = []

    t0 = time.time()

    if args.scan_type in ("openvas", "both"):
        f = run_openvas(args.target, args.scan_config if hasattr(args,"scan_config") else args.mode)
        if f: result_files.append(f)
        timings["OpenVAS scan"] = round(time.time() - t0, 1)

    t1 = time.time()
    if args.scan_type in ("trivy", "both"):
        f = run_trivy()
        if f: result_files.append(f)
        timings["Trivy scan"] = round(time.time() - t1, 1)

    for rf in result_files:
        t2 = time.time()
        findings  = parse_results(rf)
        findings  = fetch_epss(findings)
        findings  = score_findings(findings)
        all_findings.extend(findings)
        timings[f"Process {rf.name}"] = round(time.time() - t2, 1)

    if all_findings:
        update_dashboard(all_findings)
        for rf in result_files:
            create_tickets(rf)

    generate_weekly_report()
    send_slack_summary(all_findings, args.scan_type)

    print_final_summary(all_findings, timings)


if __name__ == "__main__":
    main()

