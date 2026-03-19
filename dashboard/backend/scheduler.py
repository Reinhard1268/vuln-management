# scheduler.py

import json
import logging
import os
import smtplib
import subprocess
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

import requests
import schedule
import time
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()
console = Console()
logger  = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASSWORD", "")

SCAN_SCHEDULE_OPENVAS = os.getenv("SCAN_SCHEDULE_OPENVAS", "02:00")
SCAN_SCHEDULE_TRIVY   = os.getenv("SCAN_SCHEDULE_TRIVY",   "03:00")
RESULTS_DIR           = Path("scanners/scan-results")


def run_openvas_scan():
    console.print(f"[cyan][{datetime.utcnow().isoformat()}] Starting scheduled OpenVAS scan...[/cyan]")
    result = subprocess.run(
        ["python3", "scanners/openvas-config/run-openvas-scan.py",
         "--target", "192.168.1.0/24",
         "--scan-config", "full",
         "--output-dir", str(RESULTS_DIR)],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        console.print("[green]OpenVAS scan complete.[/green]")
        _post_scan_pipeline("openvas")
    else:
        logger.error(f"OpenVAS scan failed: {result.stderr[:500]}")


def run_trivy_scan():
    console.print(f"[cyan][{datetime.utcnow().isoformat()}] Starting scheduled Trivy scan...[/cyan]")
    result = subprocess.run(
        ["python3", "scanners/trivy-config/trivy-scan.py", "--all-lab",
         "--output", str(RESULTS_DIR)],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        console.print("[green]Trivy scan complete.[/green]")
        _post_scan_pipeline("trivy")
    else:
        logger.error(f"Trivy scan failed: {result.stderr[:500]}")


def _post_scan_pipeline(scan_type: str):
    latest = _get_latest_results(scan_type)
    if not latest:
        return

    data     = json.loads(latest.read_text())
    findings = data.get("findings", [])
    counts   = data.get("counts", {})

    _update_dashboard(findings)
    _create_thehive_tickets(latest)
    _send_slack_summary(scan_type, counts, latest.name)
    _send_email_summary(scan_type, counts)


def _get_latest_results(scan_type: str) -> Path | None:
    files = sorted(RESULTS_DIR.glob(f"{scan_type}-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _update_dashboard(findings: list):
    try:
        from database import Database
        from risk_scorer import RiskScorer
        db     = Database(os.getenv("DATABASE_PATH", "dashboard/backend/vulndb.sqlite"))
        scorer = RiskScorer()
        db.init_db()
        scored = scorer.batch_score(findings)
        for f in scored:
            db.upsert_vulnerability(f)
        console.print(f"[green]Dashboard updated with {len(scored)} findings.[/green]")
    except Exception as e:
        logger.error(f"Dashboard update failed: {e}")


def _create_thehive_tickets(results_file: Path):
    result = subprocess.run(
        ["python3", "thehive-integration/auto-create-scripts/thehive-ticket-creator.py",
         "--findings", str(results_file),
         "--severity-threshold", "high"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.warning(f"TheHive ticket creation warning: {result.stderr[:300]}")


def _send_slack_summary(scan_type: str, counts: dict, filename: str):
    if not SLACK_WEBHOOK:
        return
    msg = {
        "text": f":shield: *Vuln Scan Complete* — `{scan_type}`\n"
                f"*Critical:* {counts.get('Critical', 0)}  "
                f"*High:* {counts.get('High', 0)}  "
                f"*Medium:* {counts.get('Medium', 0)}  "
                f"*Low:* {counts.get('Low', 0)}\n"
                f"_File: {filename}_"
    }
    try:
        requests.post(SLACK_WEBHOOK, json=msg, timeout=5)
    except Exception as e:
        logger.warning(f"Slack notification failed: {e}")


def _send_email_summary(scan_type: str, counts: dict):
    if not all([SMTP_USER, SMTP_PASS]):
        return
    body = (
        f"Vulnerability Scan Summary — {scan_type.upper()}\n"
        f"Time: {datetime.utcnow().isoformat()}\n\n"
        f"Critical : {counts.get('Critical', 0)}\n"
        f"High     : {counts.get('High', 0)}\n"
        f"Medium   : {counts.get('Medium', 0)}\n"
        f"Low      : {counts.get('Low', 0)}\n\n"
        "View dashboard: http://localhost:5000"
    )
    msg            = MIMEText(body)
    msg["Subject"] = f"[VulnMgmt] {scan_type.capitalize()} scan complete"
    msg["From"]    = SMTP_USER
    msg["To"]      = SMTP_USER
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception as e:
        logger.warning(f"Email notification failed: {e}")


def run_weekly_full_scan():
    console.print("[bold cyan]Running weekly full scan...[/bold cyan]")
    run_openvas_scan()
    run_trivy_scan()


def main():
    console.rule("[bold cyan]Vulnerability Scan Scheduler")
    console.print(f"  OpenVAS schedule : {SCAN_SCHEDULE_OPENVAS}")
    console.print(f"  Trivy schedule   : {SCAN_SCHEDULE_TRIVY}")
    console.print("  Weekly full scan : Sunday 01:00\n")

    schedule.every().day.at(SCAN_SCHEDULE_OPENVAS).do(run_openvas_scan)
    schedule.every().day.at(SCAN_SCHEDULE_TRIVY).do(run_trivy_scan)
    schedule.every().sunday.at("01:00").do(run_weekly_full_scan)

    console.print("[green]Scheduler running. Press Ctrl+C to stop.[/green]")
    while True:
        schedule.run_pending()
        time.sleep(30)


if __name__ == "__main__":
    main()
