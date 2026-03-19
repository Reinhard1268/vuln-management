
````python
# generate-report.py

import argparse
import json
import os
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader, BaseLoader
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
)
from rich.console import Console

load_dotenv()
console = Console()

DB_PATH   = os.getenv("DATABASE_PATH", "dashboard/backend/vulndb.sqlite")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASSWORD", "")

REPORT_DIRS = {
    "weekly":    Path("reports/weekly"),
    "monthly":   Path("reports/monthly"),
    "executive": Path("reports/executive"),
}


def parse_args():
    p = argparse.ArgumentParser(description="Generate vulnerability management reports")
    p.add_argument("--type",   choices=["weekly","monthly","executive"], required=True)
    p.add_argument("--format", choices=["pdf","markdown","both"], default="both")
    p.add_argument("--send",   action="store_true", help="Email report after generation")
    return p.parse_args()


def get_db_data() -> dict:
    import sys; sys.path.insert(0, "dashboard/backend")
    try:
        from database import Database
        from risk_scorer import RiskScorer
        db     = Database(DB_PATH)
        stats  = db.get_stats()
        vulns  = db.get_vulnerabilities(limit=500)
        scored = RiskScorer().batch_score(vulns)
        scans  = db.get_scan_history()
        return {
            "stats":  stats,
            "vulns":  vulns,
            "scored": scored,
            "scans":  scans,
        }
    except Exception as e:
        console.print(f"[yellow]DB load warning: {e} — using empty data[/yellow]")
        return {"stats": {}, "vulns": [], "scored": [], "scans": []}


def generate_severity_chart(stats: dict, output_path: Path) -> Path:
    by_sev = stats.get("by_severity", {})
    labels = ["Critical", "High", "Medium", "Low"]
    values = [by_sev.get(l, 0) for l in labels]
    colors_list = ["#ff4d4d", "#f97316", "#facc15", "#60a5fa"]

    fig, ax = plt.subplots(figsize=(5, 3), facecolor="#161b22")
    ax.set_facecolor("#161b22")
    bars = ax.bar(labels, values, color=colors_list, edgecolor="#30363d")
    ax.set_title("Vulnerabilities by Severity", color="#e6edf3", fontsize=11)
    ax.tick_params(colors="#8b949e")
    for spine in ax.spines.values(): spine.set_color("#30363d")
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                str(val), ha="center", color="#e6edf3", fontsize=9)

    out = output_path / "chart-severity.png"
    plt.tight_layout()
    plt.savefig(out, dpi=120, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    return out


def build_pdf(report_type: str, data: dict, output_dir: Path) -> Path:
    ts       = datetime.utcnow().strftime("%Y%m%d-%H%M")
    out_path = output_dir / f"{report_type}-report-{ts}.pdf"
    doc      = SimpleDocTemplate(str(out_path), pagesize=A4,
                                  leftMargin=2*cm, rightMargin=2*cm,
                                  topMargin=2*cm, bottomMargin=2*cm)
    styles   = getSampleStyleSheet()
    story    = []

    title_style = ParagraphStyle("title", parent=styles["Title"],
                                  fontSize=18, spaceAfter=10)
    h1_style    = ParagraphStyle("h1", parent=styles["Heading1"],
                                  fontSize=13, spaceAfter=6)
    body_style  = styles["BodyText"]

    stats = data.get("stats", {})
    by_sev = stats.get("by_severity", {})

    story.append(Paragraph(f"Vulnerability {report_type.capitalize()} Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", body_style))
    story.append(Spacer(1, 0.5*cm))

    # Chart
    chart_path = generate_severity_chart(stats, output_dir)
    if chart_path.exists():
        story.append(Image(str(chart_path), width=12*cm, height=7*cm))
        story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("Summary Statistics", h1_style))
    table_data = [
        ["Severity", "Count"],
        ["Critical", str(by_sev.get("Critical", 0))],
        ["High",     str(by_sev.get("High", 0))],
        ["Medium",   str(by_sev.get("Medium", 0))],
        ["Low",      str(by_sev.get("Low", 0))],
        ["Total Open", str(stats.get("open", 0))],
    ]
    tbl = Table(table_data, colWidths=[8*cm, 4*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#238636")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN",      (1,0), (-1,-1), "CENTER"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#dee2e6")),
        ("FONTSIZE",   (0,0), (-1,-1), 10),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Top 10 Priority Vulnerabilities", h1_style))
    scored   = data.get("scored", [])[:10]
    top_data = [["CVE", "Severity", "Host", "Risk Score"]]
    for v in scored:
        cve = v.get("cve") or (v.get("cves") or ["—"])[0] or "—"
        top_data.append([cve[:20], v.get("severity","—"), v.get("host","—"),
                          str(v.get("risk_score", 0))])
    tbl2 = Table(top_data, colWidths=[5*cm, 3*cm, 5*cm, 3*cm])
    tbl2.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1f3a5f")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#dee2e6")),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
    ]))
    story.append(tbl2)

    doc.build(story)
    return out_path


def build_markdown(report_type: str, data: dict, output_dir: Path) -> Path:
    ts        = datetime.utcnow().strftime("%Y%m%d-%H%M")
    out_path  = output_dir / f"{report_type}-report-{ts}.md"
    stats     = data.get("stats", {})
    by_sev    = stats.get("by_severity", {})
    scored    = data.get("scored", [])[:10]

    lines = [
        f"# Vulnerability {report_type.capitalize()} Report",
        f"",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| Critical | {by_sev.get('Critical', 0)} |",
        f"| High     | {by_sev.get('High', 0)} |",
        f"| Medium   | {by_sev.get('Medium', 0)} |",
        f"| Low      | {by_sev.get('Low', 0)} |",
        f"| **Open** | **{stats.get('open', 0)}** |",
        f"",
        f"## Top 10 Priority Vulnerabilities",
        f"",
        f"| CVE | Name | Host | CVSS | EPSS | Risk Score |",
        f"|-----|------|------|------|------|------------|",
    ]
    for v in scored:
        cve  = v.get("cve") or (v.get("cves") or ["—"])[0] or "—"
        name = (v.get("name") or "—")[:50]
        lines.append(
            f"| {cve} | {name} | {v.get('host','—')} | "
            f"{v.get('cvss_score',0):.1f} | {v.get('epss_score',0)*100:.1f}% | "
            f"{v.get('risk_score',0)} |"
        )

    out_path.write_text("\n".join(lines))
    return out_path


def send_email(report_path: Path):
    if not all([SMTP_USER, SMTP_PASS]):
        console.print("[yellow]Email credentials not configured — skipping send[/yellow]")
        return
    msg                    = MIMEMultipart()
    msg["Subject"]         = f"[VulnMgmt] Report — {report_path.name}"
    msg["From"]            = SMTP_USER
    msg["To"]              = SMTP_USER
    msg.attach(MIMEText("Please find the vulnerability management report attached.", "plain"))
    with open(report_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={report_path.name}")
        msg.attach(part)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        console.print("[green]✓ Report emailed[/green]")
    except Exception as e:
        console.print(f"[yellow]Email failed: {e}[/yellow]")


def main():
    args       = parse_args()
    output_dir = REPORT_DIRS[args.type]
    output_dir.mkdir(parents=True, exist_ok=True)

    console.rule(f"[bold cyan]Generating {args.type.capitalize()} Report")
    data = get_db_data()

    outputs = []

    if args.format in ("pdf", "both"):
        pdf_path = build_pdf(args.type, data, output_dir)
        console.print(f"[green]✓ PDF:[/green] {pdf_path}")
        outputs.append(pdf_path)

    if args.format in ("markdown", "both"):
        md_path = build_markdown(args.type, data, output_dir)
        console.print(f"[green]✓ Markdown:[/green] {md_path}")
        outputs.append(md_path)

    if args.send and outputs:
        send_email(outputs[0])


if __name__ == "__main__":
    main()

