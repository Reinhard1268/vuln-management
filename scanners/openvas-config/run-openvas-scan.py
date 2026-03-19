# run-openvas-scan.py

import argparse
import json
import os
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

load_dotenv()
console = Console()

OPENVAS_SOCKET = "/run/gvmd/gvmd.sock"
OPENVAS_USER   = os.getenv("OPENVAS_USER", "admin")
OPENVAS_PASS   = os.getenv("OPENVAS_PASSWORD", "")
RESULTS_DIR    = Path("scanners/scan-results")

SCAN_CONFIGS = {
    "full":  "daba56c8-73ec-11df-a475-002264764cea",
    "web":   "085569ce-73ed-11df-83c3-002264764cea",
    "quick": "2d3f051c-55ba-11e3-bf43-406186ea4fc5",
}

SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"


def parse_args():
    p = argparse.ArgumentParser(description="Run OpenVAS scan via GVM API")
    p.add_argument("--target",      required=True, help="IP address or CIDR range")
    p.add_argument("--scan-config", choices=["full", "web", "quick"], default="full")
    p.add_argument("--output-dir",  default=str(RESULTS_DIR))
    p.add_argument("--name",        default="", help="Scan name (auto-generated if omitted)")
    return p.parse_args()


def connect():
    conn      = UnixSocketConnection(path=OPENVAS_SOCKET)
    transform = EtreeCheckCommandTransform()
    return Gmp(connection=conn, transform=transform)


def create_target(gmp, host: str, name: str) -> str:
    port_list_id = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    resp = gmp.create_target(name=name, hosts=[host], port_list_id=port_list_id)
    return resp.get("id")


def create_task(gmp, name: str, target_id: str, config_id: str) -> str:
    resp = gmp.create_task(
        name=name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=SCANNER_ID,
    )
    return resp.get("id")


def start_task(gmp, task_id: str) -> str:
    resp = gmp.start_task(task_id)
    return resp.find("report_id").text


def poll_task(gmp, task_id: str) -> dict:
    while True:
        resp   = gmp.get_task(task_id=task_id)
        status = resp.find(".//status").text
        prog   = resp.find(".//progress").text or "0"
        prog   = int(prog) if str(prog).lstrip("-").isdigit() else 0
        prog   = max(0, prog)

        if status in ("Done", "Stopped", "Interrupted"):
            return {"status": status, "progress": 100}
        yield {"status": status, "progress": prog}
        time.sleep(30)


def download_report(gmp, report_id: str, output_dir: Path, fmt: str = "xml") -> Path:
    FORMAT_IDS = {
        "xml": "a994b278-1f62-11e1-96ac-406186ea4fc5",
        "pdf": "c402cc3e-b531-11e1-9163-406186ea4fc5",
    }
    fmt_id = FORMAT_IDS[fmt]
    resp   = gmp.get_report(
        report_id=report_id,
        filter_string="apply_overrides=0 levels=hmlg",
        report_format_id=fmt_id,
        ignore_pagination=True,
    )
    content = ET.tostring(resp, encoding="unicode")
    out     = output_dir / f"openvas-{report_id[:8]}.{fmt}"
    out.write_text(content, encoding="utf-8")
    return out


def xml_to_json(xml_path: Path, output_dir: Path) -> Path:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    findings = []
    for result in root.findall(".//result"):
        name        = result.findtext("name", "")
        description = result.findtext("description", "")
        severity    = result.findtext("severity", "0")
        host        = result.findtext("host", "")
        port        = result.findtext("port", "")
        threat      = result.findtext("threat", "")
        solution    = result.findtext("solution", "")
        cve_list     = [ref.get("id", "") for ref in result.findall(".//ref[@type='cve']")]
        refs         = [ref.get("id", "") for ref in result.findall(".//ref")]

        findings.append({
            "id":          result.get("id", ""),
            "name":        name,
            "description": description,
            "severity":    float(severity) if severity else 0.0,
            "threat":      threat,
            "host":        host,
            "port":        port,
            "cves":        cve_list,
            "references":  refs,
            "solution":    solution,
            "scanned_at":  datetime.utcnow().isoformat(),
            "source":      "openvas",
        })

    json_path = output_dir / f"openvas-{xml_path.stem}.json"
    json_path.write_text(json.dumps({"findings": findings, "total": len(findings)}, indent=2))
    return json_path


def severity_counts(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", 0)
        if s >= 9.0:
            counts["critical"] += 1
        elif s >= 7.0:
            counts["high"] += 1
        elif s >= 4.0:
            counts["medium"] += 1
        elif s > 0:
            counts["low"] += 1
        else:
            counts["info"] += 1
    return counts


def main():
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_name  = args.name or f"Lab-Scan-{args.target}-{datetime.utcnow().strftime('%Y%m%d-%H%M')}"
    config_id  = SCAN_CONFIGS[args.scan_config]

    console.rule("[bold cyan]OpenVAS Scan Runner")
    console.print(f"  Target      : [yellow]{args.target}[/yellow]")
    console.print(f"  Scan config : [yellow]{args.scan_config}[/yellow]")
    console.print(f"  Output dir  : [yellow]{output_dir}[/yellow]\n")

    with connect() as gmp:
        gmp.authenticate(OPENVAS_USER, OPENVAS_PASS)

        console.print("[cyan]Creating target...[/cyan]")
        target_id = create_target(gmp, args.target, f"Target-{scan_name}")
        console.print(f"  Target ID: [green]{target_id}[/green]")

        console.print("[cyan]Creating task...[/cyan]")
        task_id = create_task(gmp, scan_name, target_id, config_id)
        console.print(f"  Task ID: [green]{task_id}[/green]")

        console.print("[cyan]Starting scan...[/cyan]")
        report_id = start_task(gmp, task_id)
        console.print(f"  Report ID: [green]{report_id}[/green]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=100)
            for state in poll_task(gmp, task_id):
                progress.update(task, completed=state["progress"],
                                description=f"[cyan]{state['status']}[/cyan]")

        console.print("\n[green]Scan complete. Downloading reports...[/green]")
        xml_path = download_report(gmp, report_id, output_dir, "xml")
        pdf_path = download_report(gmp, report_id, output_dir, "pdf")
        console.print(f"  XML: {xml_path}")
        console.print(f"  PDF: {pdf_path}")

        json_path = xml_to_json(xml_path, output_dir)
        console.print(f"  JSON: {json_path}")

        data   = json.loads(json_path.read_text())
        counts = severity_counts(data["findings"])

    table = Table(title="Scan Summary", style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("[red]Critical[/red]",  str(counts["critical"]))
    table.add_row("[orange3]High[/orange3]",   str(counts["high"]))
    table.add_row("[yellow]Medium[/yellow]", str(counts["medium"]))
    table.add_row("[blue]Low[/blue]",      str(counts["low"]))
    table.add_row("Info",                  str(counts["info"]))
    console.print(table)
    console.print(f"\n[green]Total findings: {data['total']}[/green]")


if __name__ == "__main__":
    main()
