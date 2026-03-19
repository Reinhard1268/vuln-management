# parse-openvas-results.py

import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()


def parse_args():
    p = argparse.ArgumentParser(description="Parse OpenVAS XML report into structured JSON")
    p.add_argument("--input",  required=True, help="Path to OpenVAS XML report")
    p.add_argument("--output", default="",    help="Output JSON path (auto if omitted)")
    return p.parse_args()


def severity_label(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return "Info"


def parse_finding(result) -> dict:
    cves = [r.get("id", "") for r in result.findall(".//ref[@type='cve']")]
    refs = [r.get("id", "") for r in result.findall(".//ref")]

    raw_severity = result.findtext("severity", "0").strip()
    try:
        severity_score = float(raw_severity)
    except ValueError:
        severity_score = 0.0

    nvt      = result.find("nvt") or {}
    cvss_vec = ""
    if hasattr(nvt, "findtext"):
        cvss_vec = nvt.findtext("cvss_base_vector", "")

    host_elem = result.find("host")
    host      = host_elem.text.strip() if host_elem is not None and host_elem.text else ""
    hostname  = host_elem.findtext("hostname", "") if host_elem is not None else ""

    return {
        "id":            result.get("id", ""),
        "name":          result.findtext("name", "").strip(),
        "description":   result.findtext("description", "").strip(),
        "solution":      result.findtext("solution", "").strip(),
        "cvss_score":    severity_score,
        "cvss_vector":   cvss_vec,
        "severity":      severity_label(severity_score),
        "host":          host,
        "hostname":      hostname,
        "port":          result.findtext("port", "").strip(),
        "cves":          cves,
        "references":    refs,
        "threat":        result.findtext("threat", "").strip(),
        "source":        "openvas",
        "parsed_at":     datetime.utcnow().isoformat(),
    }


def deduplicate(findings: list) -> list:
    seen = {}
    for f in findings:
        key = f"{f['name']}|{f['host']}|{f['port']}"
        if key not in seen:
            seen[key] = f
        else:
            existing_cves = set(seen[key]["cves"])
            existing_cves.update(f["cves"])
            seen[key]["cves"] = list(existing_cves)
    return list(seen.values())


def main():
    args    = parse_args()
    in_path = Path(args.input)
    if not in_path.exists():
        console.print(f"[red]File not found: {in_path}[/red]")
        raise SystemExit(1)

    console.print(f"[cyan]Parsing:[/cyan] {in_path}")

    tree     = ET.parse(in_path)
    root     = tree.getroot()
    results  = root.findall(".//result")

    console.print(f"[cyan]Raw results found:[/cyan] {len(results)}")

    findings = [parse_finding(r) for r in results]
    findings = deduplicate(findings)

    findings.sort(key=lambda x: x["cvss_score"], reverse=True)

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    out_path = Path(args.output) if args.output else in_path.parent / f"{in_path.stem}-parsed.json"
    out_path.write_text(json.dumps({
        "source":    "openvas",
        "parsed_at": datetime.utcnow().isoformat(),
        "total":     len(findings),
        "counts":    counts,
        "findings":  findings,
    }, indent=2))

    table = Table(title="Parse Summary")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev, cnt in counts.items():
        table.add_row(sev, str(cnt))
    console.print(table)
    console.print(f"\n[green]Output:[/green] {out_path}")


if __name__ == "__main__":
    main()
