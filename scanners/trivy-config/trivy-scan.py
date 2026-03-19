# trivy-scan.py

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from tqdm import tqdm

console = Console()

LAB_CONTAINERS = [
    "wazuh/wazuh-manager:latest",
    "docker.elastic.co/elasticsearch/elasticsearch:8.13.0",
    "docker.elastic.co/kibana/kibana:8.13.0",
    "strangebee/thehive:5",
    "frikky/shuffle:latest",
]

RESULTS_DIR = Path("scanners/scan-results")


def parse_args():
    p = argparse.ArgumentParser(description="Trivy scanner wrapper")
    p.add_argument("--target",  default="",       help="Target image/path/repo")
    p.add_argument("--type",    default="image",  choices=["image", "fs", "repo", "k8s"])
    p.add_argument("--output",  default=str(RESULTS_DIR))
    p.add_argument("--all-lab", action="store_true", help="Scan all Project 1 lab containers")
    return p.parse_args()


def run_trivy(target: str, scan_type: str, output_file: Path) -> dict:
    cmd = [
        "trivy", scan_type,
        "--format", "json",
        "--output", str(output_file),
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        "--no-progress",
        target,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        console.print(f"[red]Trivy error:[/red] {result.stderr[:500]}")
        return {}
    if output_file.exists():
        return json.loads(output_file.read_text())
    return {}


def normalize_finding(vuln: dict, target: str, result_target: str) -> dict:
    return {
        "id":              vuln.get("VulnerabilityID", ""),
        "package":         vuln.get("PkgName", ""),
        "installed_ver":   vuln.get("InstalledVersion", ""),
        "fixed_ver":       vuln.get("FixedVersion", ""),
        "severity":        vuln.get("Severity", "UNKNOWN").capitalize(),
        "cvss_score":      vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
        "title":           vuln.get("Title", ""),
        "description":     vuln.get("Description", "")[:500],
        "references":      vuln.get("References", [])[:5],
        "target":          target,
        "result_target":   result_target,
        "source":          "trivy",
        "scanned_at":      datetime.utcnow().isoformat(),
    }


def parse_trivy_output(data: dict, target: str) -> list:
    findings = []
    results  = data if isinstance(data, list) else data.get("Results", [])
    for r in results:
        for vuln in r.get("Vulnerabilities") or []:
            findings.append(normalize_finding(vuln, target, r.get("Target", "")))
    return findings


def deduplicate(findings: list) -> list:
    seen = {}
    for f in findings:
        key = f"{f['id']}|{f['package']}|{f['target']}"
        if key not in seen:
            seen[key] = f
    return list(seen.values())


def severity_counts(findings: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for f in findings:
        sev = f.get("severity", "Unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def scan_target(target: str, scan_type: str, output_dir: Path) -> list:
    safe    = target.replace("/", "-").replace(":", "-")
    ts      = datetime.utcnow().strftime("%Y%m%d-%H%M")
    out_raw = output_dir / f"trivy-raw-{safe}-{ts}.json"

    console.print(f"  [cyan]Scanning:[/cyan] {target}")
    data     = run_trivy(target, scan_type, out_raw)
    findings = parse_trivy_output(data, target)
    console.print(f"  [green]Found:[/green] {len(findings)} vulnerabilities")
    return findings


def main():
    args = parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []

    if args.all_lab:
        console.rule("[bold cyan]Scanning All Lab Containers")
        for image in tqdm(LAB_CONTAINERS, desc="Containers"):
            findings = scan_target(image, "image", output_dir)
            all_findings.extend(findings)
    elif args.target:
        console.rule("[bold cyan]Trivy Scan")
        findings = scan_target(args.target, args.type, output_dir)
        all_findings.extend(findings)
    else:
        console.print("[red]Provide --target or --all-lab[/red]")
        sys.exit(1)

    all_findings = deduplicate(all_findings)
    all_findings.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)

    ts       = datetime.utcnow().strftime("%Y%m%d-%H%M")
    out_file = output_dir / f"trivy-{ts}.json"
    out_file.write_text(json.dumps({
        "source":     "trivy",
        "scanned_at": datetime.utcnow().isoformat(),
        "total":      len(all_findings),
        "counts":     severity_counts(all_findings),
        "findings":   all_findings,
    }, indent=2))

    counts = severity_counts(all_findings)
    table  = Table(title="Trivy Scan Summary")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    table.add_row("[red]Critical[/red]", str(counts["Critical"]))
    table.add_row("[orange3]High[/orange3]",   str(counts["High"]))
    table.add_row("[yellow]Medium[/yellow]", str(counts["Medium"]))
    table.add_row("[blue]Low[/blue]",      str(counts["Low"]))
    console.print(table)
    console.print(f"\n[green]Results:[/green] {out_file}")


if __name__ == "__main__":
    main()
