# epss_fetcher.py

import argparse
import csv
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests
from rich.console import Console
from rich.table import Table

console   = Console()
EPSS_API  = "https://api.first.org/data/v1/epss"
CACHE_DIR = Path("prioritization/epss-scores/cache")
CACHE_TTL = int(os.getenv("EPSS_CACHE_TTL_HOURS", 24))


def parse_args():
    p = argparse.ArgumentParser(description="Fetch EPSS scores from FIRST.org API")
    p.add_argument("--cves",      nargs="*", default=[],  help="CVE IDs to look up")
    p.add_argument("--file",      default="",             help="File with one CVE per line")
    p.add_argument("--output",    choices=["json","csv","both"], default="json")
    p.add_argument("--threshold", type=float, default=0.0,help="Only show CVEs above this EPSS score (0-1)")
    return p.parse_args()


def load_cves_from_file(filepath: str) -> list:
    p = Path(filepath)
    if not p.exists():
        console.print(f"[red]File not found: {filepath}[/red]")
        return []
    lines = p.read_text().splitlines()
    return [l.strip() for l in lines if l.strip().startswith("CVE-")]


def load_cache() -> dict:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / "epss_cache.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            return {}
    return {}


def save_cache(cache: dict):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / "epss_cache.json").write_text(json.dumps(cache, indent=2))


def is_fresh(entry: dict) -> bool:
    try:
        fetched = datetime.fromisoformat(entry["fetched_at"])
        return datetime.utcnow() - fetched < timedelta(hours=CACHE_TTL)
    except Exception:
        return False


def fetch_epss_batch(cve_ids: list, cache: dict) -> dict:
    needed  = [c for c in cve_ids if c not in cache or not is_fresh(cache[c])]
    results = {}

    if needed:
        console.print(f"[cyan]Fetching EPSS for {len(needed)} CVEs from FIRST.org...[/cyan]")
        for i in range(0, len(needed), 100):
            batch = needed[i:i+100]
            try:
                resp = requests.get(EPSS_API, params={"cve": ",".join(batch)}, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        cve   = item["cve"]
                        score = float(item["epss"])
                        pct   = float(item.get("percentile", 0))
                        cache[cve] = {
                            "score":      score,
                            "percentile": pct,
                            "fetched_at": datetime.utcnow().isoformat(),
                        }
                else:
                    console.print(f"[yellow]EPSS API returned {resp.status_code}[/yellow]")
            except requests.RequestException as e:
                console.print(f"[red]EPSS API error: {e}[/red]")
            time.sleep(0.5)
        save_cache(cache)

    for cve in cve_ids:
        entry = cache.get(cve, {})
        results[cve] = {
            "cve":        cve,
            "score":      entry.get("score", 0.0),
            "percentile": entry.get("percentile", 0.0),
            "fetched_at": entry.get("fetched_at", ""),
        }
    return results


def save_json(results: dict, threshold: float):
    filtered = {k: v for k, v in results.items() if v["score"] >= threshold}
    out_path = CACHE_DIR / f"epss-results-{datetime.utcnow().strftime('%Y%m%d-%H%M')}.json"
    out_path.write_text(json.dumps(list(filtered.values()), indent=2))
    console.print(f"[green]JSON saved:[/green] {out_path}")


def save_csv(results: dict, threshold: float):
    filtered = [v for v in results.values() if v["score"] >= threshold]
    out_path = CACHE_DIR / f"epss-results-{datetime.utcnow().strftime('%Y%m%d-%H%M')}.csv"
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["cve","score","percentile","fetched_at"])
        writer.writeheader()
        writer.writerows(filtered)
    console.print(f"[green]CSV saved:[/green] {out_path}")


def print_table(results: dict, threshold: float):
    filtered = sorted(
        [v for v in results.values() if v["score"] >= threshold],
        key=lambda x: x["score"], reverse=True
    )
    table = Table(title=f"EPSS Scores (threshold ≥ {threshold})")
    table.add_column("CVE",         style="cyan")
    table.add_column("EPSS Score",  justify="right")
    table.add_column("Percentile",  justify="right")
    table.add_column("Risk Level",  justify="center")
    table.add_column("Fetched At",  style="dim")

    for r in filtered:
        score = r["score"]
        if score >= 0.7:
            level = "[red]CRITICAL[/red]"
        elif score >= 0.4:
            level = "[orange3]HIGH[/orange3]"
        elif score >= 0.1:
            level = "[yellow]MEDIUM[/yellow]"
        else:
            level = "[blue]LOW[/blue]"
        table.add_row(
            r["cve"],
            f"{score:.4f}",
            f"{r['percentile']*100:.1f}%",
            level,
            r["fetched_at"][:19] if r["fetched_at"] else "—",
        )
    console.print(table)


def main():
    args     = parse_args()
    cve_list = list(args.cves)

    if args.file:
        cve_list.extend(load_cves_from_file(args.file))

    cve_list = list(dict.fromkeys(c for c in cve_list if c.startswith("CVE-")))

    if not cve_list:
        console.print("[red]No valid CVE IDs provided. Use --cves CVE-XXXX-XXXXX or --file cves.txt[/red]")
        return

    cache   = load_cache()
    results = fetch_epss_batch(cve_list, cache)

    print_table(results, args.threshold)

    if args.output in ("json", "both"):
        save_json(results, args.threshold)
    if args.output in ("csv", "both"):
        save_csv(results, args.threshold)


if __name__ == "__main__":
    main()
