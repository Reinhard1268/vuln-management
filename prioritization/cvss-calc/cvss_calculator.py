# cvss_calculator.py

import argparse
import math
from rich.console import Console
from rich.table import Table

console = Console()

# CVSS v3.1 metric weights
METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N":  {"U": 0.85, "C": 0.85},
        "L":  {"U": 0.62, "C": 0.68},
        "H":  {"U": 0.27, "C": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.00, "L": 0.22, "H": 0.56},
    # Temporal
    "E":  {"X": 1.00, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.00},
    "RL": {"X": 1.00, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.00},
    "RC": {"X": 1.00, "U": 0.92, "R": 0.96, "C": 1.00},
    # Environmental
    "CR": {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50},
    "IR": {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50},
    "AR": {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50},
}

SEVERITY_LABELS = {
    (0.0, 0.0):  "None",
    (0.1, 3.9):  "Low",
    (4.0, 6.9):  "Medium",
    (7.0, 8.9):  "High",
    (9.0, 10.0): "Critical",
}


def parse_vector(vector: str) -> dict:
    vector = vector.strip()
    if vector.startswith("CVSS:3"):
        vector = vector.split("/", 1)[1]
    parts = vector.split("/")
    parsed = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            parsed[k.strip()] = v.strip()
    return parsed


def validate_vector(parsed: dict) -> list:
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    errors   = []
    for r in required:
        if r not in parsed:
            errors.append(f"Missing required metric: {r}")
    return errors


def severity_label(score: float) -> str:
    if score == 0.0:
        return "None"
    for (lo, hi), label in SEVERITY_LABELS.items():
        if lo <= score <= hi:
            return label
    return "Critical"


def roundup(val: float) -> float:
    return math.ceil(val * 10) / 10


def calculate_base_score(p: dict) -> tuple:
    scope_changed = p.get("S", "U") == "C"

    av  = METRICS["AV"][p["AV"]]
    ac  = METRICS["AC"][p["AC"]]
    pr_vals = METRICS["PR"][p["PR"]]
    pr  = pr_vals["C"] if scope_changed else pr_vals["U"]
    ui  = METRICS["UI"][p["UI"]]

    c   = METRICS["C"][p["C"]]
    i   = METRICS["I"][p["I"]]
    a   = METRICS["A"][p["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0, 0.0, 0.0, impact, exploitability

    if scope_changed:
        base = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base = roundup(min(impact + exploitability, 10))

    return base, impact, exploitability, iss, exploitability


def calculate_temporal_score(base: float, p: dict) -> float:
    e  = METRICS["E"].get(p.get("E",  "X"), 1.0)
    rl = METRICS["RL"].get(p.get("RL", "X"), 1.0)
    rc = METRICS["RC"].get(p.get("RC", "X"), 1.0)
    return roundup(base * e * rl * rc)


def calculate_environmental_score(p: dict) -> float:
    scope_changed = p.get("MS", p.get("S", "U")) == "C"

    av  = METRICS["AV"].get(p.get("MAV", p.get("AV", "N")), 0.85)
    ac  = METRICS["AC"].get(p.get("MAC", p.get("AC", "L")), 0.77)
    pr_map = METRICS["PR"][p.get("MPR", p.get("PR", "N"))]
    pr  = pr_map["C"] if scope_changed else pr_map["U"]
    ui  = METRICS["UI"].get(p.get("MUI", p.get("UI", "N")), 0.85)

    c   = METRICS["C"].get(p.get("MC", p.get("C", "N")), 0.0)
    i   = METRICS["I"].get(p.get("MI", p.get("I", "N")), 0.0)
    a   = METRICS["A"].get(p.get("MA", p.get("A", "N")), 0.0)

    cr  = METRICS["CR"].get(p.get("CR", "X"), 1.0)
    ir  = METRICS["IR"].get(p.get("IR", "X"), 1.0)
    ar  = METRICS["AR"].get(p.get("AR", "X"), 1.0)

    miss = min(1 - (1 - c*cr) * (1 - i*ir) * (1 - a*ar), 0.915)

    if scope_changed:
        m_impact = 7.52*(miss-0.029) - 3.25*((miss*0.9731-0.02)**13)
    else:
        m_impact = 6.42 * miss

    m_exploit = 8.22 * av * ac * pr * ui

    if m_impact <= 0:
        return 0.0

    e  = METRICS["E"].get(p.get("E",  "X"), 1.0)
    rl = METRICS["RL"].get(p.get("RL", "X"), 1.0)
    rc = METRICS["RC"].get(p.get("RC", "X"), 1.0)

    if scope_changed:
        env = roundup(roundup(min(1.08*(m_impact + m_exploit), 10)) * e * rl * rc)
    else:
        env = roundup(roundup(min(m_impact + m_exploit, 10)) * e * rl * rc)

    return env


def print_breakdown(vector: str, p: dict, base: float, temporal: float | None, env: float | None,
                    impact: float, exploitability: float):
    console.rule("[bold cyan]CVSS v3.1 Score Breakdown")
    console.print(f"  Vector: [yellow]{vector}[/yellow]\n")

    t1 = Table(show_header=True)
    t1.add_column("Component",    style="bold")
    t1.add_column("Score",        justify="right")
    t1.add_column("Severity",     justify="center")
    t1.add_row("Base Score",   f"[bold]{base:.1f}[/bold]", severity_label(base))
    if temporal is not None:
        t1.add_row("Temporal Score", f"{temporal:.1f}", severity_label(temporal))
    if env is not None:
        t1.add_row("Environmental Score", f"{env:.1f}", severity_label(env))
    console.print(t1)

    t2 = Table(title="Metric Breakdown", show_header=True)
    t2.add_column("Metric")
    t2.add_column("Value")
    t2.add_column("Description")
    metric_desc = {
        "AV": "Attack Vector",    "AC": "Attack Complexity",
        "PR": "Privileges Required", "UI": "User Interaction",
        "S":  "Scope",            "C":  "Confidentiality Impact",
        "I":  "Integrity Impact", "A":  "Availability Impact",
        "E":  "Exploit Maturity", "RL": "Remediation Level",
        "RC": "Report Confidence",
    }
    for k, v in p.items():
        t2.add_row(k, v, metric_desc.get(k, ""))
    console.print(t2)


def calculate(vector: str) -> dict:
    p      = parse_vector(vector)
    errors = validate_vector(p)
    if errors:
        for e in errors:
            console.print(f"[red]Error: {e}[/red]")
        return {}

    base, impact, exploit, iss, _ = calculate_base_score(p)

    temporal = None
    if any(k in p for k in ["E", "RL", "RC"]):
        temporal = calculate_temporal_score(base, p)

    env = None
    if any(k in p for k in ["CR", "IR", "AR", "MAV", "MAC"]):
        env = calculate_environmental_score(p)

    print_breakdown(vector, p, base, temporal, env, impact, exploit)

    return {
        "vector":      vector,
        "base_score":  base,
        "base_severity": severity_label(base),
        "temporal_score":     temporal,
        "environmental_score": env,
    }


def parse_args():
    p = argparse.ArgumentParser(description="CVSS v3.1 Calculator")
    p.add_argument("vector", nargs="?", default="",
                   help="CVSS v3.1 vector string e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    return p.parse_args()


def main():
    args = parse_args()
    if not args.vector:
        console.print("[yellow]Example:[/yellow] python3 cvss_calculator.py AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        return
    calculate(args.vector)


if __name__ == "__main__":
    main()
