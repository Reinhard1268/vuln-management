# business_risk_model.py

import json
from pathlib import Path
from rich.console import Console
from rich.table import Table

console    = Console()
ASSETS_FILE = Path("prioritization/business-risk-model/assets.json")


class AssetInventory:
    def __init__(self, path: Path = ASSETS_FILE):
        self.assets: dict = {}
        self._load(path)

    def _load(self, path: Path):
        if path.exists():
            data = json.loads(path.read_text())
            for a in data.get("assets", []):
                self.assets[a["id"]] = a
                self.assets[a.get("ip", "")] = a
                self.assets[a.get("hostname", "")] = a

    def get_asset(self, identifier: str) -> dict:
        return self.assets.get(identifier, {})

    def all_assets(self) -> list:
        seen = set()
        result = []
        for v in self.assets.values():
            aid = v.get("id")
            if aid and aid not in seen:
                seen.add(aid)
                result.append(v)
        return result


class BusinessRiskCalculator:
    def __init__(self, inventory: AssetInventory = None):
        self.inventory = inventory or AssetInventory()

    def calculate_asset_value(self, asset: dict) -> float:
        criticality_map = {
            "critical":    1.0,
            "high":        0.8,
            "medium":      0.5,
            "low":         0.2,
        }
        sensitivity_map = {
            "pii":         0.4,
            "financial":   0.4,
            "confidential":0.3,
            "internal":    0.15,
            "public":      0.0,
        }
        base = criticality_map.get(asset.get("criticality", "low").lower(), 0.2)
        sens = sensitivity_map.get(asset.get("data_sensitivity", "internal").lower(), 0.15)
        return min(base + sens, 1.0)

    def calculate_exposure_factor(self, asset: dict) -> float:
        exposure = asset.get("exposure", "internal").lower()
        exposure_map = {
            "internet":    1.5,
            "dmz":         1.3,
            "internal":    1.0,
            "isolated":    0.5,
            "air_gapped":  0.2,
        }
        multiplier = exposure_map.get(exposure, 1.0)

        if asset.get("internet_facing"):   multiplier = max(multiplier, 1.5)
        if asset.get("contains_pii"):       multiplier = max(multiplier, 1.4)
        if asset.get("is_production"):      multiplier = max(multiplier, 1.3)
        if asset.get("is_dev"):             multiplier = min(multiplier, 0.7)

        return multiplier

    def calculate_business_impact(self, vuln: dict, asset: dict) -> float:
        asset_value = self.calculate_asset_value(asset)
        exposure    = self.calculate_exposure_factor(asset)
        raw         = asset_value * 25.0 * exposure
        return min(round(raw, 2), 25.0)

    def score_vulnerability(self, vuln: dict) -> dict:
        vuln = dict(vuln)

        host     = vuln.get("host", "")
        hostname = vuln.get("hostname", "")
        asset    = (self.inventory.get_asset(host)
                    or self.inventory.get_asset(hostname)
                    or {})

        cvss_score  = float(vuln.get("cvss_score", 0) or 0)
        cvss_comp   = min(cvss_score / 10.0, 1.0) * 40.0

        cve         = vuln.get("cve") or (vuln.get("cves") or [""])[0]
        epss_score  = float(vuln.get("epss_score", 0) or 0)
        epss_comp   = min(epss_score, 1.0) * 35.0

        biz_comp    = self.calculate_business_impact(vuln, asset)

        composite   = round(cvss_comp + epss_comp + biz_comp, 2)
        composite   = min(composite, 100.0)

        vuln["asset_info"]       = asset
        vuln["asset_value"]      = self.calculate_asset_value(asset) if asset else 0.5
        vuln["exposure_factor"]  = self.calculate_exposure_factor(asset) if asset else 1.0
        vuln["cvss_component"]   = round(cvss_comp, 2)
        vuln["epss_component"]   = round(epss_comp, 2)
        vuln["business_component"] = round(biz_comp, 2)
        vuln["composite_score"]  = composite

        if composite >= 80:
            vuln["priority"] = "CRITICAL"
        elif composite >= 60:
            vuln["priority"] = "HIGH"
        elif composite >= 40:
            vuln["priority"] = "MEDIUM"
        else:
            vuln["priority"] = "LOW"

        return vuln

    def batch_score(self, findings: list) -> list:
        scored = [self.score_vulnerability(f) for f in findings]
        scored.sort(key=lambda x: x["composite_score"], reverse=True)
        return scored

    def print_scores(self, scored: list, top: int = 20):
        table = Table(title=f"Top {top} Prioritised Vulnerabilities (Business Risk Model)")
        table.add_column("CVE",            style="cyan")
        table.add_column("Host")
        table.add_column("CVSS pts",       justify="right")
        table.add_column("EPSS pts",       justify="right")
        table.add_column("Biz pts",        justify="right")
        table.add_column("Total",          justify="right", style="bold")
        table.add_column("Priority",       justify="center")
        table.add_column("Asset")

        for v in scored[:top]:
            cve = v.get("cve") or (v.get("cves") or [""])[0] or v.get("id", "—")
            pri = v.get("priority", "LOW")
            color_map = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "blue"}
            col = color_map.get(pri, "white")
            asset_name = v.get("asset_info", {}).get("name", v.get("hostname", "—"))
            table.add_row(
                cve[:24],
                v.get("host", "—"),
                str(v.get("cvss_component", 0)),
                str(v.get("epss_component", 0)),
                str(v.get("business_component", 0)),
                f"[{col}]{v.get('composite_score', 0)}[/{col}]",
                f"[{col}]{pri}[/{col}]",
                asset_name,
            )
        console.print(table)
