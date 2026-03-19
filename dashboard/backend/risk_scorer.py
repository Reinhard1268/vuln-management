# risk_scorer.py

import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

EPSS_API      = "https://api.first.org/data/v1/epss"
CACHE_DIR     = Path("prioritization/epss-scores/cache")
CACHE_TTL_H   = int(os.getenv("EPSS_CACHE_TTL_HOURS", 24))

ASSET_WEIGHTS = {
    "internet_facing": 1.5,
    "pii":             1.4,
    "production":      1.3,
    "dev":             0.7,
}


class RiskScorer:
    def __init__(self):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._epss_cache: dict = {}
        self._load_cache()

    # ── Cache ──────────────────────────────────────────────────────────────────

    def _cache_path(self) -> Path:
        return CACHE_DIR / "epss_cache.json"

    def _load_cache(self):
        p = self._cache_path()
        if p.exists():
            try:
                self._epss_cache = json.loads(p.read_text())
            except Exception:
                self._epss_cache = {}

    def _save_cache(self):
        self._cache_path().write_text(json.dumps(self._epss_cache, indent=2))

    def _is_fresh(self, entry: dict) -> bool:
        try:
            fetched = datetime.fromisoformat(entry["fetched_at"])
            return datetime.utcnow() - fetched < timedelta(hours=CACHE_TTL_H)
        except Exception:
            return False

    # ── EPSS ───────────────────────────────────────────────────────────────────

    def get_epss_score(self, cve_id: str) -> float:
        if not cve_id or not cve_id.startswith("CVE-"):
            return 0.0
        cached = self._epss_cache.get(cve_id)
        if cached and self._is_fresh(cached):
            return cached["score"]
        try:
            resp = requests.get(EPSS_API, params={"cve": cve_id}, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                score = float(data[0]["epss"]) if data else 0.0
            else:
                score = 0.0
        except Exception:
            score = 0.0

        self._epss_cache[cve_id] = {"score": score, "fetched_at": datetime.utcnow().isoformat()}
        self._save_cache()
        return score

    def bulk_epss(self, cve_ids: list) -> dict:
        needed  = [c for c in cve_ids if c and c.startswith("CVE-")
                   and (c not in self._epss_cache or not self._is_fresh(self._epss_cache[c]))]
        results = {}

        for i in range(0, len(needed), 100):
            batch = needed[i:i+100]
            try:
                resp = requests.get(
                    EPSS_API,
                    params={"cve": ",".join(batch)},
                    timeout=15
                )
                if resp.status_code == 200:
                    for item in resp.json().get("data", []):
                        cve   = item["cve"]
                        score = float(item["epss"])
                        self._epss_cache[cve] = {"score": score, "fetched_at": datetime.utcnow().isoformat()}
            except Exception:
                pass
            time.sleep(0.5)

        self._save_cache()
        for cve in cve_ids:
            results[cve] = self._epss_cache.get(cve, {}).get("score", 0.0)
        return results

    # ── Scoring ────────────────────────────────────────────────────────────────

    def cvss_component(self, cvss_score: float) -> float:
        return min(cvss_score / 10.0, 1.0) * 40.0

    def epss_component(self, epss_score: float) -> float:
        return min(epss_score, 1.0) * 35.0

    def business_component(self, vuln: dict) -> float:
        asset_value = 0.5
        host = (vuln.get("host") or "").lower()
        name = (vuln.get("hostname") or "").lower()

        if "web" in name or "192.168.1.10" in host:
            asset_value = 0.9
        elif "db" in name or "database" in name or "192.168.1.30" in host:
            asset_value = 0.95
        elif "mail" in name or "192.168.1.20" in host:
            asset_value = 0.75
        elif "wazuh" in name or "security" in name:
            asset_value = 0.85

        return asset_value * 25.0

    def calculate_composite_score(self, vuln: dict) -> float:
        cve        = vuln.get("cve") or (vuln.get("cves") or [""])[0]
        epss       = self.get_epss_score(cve)
        cvss       = float(vuln.get("cvss_score", 0) or 0)

        c_cvss     = self.cvss_component(cvss)
        c_epss     = self.epss_component(epss)
        c_biz      = self.business_component(vuln)

        composite  = c_cvss + c_epss + c_biz

        port = (vuln.get("port") or "").lower()
        if any(p in port for p in ["443", "80", "8080", "8443"]):
            composite *= 1.2
        composite = min(composite, 100.0)
        return round(composite, 2)

    def classify_priority(self, score: float) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        return "LOW"

    def batch_score(self, findings: list) -> list:
        cve_ids = []
        for f in findings:
            cve = f.get("cve") or (f.get("cves") or [""])[0]
            if cve:
                cve_ids.append(cve)
        self.bulk_epss(cve_ids)

        scored = []
        for f in findings:
            f = dict(f)
            score = self.calculate_composite_score(f)
            cve   = f.get("cve") or (f.get("cves") or [""])[0]
            f["risk_score"]      = score
            f["epss_score"]      = self._epss_cache.get(cve, {}).get("score", 0.0)
            f["priority_label"]  = self.classify_priority(score)
            scored.append(f)

        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored
