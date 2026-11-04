"""Stage 2: official severity data for each CVE (FR-5, FR-7 to FR-9).

NVD gives the CVSS score, CISA KEV says whether it is exploited in the wild,
and FIRST EPSS estimates how likely exploitation is. None of it comes from AI.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass

from .safety import FetchError, HTTPStatusError
from .settings import Config

log = logging.getLogger(__name__)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# FR-8 bands: (lowest score, name)
BANDS = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"), (0.0, "None")]


def band(score: float | None) -> str | None:
    if score is None:
        return None
    return next((name for low, name in BANDS if score >= low), None)


@dataclass
class CveInfo:
    id: str
    status: str  # "scored", "pending" (no NVD score yet) or "unavailable" (NVD unreachable)
    cvss: float | None = None
    cvss_version: str | None = None
    kev: bool = False
    epss: float | None = None

    @property
    def band(self) -> str | None:
        return band(self.cvss)

    def priority(self, cfg: Config) -> float:
        """FR-5. A missing CVSS or EPSS counts as 0, so unscored CVEs never rank high by accident."""
        w = cfg.priority
        return 100 * (w.cvss * (self.cvss or 0) / 10 + w.epss * (self.epss or 0) + w.kev * self.kev)


def parse_nvd(cve_id: str, body: dict) -> CveInfo:
    """Prefer CVSS v3.1, then v4.0, then v3.0; within a version prefer NVD's own (Primary) score."""
    vulns = body.get("vulnerabilities") or []
    if not vulns:
        return CveInfo(cve_id, "pending")  # NVD has no record yet
    metrics = (vulns[0].get("cve") or {}).get("metrics") or {}
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0")):
        entries = metrics.get(key) or []
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        for m in entries:
            score = (m.get("cvssData") or {}).get("baseScore")
            if isinstance(score, (int, float)) and 0 <= score <= 10:
                return CveInfo(cve_id, "scored", float(score), version)
    return CveInfo(cve_id, "pending")  # record exists, analysis not done


class Enricher:
    def __init__(self, fetcher, cfg: Config, nvd_key: str | None, interval: float | None = None):
        self.fetcher = fetcher
        self.cfg = cfg
        self.e = cfg.enrich
        self.nvd_key = nvd_key or None
        self.interval = interval if interval is not None else (
            self.e.nvd_interval_seconds if self.nvd_key else self.e.nvd_interval_no_key)
        self.cache: dict[str, CveInfo] = {}
        self.nvd_down = False
        self.kev: set[str] | None = None
        self.kev_ok = True
        self.lookups = 0
        self._last = 0.0

    def _json(self, url: str, **kw) -> dict:
        result = self.fetcher.get(url, **kw)
        data = json.loads(result.content)
        if not isinstance(data, dict):
            raise ValueError("unexpected JSON")
        return data

    def _load_kev(self) -> set[str]:
        if self.kev is None:
            try:
                data = self._json(str(self.e.kev_url), max_bytes=self.cfg.collection.max_feed_bytes)
                self.kev = {v["cveID"] for v in data.get("vulnerabilities", []) if isinstance(v, dict) and "cveID" in v}
            except (FetchError, ValueError, KeyError) as e:
                log.warning("CISA KEV unavailable (%s); no Known Exploited badges this run", e)
                self.kev, self.kev_ok = set(), False
        return self.kev

    def _load_epss(self, ids: list[str]) -> dict[str, float]:
        scores: dict[str, float] = {}
        for i in range(0, len(ids), 100):
            batch = ",".join(ids[i:i + 100])
            try:
                data = self._json(f"{self.e.epss_url}?cve={batch}")
            except (FetchError, ValueError) as e:
                log.warning("FIRST EPSS unavailable (%s)", e)
                return scores
            for row in data.get("data", []):
                try:
                    value = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
                if 0 <= value <= 1:
                    scores[str(row.get("cve"))] = value
        return scores

    def _nvd(self, cve_id: str) -> CveInfo:
        if self.nvd_down or self.lookups >= self.e.max_lookups_per_run:
            return CveInfo(cve_id, "unavailable")
        wait = self.interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.lookups += 1
        headers = {"apiKey": self.nvd_key} if self.nvd_key else None
        try:
            return parse_nvd(cve_id, self._json(f"{self.e.nvd_url}?cveId={cve_id}", headers=headers))
        except HTTPStatusError as e:
            if e.status == 404:  # NVD does not know this CVE yet: pending, and NVD itself is fine
                return CveInfo(cve_id, "pending")
            log.warning("NVD unavailable (%s); remaining CVEs show 'Score unavailable'", e)
            self.nvd_down = True
            return CveInfo(cve_id, "unavailable")
        except (FetchError, ValueError) as e:
            # FR-9: print "Score unavailable" and continue; stop asking NVD for the rest of the run.
            log.warning("NVD unavailable (%s); remaining CVEs show 'Score unavailable'", e)
            self.nvd_down = True
            return CveInfo(cve_id, "unavailable")

    def lookup(self, cve_ids: Iterable[str]) -> dict[str, CveInfo]:
        """Look up each CVE once per run (cached). Order matters: lookups stop at the cap."""
        todo = [c for c in dict.fromkeys(cve_ids) if CVE_ID_RE.match(c) and c not in self.cache]
        if todo:
            kev = self._load_kev()
            epss = self._load_epss(todo)
            for cve_id in todo:
                info = self._nvd(cve_id)
                info.kev = cve_id in kev
                info.epss = epss.get(cve_id)
                self.cache[cve_id] = info
        return {c: self.cache[c] for c in cve_ids if c in self.cache}
