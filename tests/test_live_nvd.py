"""Phase 2 acceptance: 10 sample CVEs match NVD exactly. Needs internet; skipped by default.

    pytest -m live -s

Uses NVD_API_KEY from .env if present (faster). Compares what MalNews prints
against NVD's own record for each CVE, fetched separately.
"""

from __future__ import annotations

import os

import pytest
import requests

from malnews.enrich import Enricher
from malnews.safety import SafeFetcher

from .conftest import ROOT

pytestmark = pytest.mark.live

SAMPLES = [
    "CVE-2021-44228",  # Log4Shell
    "CVE-2023-4966",   # Citrix Bleed
    "CVE-2024-3400",   # PAN-OS GlobalProtect
    "CVE-2023-34362",  # MOVEit Transfer
    "CVE-2024-6387",   # regreSSHion
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2024-3094",   # xz backdoor
    "CVE-2023-20198",  # Cisco IOS XE
    "CVE-2022-30190",  # Follina
    "CVE-2021-26855",  # ProxyLogon
]


def nvd_reference(cve: str, key: str | None) -> float | None:
    """NVD's own Primary CVSS v3.1 score, read directly from the API."""
    headers = {"apiKey": key} if key else {}
    body = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve},
                        headers=headers, timeout=30).json()
    metrics = body["vulnerabilities"][0]["cve"]["metrics"]
    for m in metrics.get("cvssMetricV31", []):
        if m["type"] == "Primary":
            return m["cvssData"]["baseScore"]
    return None


def test_ten_cves_match_nvd(cfg):
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
    key = os.environ.get("NVD_API_KEY", "").strip() or None
    c = cfg.collection
    fetcher = SafeFetcher(user_agent=c.user_agent, timeout=30, retries=c.retries,
                          max_redirects=c.max_redirects, max_bytes=c.max_response_bytes)
    infos = Enricher(fetcher, cfg, key).lookup(SAMPLES)

    rows = []
    for cve in SAMPLES:
        info = infos[cve]
        expected = nvd_reference(cve, key)
        rows.append(f"{cve:16} MalNews {info.cvss!s:5} {info.band!s:9} KEV={info.kev!s:5} "
                    f"EPSS={info.epss}  NVD {expected}")
        assert info.status == "scored", cve
        if expected is not None:
            assert info.cvss == expected, cve
    print("\n" + "\n".join(rows))
    assert infos["CVE-2021-44228"].kev  # Log4Shell is in CISA KEV
