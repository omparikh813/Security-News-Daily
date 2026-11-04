"""FR-5, FR-7 to FR-9: NVD, CISA KEV and FIRST EPSS enrichment."""

from __future__ import annotations

import json

import pytest

from malnews.enrich import CveInfo, Enricher, band, parse_nvd
from malnews.safety import FetchResult, HTTPStatusError

from .conftest import FakeFetcher

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"


def nvd_body(**metrics) -> dict:
    return {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001", "metrics": metrics}}]}


def metric(score, kind="Primary", source="nvd@nist.gov"):
    return {"source": source, "type": kind, "cvssData": {"baseScore": score}}


# --- parsing (FR-7) -------------------------------------------------------------

def test_prefers_v31_primary():
    body = nvd_body(cvssMetricV31=[metric(7.5, "Secondary", "vendor"), metric(9.8)], cvssMetricV40=[metric(6.0)])
    info = parse_nvd("CVE-2026-0001", body)
    assert (info.status, info.cvss, info.cvss_version) == ("scored", 9.8, "3.1")


def test_falls_back_to_v40_then_v30():
    assert parse_nvd("CVE-2026-0001", nvd_body(cvssMetricV40=[metric(8.7)])).cvss_version == "4.0"
    assert parse_nvd("CVE-2026-0001", nvd_body(cvssMetricV30=[metric(5.3)])).cvss == 5.3


def test_secondary_used_when_no_primary():
    assert parse_nvd("CVE-2026-0001", nvd_body(cvssMetricV31=[metric(8.1, "Secondary", "vendor")])).cvss == 8.1


@pytest.mark.parametrize("body", [
    {"totalResults": 0, "vulnerabilities": []},  # not in NVD yet
    nvd_body(),  # record exists, awaiting analysis
    nvd_body(cvssMetricV31=[metric("9.8")]),  # wrong type is ignored
    nvd_body(cvssMetricV31=[metric(11.0)]),  # out of range is ignored
])
def test_pending_when_no_usable_score(body):
    info = parse_nvd("CVE-2026-0001", body)
    assert info.status == "pending" and info.cvss is None


# --- bands and priority (FR-5, FR-8) -------------------------------------------

@pytest.mark.parametrize("score, name", [
    (10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"), (6.9, "Medium"),
    (4.0, "Medium"), (3.9, "Low"), (0.1, "Low"), (0.0, "None"), (None, None),
])
def test_bands(score, name):
    assert band(score) == name


def test_priority_formula(cfg):
    info = CveInfo("CVE-2026-0001", "scored", cvss=9.8, kev=True, epss=0.5)
    assert info.priority(cfg) == pytest.approx(100 * (0.35 * 0.98 + 0.35 * 0.5 + 0.30))


def test_missing_values_count_as_zero(cfg):
    assert CveInfo("CVE-2026-0001", "pending").priority(cfg) == 0
    assert CveInfo("CVE-2026-0001", "pending", kev=True).priority(cfg) == pytest.approx(30)


# --- the Enricher ----------------------------------------------------------------

def world(**nvd) -> FakeFetcher:
    pages = {
        KEV: json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}).encode(),
        f"{EPSS}?cve=CVE-2026-0001,CVE-2026-0002": json.dumps(
            {"data": [{"cve": "CVE-2026-0001", "epss": "0.91"}, {"cve": "CVE-2026-0002", "epss": "oops"}]}).encode(),
    }
    for cve, body in nvd.items():
        pages[f"{NVD}?cveId={cve.replace('_', '-')}"] = body if isinstance(body, int) else json.dumps(body).encode()
    return FakeFetcher(pages)


def test_enrich_combines_sources(cfg):
    f = world(CVE_2026_0001=nvd_body(cvssMetricV31=[metric(9.8)]), CVE_2026_0002={"vulnerabilities": []})
    infos = Enricher(f, cfg, "nvd-key", interval=0).lookup(["CVE-2026-0001", "CVE-2026-0002"])
    one, two = infos["CVE-2026-0001"], infos["CVE-2026-0002"]
    assert (one.cvss, one.kev, one.epss, one.band) == (9.8, True, 0.91, "Critical")
    assert (two.status, two.kev, two.epss) == ("pending", False, None)


def test_nvd_key_goes_only_to_nvd(cfg):
    f = world(CVE_2026_0001=nvd_body(cvssMetricV31=[metric(9.8)]), CVE_2026_0002={"vulnerabilities": []})
    Enricher(f, cfg, "nvd-key", interval=0).lookup(["CVE-2026-0001", "CVE-2026-0002"])
    for url, headers in f.headers.items():
        if url.startswith(NVD):
            assert headers == {"apiKey": "nvd-key"}
        else:
            assert not headers, url


def test_no_key_sends_no_header(cfg):
    f = world(CVE_2026_0001=nvd_body(cvssMetricV31=[metric(9.8)]))
    Enricher(f, cfg, None, interval=0).lookup(["CVE-2026-0001"])
    assert f.headers[f"{NVD}?cveId=CVE-2026-0001"] is None


def test_cached_per_run(cfg):
    f = world(CVE_2026_0001=nvd_body(cvssMetricV31=[metric(9.8)]))
    e = Enricher(f, cfg, "k", interval=0)
    e.lookup(["CVE-2026-0001"])
    before = len(f.requested)
    e.lookup(["CVE-2026-0001"])
    assert len(f.requested) == before and e.lookups == 1


def test_nvd_down_marks_unavailable_and_stops_asking(cfg):
    f = world(CVE_2026_0001=503, CVE_2026_0002=nvd_body(cvssMetricV31=[metric(5.0)]))
    e = Enricher(f, cfg, "k", interval=0)
    infos = e.lookup(["CVE-2026-0001", "CVE-2026-0002"])
    assert infos["CVE-2026-0001"].status == infos["CVE-2026-0002"].status == "unavailable"
    assert e.nvd_down and not any("CVE-2026-0002" in u and u.startswith(NVD) for u in f.requested)
    assert infos["CVE-2026-0001"].kev  # KEV still applies


def test_unknown_cve_404_is_pending_not_an_outage(cfg):
    f = world(CVE_2026_0001=404, CVE_2026_0002=nvd_body(cvssMetricV31=[metric(5.0)]))
    e = Enricher(f, cfg, "k", interval=0)
    infos = e.lookup(["CVE-2026-0001", "CVE-2026-0002"])
    assert infos["CVE-2026-0001"].status == "pending" and infos["CVE-2026-0002"].cvss == 5.0
    assert not e.nvd_down


def test_lookup_cap(cfg):
    f = world(CVE_2026_0001=nvd_body(cvssMetricV31=[metric(9.8)]))
    e = Enricher(f, cfg, "k", interval=0)
    e.lookups = cfg.enrich.max_lookups_per_run
    assert e.lookup(["CVE-2026-0001"])["CVE-2026-0001"].status == "unavailable"


def test_kev_down_is_not_fatal(cfg):
    f = world(CVE_2026_0001=nvd_body(cvssMetricV31=[metric(9.8)]))
    f.pages[KEV] = 500
    e = Enricher(f, cfg, "k", interval=0)
    info = e.lookup(["CVE-2026-0001"])["CVE-2026-0001"]
    assert info.cvss == 9.8 and not info.kev and not e.kev_ok


def test_invalid_ids_never_reach_a_url(cfg):
    f = FakeFetcher({})
    assert Enricher(f, cfg, "k", interval=0).lookup(["CVE-2026-1&apiKey=x", "../etc"]) == {}
    assert f.requested == []


def test_garbage_json_is_unavailable(cfg):
    f = world()
    f.pages[f"{NVD}?cveId=CVE-2026-0001"] = b"<html>maintenance</html>"
    assert Enricher(f, cfg, "k", interval=0).lookup(["CVE-2026-0001"])["CVE-2026-0001"].status == "unavailable"


def test_fake_fetcher_contract():
    assert isinstance(FakeFetcher({"u": b"x"}).get("u", headers={"a": "b"}), FetchResult)
    with pytest.raises(HTTPStatusError):
        FakeFetcher({}).get("missing")
