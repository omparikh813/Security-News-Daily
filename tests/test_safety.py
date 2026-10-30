"""SR-1, SR-2, SR-6 unit tests."""

from __future__ import annotations

import socket

import pytest

from malnews import safety
from malnews.safety import (
    BlockedURL, FetchError, InvalidOutput, SafeFetcher, canonical_url, clean_text,
    extract_cves, safe_href, validate_ai_output,
)

FIELDS = {"summary": (600, False), "mitigation": (300, True)}
SOURCE = "Northwind fixed CVE-2026-90011 in version 8.4.2."


# --- CVE regex (FR-7) -------------------------------------------------------

def test_cve_regex_extracts_and_normalizes():
    assert extract_cves("cve-2026-1234 and CVE-2026-123456, not CVE-26-1") == {"CVE-2026-1234", "CVE-2026-123456"}


# --- links (SR-2) -----------------------------------------------------------

@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd", "ftp://x.com/a",
    "https://user:pw@example.com/", "https://example.com:8443/", "https://exa mple.com/",
    "https://localhost/", "https://example.com/‮", "", None,
])
def test_safe_href_rejects(url):
    assert safe_href(url) is None


def test_safe_href_upgrades_http():
    assert safe_href("http://Example.com/a?b=1") == "https://example.com/a?b=1"


def test_canonical_url_drops_tracking():
    assert canonical_url("https://www.x.com/a/?utm_source=feed&id=2#c") == "https://x.com/a?id=2"


def test_clean_text_strips_tags_and_bidi():
    assert clean_text("<p>Hi &amp; <b>bye</b>‮</p>") == "Hi & bye"


# --- AI output (SR-1) -------------------------------------------------------

def test_valid_output_with_fences_and_prose():
    raw = 'Sure!\n```json\n{"summary": "Northwind fixed CVE-2026-90011.", "mitigation": null}\n```'
    assert validate_ai_output(raw, SOURCE, FIELDS) == {"summary": "Northwind fixed CVE-2026-90011.", "mitigation": None}


@pytest.mark.parametrize("raw, reason", [
    ('{"summary": "See https://evil.example/x", "mitigation": null}', "URL"),
    ('{"summary": "Download the fix from evil-updates.com now.", "mitigation": null}', "URL"),
    ('{"summary": "Visit www.example.org", "mitigation": null}', "URL"),
    ('{"summary": "Click <a href=x>here</a>", "mitigation": null}', "HTML"),
    ('{"summary": "Read [this](x)", "mitigation": null}', "HTML"),
    ('{"summary": "Also CVE-2025-0001 is bad.", "mitigation": null}', "CVEs not in the source"),
    ('{"summary": "ok", "mitigation": null, "link": "x"}', "unexpected keys"),
    ('{"summary": "ok"}', "unexpected keys"),
    ('{"summary": 5, "mitigation": null}', "not a string"),
    ('{"summary": "' + "a" * 601 + '", "mitigation": null}', "longer than"),
    ('{"summary": "", "mitigation": null}', "empty"),
    ("no json here", "no JSON"),
])
def test_invalid_output_rejected(raw, reason):
    with pytest.raises(InvalidOutput, match=reason):
        validate_ai_output(raw, SOURCE, FIELDS)


# --- outbound fetching (SR-6) -----------------------------------------------

@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254",
                                "100.64.0.1", "::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0"])
def test_non_public_ips_blocked(ip):
    assert not safety.is_public_ip(ip)


def _fetcher(session=None):
    return SafeFetcher(user_agent="MalNewsBot/1.0 test", timeout=1, retries=0, max_redirects=3,
                       max_bytes={"feed": 100, "html": 100, "robots": 100, "image": 100}, session=session)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://localhost/",
    "http://metadata.google.internal/", "file:///etc/passwd", "gopher://x.com/",
    "http://user:pw@x.com/", "http://x.com:2375/", "http://[::1]/",
])
def test_fetcher_blocks_before_connecting(url, no_network):
    with pytest.raises(BlockedURL):
        _fetcher().get(url, "html")


def test_fetcher_blocks_hostnames_resolving_private(monkeypatch, no_network):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 80))])
    with pytest.raises(BlockedURL, match="non-public"):
        _fetcher().get("https://innocent.example.com/", "html")


def test_connection_level_guard_stops_dns_rebinding(monkeypatch, no_network):
    """Even if the pre-check passed, the socket only connects to a re-validated address."""
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    conn = safety._GuardedHTTPSConnection("rebind.example.com", 443)
    with pytest.raises(BlockedURL):
        conn._new_conn()


class FakeResp:
    def __init__(self, status=200, headers=None, chunks=(b"<html></html>",)):
        self.status_code = status
        self.headers = {"content-type": "text/html", **(headers or {})}
        self.is_redirect = status in (301, 302, 303, 307, 308)
        self._chunks = chunks

    def iter_content(self, n):
        yield from self._chunks

    def close(self):
        pass


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.headers = {}
        self.urls = []

    def get(self, url, **kw):
        assert kw["allow_redirects"] is False and kw["stream"] is True
        self.urls.append(url)
        return self.responses.pop(0)


@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.215.14", 443))])


def test_redirect_to_metadata_service_blocked(public_dns):
    session = FakeSession([FakeResp(302, {"location": "http://169.254.169.254/latest/meta-data/"})])
    with pytest.raises(BlockedURL):
        _fetcher(session).get("https://news.example.com/a", "html")
    assert session.urls == ["https://news.example.com/a"]  # never requested the internal URL


def test_too_many_redirects(public_dns):
    session = FakeSession([FakeResp(302, {"location": f"/r{i}"}) for i in range(5)])
    with pytest.raises(FetchError, match="redirects"):
        _fetcher(session).get("https://news.example.com/a", "html")


def test_oversized_response_rejected(public_dns):
    session = FakeSession([FakeResp(chunks=[b"x" * 60, b"x" * 60])])
    with pytest.raises(FetchError, match="larger than"):
        _fetcher(session).get("https://news.example.com/a", "html")


def test_declared_oversize_rejected(public_dns):
    session = FakeSession([FakeResp(headers={"content-length": "999999"})])
    with pytest.raises(FetchError, match="larger than"):
        _fetcher(session).get("https://news.example.com/a", "html")


def test_wrong_content_type_rejected(public_dns):
    session = FakeSession([FakeResp(headers={"content-type": "application/x-msdownload"})])
    with pytest.raises(FetchError, match="Content-Type"):
        _fetcher(session).get("https://news.example.com/a", "html")
