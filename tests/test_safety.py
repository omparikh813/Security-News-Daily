"""SR-2 links and SR-6 outbound fetching."""

from __future__ import annotations

import socket

import pytest

from malnews.safety import (
    BlockedURL, FetchError, SafeFetcher, canonical_url, check_url, clean_text,
    extract_cves, is_public_ip, safe_href,
)


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


# --- outbound fetching (SR-6) -----------------------------------------------

@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254",
                                "100.64.0.1", "::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0"])
def test_non_public_ips(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://localhost/",
    "http://[::1]/", "file:///etc/passwd", "gopher://x.com/", "http://user:pw@x.com/",
])
def test_internal_and_odd_urls_blocked(url, no_network):
    with pytest.raises(BlockedURL):
        check_url(url)


def test_hostname_resolving_to_private_ip_blocked(monkeypatch, no_network):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 443))])
    with pytest.raises(BlockedURL, match="non-public"):
        check_url("https://innocent.example.com/")


class FakeResp:
    def __init__(self, status=200, headers=None, chunks=(b"ok",)):
        self.status_code = status
        self.headers = headers or {}
        self.is_redirect = status in (301, 302, 303, 307, 308)
        self._chunks = chunks

    def iter_content(self, n):
        yield from self._chunks

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []

    def get(self, url, **kw):
        assert kw["allow_redirects"] is False and kw["stream"] is True
        self.urls.append(url)
        return self.responses.pop(0)


def fetcher_with(responses):
    f = SafeFetcher(user_agent="MalNewsBot/1.0 test", timeout=1, retries=0, max_redirects=3, max_bytes=100)
    f.session = FakeSession(responses)
    return f


@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.215.14", 443))])


def test_fetch_ok(public_dns):
    assert fetcher_with([FakeResp()]).get("https://news.example.com/a").content == b"ok"


def test_redirect_to_metadata_service_blocked(public_dns):
    f = fetcher_with([FakeResp(302, {"location": "http://169.254.169.254/latest/meta-data/"})])
    with pytest.raises(BlockedURL):
        f.get("https://news.example.com/a")
    assert f.session.urls == ["https://news.example.com/a"]  # the internal URL was never requested


def test_too_many_redirects(public_dns):
    f = fetcher_with([FakeResp(302, {"location": f"/r{i}"}) for i in range(5)])
    with pytest.raises(FetchError, match="redirects"):
        f.get("https://news.example.com/a")


def test_oversized_response_rejected(public_dns):
    f = fetcher_with([FakeResp(chunks=[b"x" * 60, b"x" * 60])])
    with pytest.raises(FetchError, match="larger than"):
        f.get("https://news.example.com/a")


def test_tls_always_verified():
    f = SafeFetcher(user_agent="MalNewsBot/1.0 test", timeout=1, retries=0, max_redirects=3, max_bytes=100)
    assert f.session.verify is True and f.session.trust_env is False
