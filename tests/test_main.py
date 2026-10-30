"""End to end with the network and model replaced, plus key protection (SR-5)."""

from __future__ import annotations

import io
import logging
import re
import subprocess
from datetime import datetime, timedelta, timezone

import pypdf
import pytest

import main
from malnews.errors import RateLimitStop

from .conftest import ROOT, FakeFetcher, rss

KEY = "sk-or-v1-test-key-0123456789"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")  # skip .env loading
    monkeypatch.setenv("OPENROUTER_API_KEY", KEY)
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)


@pytest.fixture
def fake_world(monkeypatch):
    """Feeds from FakeFetcher; a model that answers with fixed JSON."""
    now = datetime.now(timezone.utc)
    pages = {
        "https://www.cisa.gov/cybersecurity-advisories/all.xml": rss(
            ("Vendor flaw CVE-2026-1111 exploited", "https://www.cisa.gov/a", now - timedelta(hours=1), "Advisory.")),
        "https://krebsonsecurity.com/feed/": rss(
            ("Data broker breach exposes records", "https://krebsonsecurity.com/b", now - timedelta(hours=2), "Breach.")),
    }

    class Model:
        def __init__(self, **kw):
            assert kw["api_key"] == KEY

        def complete(self, system, user):
            return '{"summary": "A short summary.", "mitigation": "Patch it."}'

    monkeypatch.setattr(main, "SafeFetcher", lambda **kw: FakeFetcher(pages))
    monkeypatch.setattr(main, "OpenRouterClient", Model)
    return Model


def test_full_run_writes_site(tmp_path, env, fake_world, no_network):
    assert main.main([], out_dir=tmp_path) == 0
    pdf = (tmp_path / "latest.pdf").read_bytes()
    assert len(list((tmp_path / "archive").glob("*.pdf"))) == 1 and len(pdf) < 1_000_000
    text = " ".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)
    assert "A short summary." in text and "Patch it." in text
    index = (tmp_path / "index.html").read_text()
    assert "default-src 'none'" in index and "<script" not in index


def test_429_publishes_nothing(tmp_path, env, fake_world, monkeypatch, no_network):
    def limited(self, system, user):
        raise RateLimitStop("429")

    monkeypatch.setattr(fake_world, "complete", limited)
    assert main.main([], out_dir=tmp_path / "site") == 3
    assert not (tmp_path / "site").exists()


def test_missing_key_exits_before_network(tmp_path, env, monkeypatch, no_network):
    monkeypatch.delenv("OPENROUTER_API_KEY")
    assert main.main([], out_dir=tmp_path) == 2


def test_disallowed_model_exits_before_network(tmp_path, env, monkeypatch, no_network):
    monkeypatch.setenv("OPENROUTER_MODEL", "some/other-model")
    assert main.main([], out_dir=tmp_path) == 2


def test_keys_redacted_from_logs(env):
    rec = logging.LogRecord("x", logging.ERROR, "", 0, "request failed: Bearer %s", (KEY,), None)
    main.RedactSecrets().filter(rec)
    assert KEY not in rec.getMessage() and "[REDACTED]" in rec.getMessage()


def test_dotenv_is_git_ignored():
    out = subprocess.run(["git", "check-ignore", ".env"], cwd=ROOT, capture_output=True, text=True)
    assert out.stdout.strip() == ".env"


# Real OpenRouter keys are "sk-or-v1-" plus 64 hex characters. The fake KEY above does not match.
REAL_KEY_RE = re.compile(r"sk-or-v1-[0-9a-f]{64}")


def test_no_real_keys_committed():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    for name in files:
        path = ROOT / name
        if path.is_file() and path.suffix not in (".ttf", ".pdf"):
            assert not REAL_KEY_RE.search(path.read_text(errors="ignore")), name
