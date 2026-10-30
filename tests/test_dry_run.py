"""T2 end to end, the forced-429 acceptance check, and SR-5 fixture hygiene."""

from __future__ import annotations

import io
import re

import pypdf

import main

from .conftest import ROOT


def test_dry_run_builds_site(tmp_path, no_network):
    out = tmp_path / "site"
    assert main.main(["--dry-run", "--out", str(out)]) == 0
    pdf = (out / "latest.pdf").read_bytes()
    assert (out / "archive" / "2026-10-30.pdf").read_bytes() == pdf
    assert len(pdf) < 1_000_000

    reader = pypdf.PdfReader(io.BytesIO(pdf))
    text = " ".join(p.extract_text() for p in reader.pages)
    assert "News of the Day".upper() in text.upper()
    links = [str(a.get_object()["/A"]["/URI"]) for p in reader.pages for a in p.get("/Annots") or []]
    assert links and all(u.startswith("https://") for u in links)

    index = (out / "index.html").read_text()
    assert "default-src 'none'" in index and "<script" not in index
    assert "2026-10-30.pdf" in index


def test_forced_429_publishes_nothing(tmp_path, no_network):
    out = tmp_path / "site"
    assert main.main(["--dry-run", "--force-429", "--out", str(out)]) == 3
    assert not out.exists()


def test_forced_429_keeps_previous_edition(tmp_path, no_network):
    out = tmp_path / "site"
    assert main.main(["--dry-run", "--out", str(out)]) == 0
    before = (out / "latest.pdf").read_bytes()
    assert main.main(["--dry-run", "--force-429", "--out", str(out)]) == 3
    assert (out / "latest.pdf").read_bytes() == before


def test_bad_model_exits_before_network(monkeypatch, tmp_path, no_network):
    monkeypatch.setenv("OPENROUTER_MODEL", "some/other-model")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")  # skip .env loading
    assert main.main(["--out", str(tmp_path / "o")]) == 2


def test_secrets_redacted_from_logs(monkeypatch, caplog):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-supersecretvalue")
    f = main.RedactSecrets()
    import logging

    rec = logging.LogRecord("x", logging.INFO, "", 0, "key=%s", ("sk-or-v1-supersecretvalue",), None)
    f.filter(rec)
    assert "supersecret" not in rec.getMessage()


SECRET_PATTERNS = re.compile(rb"(sk-or-v1-[A-Za-z0-9]{8,}|Authorization:|Bearer [A-Za-z0-9]|apiKey=)", re.I)


def test_fixtures_contain_no_secrets():
    for path in (ROOT / "fixtures").rglob("*"):
        if path.is_file():
            assert not SECRET_PATTERNS.search(path.read_bytes()), path
