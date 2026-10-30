from __future__ import annotations

import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from malnews.models import Article  # noqa: E402
from malnews.settings import load_config, load_sources  # noqa: E402

NOW = datetime(2026, 10, 30, 14, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="session")
def cfg():
    return load_config(ROOT / "config.yaml")


@pytest.fixture(scope="session")
def sources():
    return load_sources(ROOT / "sources.yaml")


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if anything opens a network connection."""

    def guard(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket, "create_connection", guard)


def make_article(title="Title of a story here", source="BleepingComputer", tier="news",
                 url="https://example.com/a", text="Body text.", cves=(), published=NOW):
    return Article(source=source, tier=tier, title=title, url=url, published=published,
                   excerpt=text, text=text, text_is_excerpt=False, cves=set(cves))
