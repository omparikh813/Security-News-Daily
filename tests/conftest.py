from __future__ import annotations

import socket
import sys
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from malnews.models import Article  # noqa: E402
from malnews.safety import FetchResult, HTTPStatusError  # noqa: E402
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


def rss(*items: tuple[str, str, datetime, str]) -> bytes:
    """Build a small RSS feed from (title, link, published, description) tuples."""
    body = "".join(
        f"<item><title>{t}</title><link>{link}</link><pubDate>{format_datetime(p)}</pubDate>"
        f"<description>{d}</description></item>"
        for t, link, p, d in items
    )
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>{body}</channel></rss>'.encode()


class FakeFetcher:
    """Serves bytes by URL; anything else is a 404, like a missing page."""

    def __init__(self, pages: dict[str, bytes]):
        self.pages = pages
        self.requested: list[str] = []

    def get(self, url: str) -> FetchResult:
        self.requested.append(url)
        if url not in self.pages:
            raise HTTPStatusError(404, url)
        return FetchResult(url, self.pages[url])
