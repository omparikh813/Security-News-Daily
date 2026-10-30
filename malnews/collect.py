"""Stage 1: feeds, article text, CVE IDs (FR-1 to FR-3, FR-7)."""

from __future__ import annotations

import calendar
import logging
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import feedparser
import trafilatura

from .errors import AllSourcesFailed
from .models import Article
from .safety import FetchError, HTTPStatusError, RobotsCache, clean_text, extract_cves, safe_href
from .settings import Config, Source

log = logging.getLogger(__name__)

MAX_EXCERPT_CHARS = 2000
MAX_ITEMS_PER_FEED = 100


@dataclass
class CollectReport:
    ok: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    articles: int = 0
    full_text: int = 0


def _entry_time(entry) -> datetime | None:
    """The later of published and updated (FR-2)."""
    with warnings.catch_warnings():  # feedparser warns when it maps updated -> published
        warnings.simplefilter("ignore", DeprecationWarning)
        stamps = [entry.get("published_parsed"), entry.get("updated_parsed")]
    times = [datetime.fromtimestamp(calendar.timegm(t), tz=timezone.utc) for t in stamps if t]
    return max(times) if times else None


def _article_text(url: str, fetcher, robots: RobotsCache, max_chars: int, refused: set[str]) -> str | None:
    host = urlsplit(url).hostname or ""
    if host in refused or not robots.allowed(url):
        return None
    try:
        page = fetcher.get(url)
    except HTTPStatusError as e:
        if e.status in (403, 429):  # rate-limited or bot-blocked: leave this site alone for the run
            refused.add(host)
            log.warning("%s returned HTTP %d; using feed excerpts for its other articles", host, e.status)
        else:
            log.info("article fetch failed, using excerpt: %s", e)
        return None
    except FetchError as e:
        log.info("article fetch failed, using excerpt: %s", e)
        return None
    text = trafilatura.extract(
        page.content.decode("utf-8", "replace"),
        include_comments=False, include_tables=False, include_links=False, include_images=False,
    )
    text = clean_text(text, max_chars)
    return text or None


def collect_source(source: Source, fetcher, robots: RobotsCache, now: datetime, cfg: Config,
                   refused: set[str]) -> list[Article]:
    result = fetcher.get(str(source.url), max_bytes=cfg.collection.max_feed_bytes)
    feed = feedparser.parse(result.content)  # parses bytes only; never fetches by itself
    if not feed.entries:
        raise FetchError(f"no entries ({feed.get('bozo_exception', 'empty feed')})")

    oldest = now - timedelta(hours=cfg.collection.window_hours)
    articles = []
    for entry in feed.entries[:MAX_ITEMS_PER_FEED]:
        published = _entry_time(entry)
        if published is None or not (oldest <= published <= now + timedelta(hours=1)):
            continue
        url = safe_href(entry.get("link"))
        title = clean_text(entry.get("title"), 300)
        if not url or not title:
            log.info("skipping item with unsafe link or no title from %s", source.name)
            continue
        excerpt = clean_text(entry.get("summary"), MAX_EXCERPT_CHARS)
        text = _article_text(url, fetcher, robots, cfg.collection.max_article_chars, refused)
        articles.append(Article(
            source=source.name,
            tier=source.tier,
            title=title,
            url=url,
            published=published,
            excerpt=excerpt,
            text=text or excerpt,
            text_is_excerpt=text is None,
            cves=extract_cves(" ".join((title, excerpt, text or ""))),
        ))
    return articles


def collect(sources: list[Source], fetcher, now: datetime, cfg: Config) -> tuple[list[Article], CollectReport]:
    robots = RobotsCache(fetcher, cfg.collection.user_agent)
    refused: set[str] = set()
    report = CollectReport()
    articles: list[Article] = []
    for source in sources:
        try:
            items = collect_source(source, fetcher, robots, now, cfg, refused)
        except (FetchError, ValueError) as e:  # FR-3: log and skip
            log.warning("source %s failed: %s", source.name, e)
            report.failed.append(source.name)
            continue
        report.ok.append(source.name)
        articles.extend(items)
    if not report.ok:
        raise AllSourcesFailed("every source failed")
    report.articles = len(articles)
    report.full_text = sum(not a.text_is_excerpt for a in articles)
    return articles, report
