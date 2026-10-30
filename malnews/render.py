"""Stage 5: HTML/CSS to PDF with WeasyPrint (FR-17, FR-18, SR-2)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from weasyprint import HTML

from .models import Story
from .safety import RenderURLFetcher, safe_href
from .settings import Config

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
FONTS = ROOT / "fonts"


def jinja_env() -> Environment:
    # SR-2: autoescape everything. Templates never use |safe on external data.
    return Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _words(text: str | None) -> int:
    return len(re.findall(r"\S+", text or ""))


def _story_words(s: Story) -> int:
    summary = s.summary
    return _words(s.title) + _words(summary.summary if summary else "") + _words(
        summary.mitigation if summary else ""
    ) + 2 * len(s.links)


def _story_view(s: Story) -> dict:
    return {
        "title": s.title,
        "summary": s.summary.summary if s.summary else "",
        "mitigation": s.summary.mitigation if s.summary else None,
        "is_excerpt": bool(s.summary and s.summary.is_excerpt),
        # Links come only from feed metadata, re-checked here (SR-1, SR-2).
        "links": [(p, h) for p, u in s.links if (h := safe_href(u))],
    }


@dataclass
class Edition:
    context: dict
    words: int
    dropped: int


def build_edition(stories: list[Story], cfg: Config, now: datetime, source_names: list[str]) -> Edition:
    """FR-17: News of the Day, then Other Headlines, trimmed to the word budget."""
    n = cfg.ranking.news_of_the_day
    top, rest = stories[:n], list(stories[n:])
    fixed = 120  # masthead, section headings, footer
    words = fixed + sum(_story_words(s) for s in stories)
    dropped = 0
    while rest and words > cfg.layout.max_words:  # drop lowest-ranked headlines first
        words -= _story_words(rest.pop())
        dropped += 1

    local = now.astimezone(timezone(timedelta(hours=cfg.edition.utc_offset_hours)))
    edition_no = max((local.date() - cfg.edition.launch_date).days + 1, 1)
    context = {
        "date_long": f"{local:%A, %B} {local.day}, {local.year}",
        "edition": edition_no,
        "read_minutes": max(1, math.ceil(words / cfg.layout.words_per_minute)),
        "generated": f"{local:%I:%M %p} PST".lstrip("0"),
        "news_of_the_day": [_story_view(s) for s in top],
        "headlines": [_story_view(s) for s in rest],
        "sources": source_names,
    }
    return Edition(context, words, dropped)


@dataclass
class RenderResult:
    pdf: bytes
    blocked: list[str]


def render_html_to_pdf(html: str) -> RenderResult:
    """Render with a fetcher that can only read templates/ and fonts/ (SR-2)."""
    fetcher = RenderURLFetcher([TEMPLATES, FONTS])
    doc = HTML(string=html, base_url=str(TEMPLATES) + "/", url_fetcher=fetcher).render()
    meta = doc.metadata
    meta.attachments = []  # never embed files, whatever the HTML asks for
    meta.authors, meta.keywords, meta.description = [], [], None
    meta.generator = None
    meta.custom = {}
    return RenderResult(doc.write_pdf(), fetcher.blocked)


def render_pdf(edition: Edition) -> RenderResult:
    html = jinja_env().get_template("edition.html.j2").render(**edition.context)
    return render_html_to_pdf(html)
