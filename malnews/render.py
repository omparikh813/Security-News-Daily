"""Stage 5: HTML/CSS to PDF with WeasyPrint (FR-17, FR-18, SR-2)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from weasyprint import HTML

from .enrich import CVE_ID_RE, CveInfo
from .models import Story
from .rank import similar_titles
from .safety import RenderURLFetcher, safe_href
from .settings import Config
from .state import StoryOfWeek, StoryRecord, WeeklyContent

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


def _words(*texts: str | None) -> int:
    return sum(len(re.findall(r"\S+", t or "")) for t in texts)


def _cve_view(i: CveInfo) -> dict | None:
    if not CVE_ID_RE.match(i.id):
        return None
    return {
        "id": i.id,
        # FR-8: link both records; the ID is regex-checked, so it is safe in a URL.
        "cve_url": f"https://www.cve.org/CVERecord?id={i.id}",
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{i.id}",
        "score": f"{i.cvss:.1f}" if i.cvss is not None else None,
        "band": i.band,
        "status": i.status,
        "kev": i.kev,
        "epss": f"{i.epss:.0%}" if i.epss is not None else None,
    }


def _cve_views(infos: list[CveInfo]) -> list[dict]:
    return [v for i in infos if (v := _cve_view(i))]


def _top_band(cves: list[dict]) -> dict | None:
    scored = [c for c in cves if c["score"] is not None]
    return max(scored, key=lambda c: float(c["score"]), default=None)


def _links(pairs) -> list[tuple[str, str]]:
    # Links come only from feed metadata, re-checked here (SR-2).
    return [(p, h) for p, u in pairs if (h := safe_href(u))]


def _view(title, summary, mitigation, links, cves) -> dict:
    return {
        "title": title, "summary": summary or "", "mitigation": mitigation,
        "links": _links(links), "cves": cves, "top": _top_band(cves), "kev": any(c["kev"] for c in cves),
        "words": _words(title, summary, mitigation) + 2 * len(links) + 4 * len(cves),
    }


def story_view(s: Story) -> dict:
    sm = s.summary
    return _view(s.title, sm.summary if sm else "", sm.mitigation if sm else None, s.links, _cve_views(s.cve_infos))


def _record_cves(record: StoryRecord, infos: dict[str, CveInfo], cfg: Config) -> list[dict]:
    found = sorted((infos[c] for c in record.cves if c in infos), key=lambda i: -i.priority(cfg))
    return _cve_views(found[: cfg.enrich.max_cves_per_story])


def usable(content: WeeklyContent | None) -> bool:
    """AI-written Story of the Week content (older state files may hold an excerpt instead)."""
    return content is not None and not content.is_excerpt


def record_summary(record: StoryRecord, content: WeeklyContent | None = None) -> str | None:
    """The AI summary for a stored story, if there is one."""
    return record.summary or (content.what_happened if usable(content) else None)


def record_view(record: StoryRecord, infos: dict[str, CveInfo], cfg: Config, summary: str) -> dict:
    return _view(record.title, summary, None, [(lk.publisher, lk.url) for lk in record.links],
                 _record_cves(record, infos, cfg))


def weekly_view(sw: StoryOfWeek, infos: dict[str, CveInfo], cfg: Config) -> dict:
    """Only called when sw.content is usable() AI content."""
    content = sw.content
    v = record_view(sw.story, infos, cfg, content.what_happened)
    v.update({
        "parts": [(label, text) for label, text in (
            ("What happened", content.what_happened), ("Who is affected", content.who_affected),
            ("What changed", content.what_changed), ("Fix", content.mitigation)) if text],
        "updated": f"Updated {sw.updated_on:%A}" if sw.updated_on else None,
    })
    v["words"] = _words(v["title"], *(t for _, t in v["parts"])) + 2 * len(v["links"]) + 4 * len(v["cves"])
    return v


def same_event(s: Story, record: StoryRecord, cfg: Config) -> bool:
    return s.id == record.id or bool(s.cves & set(record.cves)) or similar_titles(s.title, record.title, cfg)


def sections(stories: list[Story], sotw: StoryRecord | None, cfg: Config) -> tuple[list, list, list]:
    """FR-17 order: (News of the Day, New Threats, Other Headlines). Each story appears once."""
    remaining = [s for s in stories if not (sotw and same_event(s, sotw, cfg))]
    n = cfg.ranking.news_of_the_day
    top, rest = remaining[:n], remaining[n:]
    return top, [s for s in rest if s.zero_day], [s for s in rest if not s.zero_day]


FIXED_WORDS = 150  # masthead, section headings, footer


@dataclass
class Edition:
    context: dict
    words: int
    dropped: int


def build_edition(stories: list[Story], cfg: Config, now: datetime, source_names: list[str],
                  sotw: StoryOfWeek | None = None, replaced: StoryRecord | None = None,
                  infos: dict[str, CveInfo] | None = None, replaced_summary: str | None = None) -> Edition:
    """Story of the Week, News of the Day, New Threats, Other Headlines; trimmed to the word budget.

    Every story shown has an AI summary: stories without one are left out.
    """
    infos = infos or {}
    stories = [s for s in stories if s.summary]
    top, threats, others = sections(stories, sotw.story if sotw else None, cfg)
    weekly = weekly_view(sotw, infos, cfg) if sotw and usable(sotw.content) else None
    top_v, threat_v = [story_view(s) for s in top], [story_view(s) for s in threats]
    # FR-15: the replaced pick moves to Other Headlines on the day it is replaced.
    replaced_v = [record_view(replaced, infos, cfg, replaced_summary)] if replaced and replaced_summary else []
    other_v = replaced_v + [story_view(s) for s in others]

    words = FIXED_WORDS + sum(v["words"] for v in (*top_v, *threat_v, *other_v)) + (weekly["words"] if weekly else 0)
    dropped = 0
    while other_v and words > cfg.layout.max_words:  # drop lowest-ranked headlines first
        words -= other_v.pop()["words"]
        dropped += 1

    local = now.astimezone(timezone(timedelta(hours=cfg.edition.utc_offset_hours)))
    edition_no = max((local.date() - cfg.edition.launch_date).days + 1, 1)
    context = {
        "date_long": f"{local:%A, %B} {local.day}, {local.year}",
        "edition": edition_no,
        "read_minutes": max(1, math.ceil(words / cfg.layout.words_per_minute)),
        "generated": f"{local:%I:%M %p} PST".lstrip("0"),
        "story_of_week": weekly,
        "news_of_the_day": top_v,
        "new_threats": threat_v,
        "headlines": other_v,
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
