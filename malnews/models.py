"""Data passed between pipeline stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .enrich import CveInfo


@dataclass
class Article:
    source: str
    tier: str  # "official" or "news"
    title: str
    url: str  # https, validated by safety.safe_href
    published: datetime  # timezone-aware UTC
    excerpt: str
    text: str
    text_is_excerpt: bool
    cves: set[str] = field(default_factory=set)


@dataclass
class Summary:
    summary: str
    mitigation: str | None
    is_excerpt: bool


@dataclass
class Story:
    articles: list[Article]
    score: float = 0.0
    priority: float = 0.0  # FR-5: highest priority among the story's CVEs
    impact: bool = False
    zero_day: bool = False  # FR-10
    cve_infos: list[CveInfo] = field(default_factory=list)  # highest priority first
    summary: Summary | None = None

    @property
    def kev(self) -> bool:
        return any(i.kev for i in self.cve_infos)

    @property
    def id(self) -> str:
        """Stable identity across runs: the primary article's URL."""
        return self.primary.url

    @property
    def primary(self) -> Article:
        """The article to summarize: official first, then full text over excerpt, then longest."""
        return max(
            self.articles,
            key=lambda a: (a.tier == "official", not a.text_is_excerpt, len(a.text)),
        )

    @property
    def title(self) -> str:
        return self.primary.title

    @property
    def publishers(self) -> list[str]:
        return sorted({a.source for a in self.articles})

    @property
    def cves(self) -> set[str]:
        return set().union(*(a.cves for a in self.articles))

    @property
    def latest(self) -> datetime:
        return max(a.published for a in self.articles)

    @property
    def links(self) -> list[tuple[str, str]]:
        """(publisher, url) for every source article, de-duplicated, in source order."""
        seen: set[str] = set()
        out = []
        for a in sorted(self.articles, key=lambda a: (a.tier != "official", a.source)):
            if a.url not in seen:
                seen.add(a.url)
                out.append((a.source, a.url))
        return out
