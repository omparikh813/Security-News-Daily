"""Stage 3: de-duplication, threat priority, story scoring, zero-day detection (FR-4 to FR-6, FR-10)."""

from __future__ import annotations

import re
from collections import Counter

from rapidfuzz import fuzz

from .enrich import CveInfo
from .models import Article, Story
from .safety import canonical_url
from .settings import Config


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def norm_title(title: str) -> str:
    return re.sub(r"[^a-z0-9 ]+", " ", title.lower())


def similar_titles(a: str, b: str, cfg: Config) -> bool:
    a, b = norm_title(a), norm_title(b)
    if min(len(a.split()), len(b.split())) < cfg.dedupe.min_title_tokens:
        return False
    return fuzz.token_set_ratio(a, b) >= cfg.dedupe.title_similarity


def dedupe(articles: list[Article], cfg: Config) -> list[Story]:
    """One story per event: shared CVE ID, then canonical URL, then title similarity."""
    uf = _UnionFind(len(articles))
    first_with: dict[str, int] = {}
    for i, a in enumerate(articles):
        for key in [*a.cves, "url:" + canonical_url(a.url)]:
            if key in first_with:
                uf.union(i, first_with[key])
            else:
                first_with[key] = i

    for i in range(len(articles)):
        for j in range(i + 1, len(articles)):
            if uf.find(i) != uf.find(j) and similar_titles(articles[i].title, articles[j].title, cfg):
                uf.union(i, j)

    groups: dict[int, list[Article]] = {}
    for i, a in enumerate(articles):
        groups.setdefault(uf.find(i), []).append(a)
    return [Story(articles=g) for g in groups.values()]


def cves_by_importance(stories: list[Story]) -> list[str]:
    """CVE lookup order: most widely reported first, so the lookup cap drops the least covered."""
    counts = Counter(c for s in stories for c in s.cves for _ in s.publishers)
    return [c for c, _ in counts.most_common()]


def _mentions(text: str, keywords: list[str]) -> bool:
    text = text.lower()
    return any(k.lower() in text for k in keywords)


def is_zero_day(story: Story, cfg: Config) -> bool:
    """FR-10: has a CVE, and an official source or two independent publishers call it a zero-day."""
    if not story.cves:
        return False
    keywords = cfg.zero_day.keywords
    saying = {a.source for a in story.articles if _mentions(f"{a.title} {a.text}", keywords)}
    official = any(a.tier == "official" and a.source in saying for a in story.articles)
    return official or len(saying) >= 2


def score(story: Story, cfg: Config) -> float:
    r = cfg.ranking
    weighted = sum(
        r.official_multiplier if any(a.tier == "official" for a in story.articles if a.source == p) else 1
        for p in story.publishers
    )
    haystack = " ".join(f"{a.title} {a.text}" for a in story.articles).lower()
    story.impact = any(re.search(rf"\b{re.escape(k.lower())}\b", haystack) for k in r.impact_keywords)
    return (
        r.publisher_weight * min(weighted / r.publisher_cap, 1)
        + r.priority_weight * (story.priority / 100)
        + r.impact_weight * story.impact
    )


def rank(stories: list[Story], cfg: Config, infos: dict[str, CveInfo] | None = None) -> list[Story]:
    infos = infos or {}
    for s in stories:
        found = sorted((infos[c] for c in s.cves if c in infos), key=lambda i: (-i.priority(cfg), i.id))
        s.cve_infos = found[: cfg.enrich.max_cves_per_story]
        s.priority = max((i.priority(cfg) for i in found), default=0.0)
        s.zero_day = is_zero_day(s, cfg)
        s.score = score(s, cfg)
    return sorted(stories, key=lambda s: (-s.score, -s.latest.timestamp(), s.title))
