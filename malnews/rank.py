"""Stage 3: de-duplication and story scoring (FR-4, FR-6)."""

from __future__ import annotations

import re

from rapidfuzz import fuzz

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


def _norm_title(title: str) -> str:
    return re.sub(r"[^a-z0-9 ]+", " ", title.lower())


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

    titles = [_norm_title(a.title) for a in articles]
    long_enough = [len(t.split()) >= cfg.dedupe.min_title_tokens for t in titles]
    for i in range(len(articles)):
        for j in range(i + 1, len(articles)):
            if long_enough[i] and long_enough[j] and uf.find(i) != uf.find(j):
                if fuzz.token_set_ratio(titles[i], titles[j]) >= cfg.dedupe.title_similarity:
                    uf.union(i, j)

    groups: dict[int, list[Article]] = {}
    for i, a in enumerate(articles):
        groups.setdefault(uf.find(i), []).append(a)
    return [Story(articles=g) for g in groups.values()]


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


def rank(articles: list[Article], cfg: Config) -> list[Story]:
    stories = dedupe(articles, cfg)
    for s in stories:
        s.score = score(s, cfg)
    return sorted(stories, key=lambda s: (-s.score, -s.latest.timestamp(), s.title))
