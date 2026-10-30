"""T1: collection, dedupe, scoring, summaries, 429 stop, request budget, model allowlist."""

from __future__ import annotations

from datetime import timedelta

import pytest

from malnews.collect import collect
from malnews.errors import AIAuthError, AllSourcesFailed, BudgetExceeded, ConfigError, RateLimitStop
from malnews.models import Story
from malnews.rank import dedupe, rank
from malnews.summarize import (
    OpenRouterClient, Summarizer, TransientAIError, excerpt_of, parse_summary, resolve_model,
)

from .conftest import NOW, FakeFetcher, make_article, rss

CISA = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
BC = "https://www.bleepingcomputer.com/feed/"


# --- collection (FR-2, FR-3, FR-7) --------------------------------------------

def test_collect(cfg, sources, no_network):
    fetcher = FakeFetcher({
        CISA: rss(
            ("Vendor flaw CVE-2026-1111 exploited", "https://www.cisa.gov/a", NOW - timedelta(hours=2), "Advisory text."),
            ("Old advisory", "https://www.cisa.gov/old", NOW - timedelta(hours=30), "Too old."),
        ),
        BC: rss(
            ("Unsafe link item", "javascript:alert(1)", NOW - timedelta(hours=1), "Skip me."),
            ("Ransomware hits hospital", "http://www.bleepingcomputer.com/b", NOW - timedelta(hours=3), "Excerpt."),
        ),
        "https://www.cisa.gov/a": b"<html><body><article><p>" + b"Full advisory text. " * 30 + b"</p></article></body></html>",
    })
    articles, report = collect(sources, fetcher, NOW, cfg)
    by_title = {a.title: a for a in articles}

    assert set(by_title) == {"Vendor flaw CVE-2026-1111 exploited", "Ransomware hits hospital"}
    assert report.ok == ["CISA", "BleepingComputer"] and len(report.failed) == 3  # FR-3: others skipped
    assert by_title["Vendor flaw CVE-2026-1111 exploited"].cves == {"CVE-2026-1111"}
    assert not by_title["Vendor flaw CVE-2026-1111 exploited"].text_is_excerpt
    assert by_title["Ransomware hits hospital"].text_is_excerpt  # article 404 -> feed excerpt
    assert by_title["Ransomware hits hospital"].url == "https://www.bleepingcomputer.com/b"


def test_feeds_get_the_larger_cap(cfg, sources, no_network):
    fetcher = FakeFetcher({CISA: rss(("A story title here", "https://www.cisa.gov/a", NOW, "x"))})
    collect(sources, fetcher, NOW, cfg)
    assert fetcher.caps[CISA] == cfg.collection.max_feed_bytes
    assert fetcher.caps["https://www.cisa.gov/a"] is None  # articles use the default 5 MB cap


def test_site_that_rate_limits_is_left_alone(cfg, sources, no_network):
    items = [(f"Story number {i} headline", f"https://www.bleepingcomputer.com/{i}", NOW - timedelta(hours=1), "Ex.")
             for i in range(4)]
    pages = {BC: rss(*items), "https://www.bleepingcomputer.com/0": 429}
    fetcher = FakeFetcher(pages)
    articles, _ = collect(sources, fetcher, NOW, cfg)
    assert len(articles) == 4 and all(a.text_is_excerpt for a in articles)
    article_hits = [u for u in fetcher.requested if u.startswith("https://www.bleepingcomputer.com/") and u[-1].isdigit()]
    assert article_hits == ["https://www.bleepingcomputer.com/0"]  # stopped after the first 429


def test_all_sources_failed(cfg, sources, no_network):
    with pytest.raises(AllSourcesFailed):
        collect(sources, FakeFetcher({}), NOW, cfg)


# --- dedupe and ranking (FR-4, FR-6) -------------------------------------------

def test_dedupe_by_cve_url_and_title(cfg):
    arts = [
        make_article("Vendor patches flaw", url="https://a.com/1", cves=["CVE-2026-1111"]),
        make_article("Different words entirely", url="https://b.com/2", cves=["CVE-2026-1111"], source="SecurityWeek"),
        make_article("Same link story", url="https://www.c.com/x/?utm_source=rss"),
        make_article("Same link story again", url="https://c.com/x", source="The Hacker News"),
        make_article("Ransomware attack disrupts Lakeshore hospitals in three states", url="https://d.com/1"),
        make_article("Lakeshore hospitals ransomware attack disrupts three states", url="https://e.com/1", source="Krebs"),
        make_article("Unrelated startup funding news today", url="https://f.com/1"),
    ]
    assert sorted(len(s.articles) for s in dedupe(arts, cfg)) == [1, 2, 2, 2]


def test_short_titles_do_not_merge(cfg):
    arts = [make_article("Patch now", url="https://a.com/1"), make_article("Patch now", url="https://b.com/2")]
    assert len(dedupe(arts, cfg)) == 2


def test_official_counts_double_and_impact(cfg):
    official = make_article(source="CISA", tier="official", url="https://cisa.gov/1", cves=["CVE-2026-1"])
    news = make_article(source="BleepingComputer", url="https://bc.com/1", cves=["CVE-2026-1"], text="ransomware")
    top = rank([official, news], cfg)[0]
    assert top.score == pytest.approx(0.4 * 3 / 5 + 0.2)  # (2 + 1) / 5 publishers + impact
    assert top.primary is official


# --- summaries (FR-11 to FR-14) ---------------------------------------------

class ScriptedClient:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = 0

    def complete(self, system, user):
        self.calls += 1
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, Exception):
            raise a
        return a


def story():
    return Story(articles=[make_article(text="Northwind fixed CVE-2026-90011. Upgrade now. Third sentence.")])


@pytest.mark.parametrize("raw", [
    '{"summary": "S.", "mitigation": "M."}',
    'Sure!\n```json\n{"summary": "S.", "mitigation": "M."}\n```',
    'Here you go: {"summary": "S.", "mitigation": "M."} hope that helps',
])
def test_parse_summary_tolerant(raw):
    assert parse_summary(raw) == ("S.", "M.")


def test_parse_summary_null_mitigation():
    assert parse_summary('{"summary": "S.", "mitigation": null}') == ("S.", None)


def test_retry_once_then_excerpt(cfg):
    client = ScriptedClient("garbage")
    s = Summarizer(client, cfg.ai)
    out = s.summarize(story())
    assert client.calls == 2 and out.is_excerpt
    assert out.summary == "Northwind fixed CVE-2026-90011. Upgrade now."


def test_retry_succeeds(cfg):
    client = ScriptedClient("not json", '{"summary": "Northwind fixed it.", "mitigation": "Upgrade."}')
    s = Summarizer(client, cfg.ai)
    out = s.summarize(story())
    assert not out.is_excerpt and out.mitigation == "Upgrade." and s.stats.valid_retry == 1


def test_429_stops_without_retry(cfg):
    client = ScriptedClient(RateLimitStop("429"))
    with pytest.raises(RateLimitStop):
        Summarizer(client, cfg.ai).summarize(story())
    assert client.calls == 1


def test_hard_budget_raises(cfg):
    s = Summarizer(ScriptedClient('{"summary": "ok", "mitigation": null}'), cfg.ai)
    s.stats.requests = cfg.ai.max_requests_per_run
    with pytest.raises(BudgetExceeded):
        s.summarize(story())


def test_max_requests_falls_back_to_excerpts(cfg):
    client = ScriptedClient('{"summary": "ok", "mitigation": null}')
    s = Summarizer(client, cfg.ai, max_requests=1)
    s.summarize(story())
    assert s.summarize(story()).is_excerpt and client.calls == 1 and s.stats.skipped == 1


def test_model_allowlist(cfg):
    assert resolve_model(None, cfg.ai) == cfg.ai.default_model
    assert resolve_model("anthropic/claude-haiku-5.5", cfg.ai) == "anthropic/claude-haiku-5.5"
    with pytest.raises(ConfigError):
        resolve_model("openai/gpt-x", cfg.ai)


class FakeHTTP:
    def __init__(self, status, body):
        self.status, self.body = status, body
        self.verify = True
        self.sent = None

    def post(self, url, **kw):
        self.sent = kw
        resp = type("R", (), {})()
        resp.status_code = self.status
        resp.json = lambda: self.body
        return resp


@pytest.mark.parametrize("status, body, exc", [
    (429, {}, RateLimitStop),
    (402, {}, RateLimitStop),
    (200, {"error": {"code": 429, "message": "rate limited"}}, RateLimitStop),
    (401, {"error": {"code": 401, "message": "User not found."}}, AIAuthError),
    (403, {"error": {"code": 403, "message": "Input flagged"}}, TransientAIError),
    (500, {}, TransientAIError),
])
def test_openrouter_errors(cfg, status, body, exc):
    client = OpenRouterClient(api_key="sk-or-test-000000", model="m", cfg=cfg.ai, session=FakeHTTP(status, body))
    with pytest.raises(exc):
        client.complete("s", "u")


def test_auth_error_explains_itself(cfg):
    body = {"error": {"code": 401, "message": "User not found."}}
    client = OpenRouterClient(api_key="sk-or-test-000000", model="m", cfg=cfg.ai, session=FakeHTTP(401, body))
    with pytest.raises(AIAuthError, match="User not found"):
        client.complete("s", "u")


def test_openrouter_request(cfg):
    http = FakeHTTP(200, {"choices": [{"message": {"content": "hi"}}]})
    client = OpenRouterClient(api_key="sk-or-test-000000", model="m", cfg=cfg.ai, session=http)
    assert client.complete("s", "u") == "hi"
    assert http.sent["headers"]["Authorization"] == "Bearer sk-or-test-000000"
    assert http.sent["timeout"] == cfg.ai.timeout_seconds
    assert "response_format" not in http.sent["json"]  # FR-12


def test_excerpt_two_sentences():
    assert excerpt_of("One. Two. Three.") == "One. Two."
