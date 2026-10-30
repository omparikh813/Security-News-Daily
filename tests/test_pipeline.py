"""T1: collection window, dedupe, scoring, summaries, 429 stop, budget, model allowlist."""

from __future__ import annotations

from datetime import timedelta

import pytest

from malnews.collect import collect
from malnews.errors import AIAuthError, BudgetExceeded, ConfigError, RateLimitStop
from malnews.fixtures import load_fixtures
from malnews.models import Story
from malnews.rank import dedupe, rank
from malnews.summarize import OpenRouterClient, Summarizer, excerpt_of, resolve_model

from .conftest import NOW, ROOT, make_article


# --- collection --------------------------------------------------------------

def test_collect_from_fixtures(cfg, sources, no_network):
    now, fetcher, _ = load_fixtures(ROOT / "fixtures")
    articles, report = collect(sources, fetcher, now, cfg)
    titles = {a.title for a in articles}
    assert report.failed == [] and len(report.ok) == 5
    assert "Contoso HMI Panel Advisory" not in titles  # older than 24 h
    assert "An item whose link is not http" not in titles  # javascript: link skipped
    assert all(a.url.startswith("https://") for a in articles)
    assert any(a.text_is_excerpt for a in articles) and any(not a.text_is_excerpt for a in articles)


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
    sizes = sorted(len(s.articles) for s in dedupe(arts, cfg))
    assert sizes == [1, 2, 2, 2]


def test_short_titles_do_not_merge(cfg):
    arts = [make_article("Patch now", url="https://a.com/1"), make_article("Patch now", url="https://b.com/2")]
    assert len(dedupe(arts, cfg)) == 2


def test_official_counts_double_and_impact(cfg):
    official = make_article(source="CISA", tier="official", url="https://cisa.gov/1", cves=["CVE-2026-1"])
    news = make_article(source="BleepingComputer", url="https://bc.com/1", cves=["CVE-2026-1"], text="ransomware")
    top = rank([official, news], cfg)[0]
    # (2 + 1) / 5 * 0.4 + impact 0.2
    assert top.score == pytest.approx(0.4 * 3 / 5 + 0.2)
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


def story(text="Northwind fixed CVE-2026-90011. Upgrade now. Third sentence here."):
    return Story(articles=[make_article(text=text, cves=["CVE-2026-90011"])])


def test_retry_once_then_excerpt(cfg):
    client = ScriptedClient("garbage")
    s = Summarizer(client, cfg.ai)
    out = s.summarize(story())
    assert client.calls == 2 and out.is_excerpt
    assert out.summary == "Northwind fixed CVE-2026-90011. Upgrade now."
    assert s.stats.excerpts == 1


def test_retry_succeeds(cfg):
    client = ScriptedClient('{"summary": "bad https://x.com", "mitigation": null}',
                            '{"summary": "Northwind fixed it.", "mitigation": "Upgrade."}')
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


def test_soft_budget_falls_back(cfg):
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
    (401, {}, AIAuthError),
])
def test_openrouter_errors(cfg, status, body, exc):
    client = OpenRouterClient(api_key="sk-or-test-000000", model="m", cfg=cfg.ai, session=FakeHTTP(status, body))
    with pytest.raises(exc):
        client.complete("s", "u")


def test_openrouter_success_and_headers(cfg):
    http = FakeHTTP(200, {"choices": [{"message": {"content": "hi"}}]})
    client = OpenRouterClient(api_key="sk-or-test-000000", model="m", cfg=cfg.ai, session=http)
    assert client.complete("s", "u") == "hi"
    assert http.sent["headers"]["Authorization"] == "Bearer sk-or-test-000000"
    assert http.sent["timeout"] == cfg.ai.timeout_seconds
    assert "response_format" not in http.sent["json"]


def test_excerpt_removes_links():
    assert "evil" not in excerpt_of("Go to https://evil.example/x now. Or evil-site.com. Third.")


def test_window_boundary(cfg, sources):
    assert NOW - timedelta(hours=cfg.collection.window_hours) < NOW
