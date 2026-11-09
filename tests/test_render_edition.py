"""FR-8, FR-17: the full Phase 2 edition layout."""

from __future__ import annotations

import io
from datetime import date, timedelta

import pypdf
import pytest

from malnews.enrich import CveInfo
from malnews.models import Story, Summary
from malnews.render import build_edition, render_pdf
from malnews.state import LinkRecord, StoryOfWeek, StoryRecord, WeeklyContent

from .conftest import NOW, make_article

SENT = ("Attackers are exploiting the flaw to gain initial access to corporate networks and deploy "
        "web shells for persistence. ")


def full_edition(cfg, n_stories=16):
    infos = {
        "CVE-2026-10001": CveInfo("CVE-2026-10001", "scored", 9.8, "3.1", kev=True, epss=0.94),
        "CVE-2026-10002": CveInfo("CVE-2026-10002", "scored", 7.5, "3.1", epss=0.12),
        "CVE-2026-10003": CveInfo("CVE-2026-10003", "pending"),
        "CVE-2026-10004": CveInfo("CVE-2026-10004", "unavailable"),
    }
    stories = []
    for i in range(n_stories):
        cves = list(infos)[i % 4: i % 4 + 1] if i % 3 == 0 else []
        s = Story(articles=[make_article(f"Story number {i} about a security incident at a vendor",
                                         url=f"https://news.example.com/{i}", cves=cves)])
        s.cve_infos = [infos[c] for c in cves]
        s.zero_day = i in (4, 7)
        s.score = 1 - i / 100
        s.summary = Summary(SENT * 2, "Apply the vendor update and rotate credentials." if i % 2 else None)
        stories.append(s)
    weekly = StoryOfWeek(
        story=StoryRecord(id="https://news.example.com/sotw", day=date(2026, 10, 27), title="Week's biggest breach story",
                          score=0.9, links=[LinkRecord(publisher="CISA", url="https://www.cisa.gov/a")],
                          cves=["CVE-2026-10001"], text="Body."),
        content=WeeklyContent(what_happened=SENT * 2, who_affected=SENT, what_changed=SENT, mitigation=SENT),
        set_on=date(2026, 10, 27), updated_on=date(2026, 10, 29))
    replaced = StoryRecord(id="https://news.example.com/old", day=date(2026, 10, 26), title="Last pick of the week",
                           score=0.5, links=[LinkRecord(publisher="Krebs", url="https://krebsonsecurity.com/x")],
                           text="Previous pick summary sentence. Another one.", summary=None)
    return build_edition(stories, cfg, NOW, ["CISA", "Krebs"], weekly, replaced, infos,
                         replaced_summary="The previous pick, summarized by AI when it was chosen.")


def pdf_text(pdf):
    reader = pypdf.PdfReader(io.BytesIO(pdf))
    return reader, " ".join(p.extract_text() for p in reader.pages)


def test_full_edition_is_three_to_four_pages(cfg, no_network):
    edition = full_edition(cfg)
    assert edition.words <= cfg.layout.max_words
    result = render_pdf(edition)
    reader, text = pdf_text(result.pdf)
    assert 3 <= len(reader.pages) <= 4, len(reader.pages)
    assert len(result.pdf) < 1_000_000 and result.blocked == []

    for expected in ("Story of the Week", "Updated Thursday", "What happened", "Who is affected",
                     "News of the Day", "New Threats", "Other Headlines", "Last pick of the week",
                     "Critical 9.8", "High 7.5", "Score pending", "Score unavailable", "Known Exploited", "EPSS 94%"):
        # Badges print in capitals and pypdf may split them ("UNAV AILABLE"): compare without spaces.
        assert expected.lower().replace(" ", "") in text.lower().replace(" ", ""), expected


def test_cve_links_point_to_cve_org_and_nvd(cfg, no_network):
    reader, _ = pdf_text(render_pdf(full_edition(cfg)).pdf)
    links = {str(a.get_object()["/A"]["/URI"]) for p in reader.pages for a in p.get("/Annots") or []}
    assert "https://www.cve.org/CVERecord?id=CVE-2026-10001" in links
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-10001" in links
    assert all(u.startswith("https://") for u in links)


def test_word_budget_drops_lowest_headlines(cfg):
    edition = full_edition(cfg, n_stories=40)
    assert edition.words <= cfg.layout.max_words and edition.dropped > 0
    assert len(edition.context["new_threats"]) == 2  # threats are never dropped for length


@pytest.mark.parametrize("cvss, label", [(9.0, "Critical 9.0"), (0.0, "None 0.0")])
def test_score_and_band_name_both_printed(cfg, cvss, label, no_network):
    info = CveInfo("CVE-2026-10009", "scored", cvss, "3.1")
    s = Story(articles=[make_article("A single story title here", cves=["CVE-2026-10009"])],
              cve_infos=[info], summary=Summary("Summary.", None))
    _, text = pdf_text(render_pdf(build_edition([s], cfg, NOW, ["X"])).pdf)
    assert label.lower().replace(" ", "") in text.lower().replace(" ", "")


def test_story_of_week_shown_once(cfg):
    """A story that is also today's news appears only as the Story of the Week."""
    today = Story(articles=[make_article("Week's biggest breach story", url="https://news.example.com/sotw")],
                  summary=Summary("S.", None))
    weekly = StoryOfWeek(story=StoryRecord(id="https://news.example.com/sotw", day=NOW.date() - timedelta(1),
                                           title="Week's biggest breach story", score=0.9,
                                           links=[LinkRecord(publisher="P", url="https://news.example.com/sotw")]),
                         content=WeeklyContent(what_happened="AI write-up."), set_on=NOW.date())
    ctx = build_edition([today], cfg, NOW, ["X"], weekly).context
    assert ctx["story_of_week"] and ctx["news_of_the_day"] == []


def test_no_excerpts_anywhere(cfg, no_network):
    """Stories without an AI summary, an excerpt-only Story of the Week, and a replaced pick with
    no summary are all left out rather than printed."""
    ai = Story(articles=[make_article("Story with an AI summary", url="https://a.example.com/1")],
               summary=Summary("Written by the model.", None))
    raw = Story(articles=[make_article("Story the model could not summarize", url="https://a.example.com/2",
                                       text="Raw article text that must never be printed.")])
    old = StoryOfWeek(story=StoryRecord(id="https://a.example.com/w", day=NOW.date(), title="Old weekly pick",
                                        score=0.5, links=[LinkRecord(publisher="P", url="https://a.example.com/w")]),
                      content=WeeklyContent(what_happened="First two sentences of the article.", is_excerpt=True),
                      set_on=NOW.date())
    replaced = StoryRecord(id="https://a.example.com/r", day=NOW.date(), title="Replaced pick with no summary",
                           score=0.4, links=[LinkRecord(publisher="P", url="https://a.example.com/r")])
    edition = build_edition([ai, raw], cfg, NOW, ["X"], old, replaced)
    ctx = edition.context
    assert ctx["story_of_week"] is None
    assert [v["title"] for v in ctx["news_of_the_day"] + ctx["headlines"]] == ["Story with an AI summary"]
    _, text = pdf_text(render_pdf(edition).pdf)
    assert "excerpt" not in text.lower() and "Raw article text" not in text and "First two sentences" not in text
