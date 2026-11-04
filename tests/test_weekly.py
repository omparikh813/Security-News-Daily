"""FR-15 Story of the Week, SR-7 state validation, FR-10 New Threats."""

from __future__ import annotations

import json
from datetime import date, timedelta

import pytest

from malnews.models import Story
from malnews.rank import dedupe, is_zero_day, rank
from malnews.enrich import CveInfo
from malnews.state import LinkRecord, State, StateError, StoryRecord, load_state, save_state
from malnews.weekly import remember, update_story_of_week, week_start

from .conftest import make_article

MON = date(2026, 11, 2)


def rec(title, score, day, cves=(), id=None):
    return StoryRecord(id=id or f"https://news.example.com/{title.replace(' ', '-')}", day=day, title=title,
                       score=score, links=[LinkRecord(publisher="Pub", url="https://news.example.com/x")],
                       cves=list(cves), text="Body.")


def test_week_starts_monday():
    assert week_start(date(2026, 11, 8)) == MON  # Sunday
    assert week_start(MON) == MON


def test_seven_day_replay(cfg):
    """Acceptance (Phase 2): a 7-day replay swaps the Story of the Week correctly."""
    state = State()
    log = []

    def day(offset, *records):
        d = MON + timedelta(days=offset)
        today = sorted(records, key=lambda r: -r.score)
        out = update_story_of_week(state, today, d, cfg)
        remember(state, today, d, cfg)
        log.append((d.strftime("%a"), out.status, state.story_of_week.story.title,
                    out.replaced.title if out.replaced else None))

    day(0, rec("Ransomware gang hits hospital chain", 0.50, MON), rec("Minor patch roundup for the week", 0.20, MON))
    day(1, rec("Big VPN flaw exploited in the wild", 0.55, MON + timedelta(1)))  # +10%: not enough
    day(2, rec("Cloud provider breach exposes data", 0.62, MON + timedelta(2)))  # +24%: replaces
    day(3, rec("Cloud provider breach exposes customer data widely", 0.70, MON + timedelta(3)))  # same event
    day(4, rec("Worm spreads through routers worldwide", 0.80, MON + timedelta(4)))  # 0.80 < 0.70 * 1.2
    day(5, rec("Supply chain attack on build tool", 0.90, MON + timedelta(5)))  # 0.90 >= 0.84: replaces
    day(6)  # quiet Sunday
    day(7, rec("New week top story about firmware", 0.30, MON + timedelta(7)))  # Monday: reset

    assert log == [
        ("Mon", "reset", "Ransomware gang hits hospital chain", None),
        ("Tue", "kept", "Ransomware gang hits hospital chain", None),
        ("Wed", "replaced", "Cloud provider breach exposes data", "Ransomware gang hits hospital chain"),
        ("Thu", "kept", "Cloud provider breach exposes data", None),
        ("Fri", "kept", "Cloud provider breach exposes data", None),
        ("Sat", "replaced", "Supply chain attack on build tool", "Cloud provider breach exposes data"),
        ("Sun", "kept", "Supply chain attack on build tool", None),
        ("Mon", "reset", "New week top story about firmware", None),
    ]
    assert state.story_of_week.updated_on is None  # a reset clears "Updated <day>"


def test_older_story_in_history_can_win(cfg):
    state = State()
    update_story_of_week(state, [rec("First story of the week here", 0.4, MON)], MON, cfg)
    state.history = [rec("Late breaking big incident story", 0.9, MON)]
    out = update_story_of_week(state, [], MON + timedelta(1), cfg)
    assert out.status == "replaced" and state.story_of_week.updated_on == MON + timedelta(1)


def test_shared_cve_is_same_event(cfg):
    state = State()
    update_story_of_week(state, [rec("Vendor flaw exploited", 0.4, MON, cves=["CVE-2026-1111"])], MON, cfg)
    out = update_story_of_week(state, [rec("Totally new words", 0.9, MON + timedelta(1), cves=["CVE-2026-1111"])],
                               MON + timedelta(1), cfg)
    assert out.status == "kept" and state.story_of_week.story.score == 0.9


def test_remember_keeps_last_seven_days(cfg):
    state = State(history=[rec(f"Old {i} story title here", 0.1, MON - timedelta(days=i)) for i in range(10)])
    remember(state, [rec(f"Today {i} story title", 0.5, MON) for i in range(15)], MON, cfg)
    days = {r.day for r in state.history}
    assert min(days) == MON - timedelta(days=6)
    assert sum(r.day == MON for r in state.history) == cfg.story_of_week.records_per_day


# --- state.json (SR-7) ------------------------------------------------------------

def test_missing_state_is_fresh(tmp_path):
    assert load_state(tmp_path / "state.json") == State()


def test_state_round_trip(tmp_path, cfg):
    state = State(pending={"CVE-2026-0001": MON})
    update_story_of_week(state, [rec("A story title for testing", 0.5, MON)], MON, cfg)
    save_state(state, tmp_path / "state.json")
    assert load_state(tmp_path / "state.json") == state
    assert not list(tmp_path.glob(".state-*"))  # no temp files left behind


def _valid_state_json(cfg) -> dict:
    state = State()
    update_story_of_week(state, [rec("A story title for testing", 0.5, MON)], MON, cfg)
    return json.loads(state.model_dump_json())


@pytest.mark.parametrize("tamper", [
    lambda d: d.update(extra="field"),
    lambda d: d["story_of_week"]["story"]["links"][0].update(url="javascript:alert(1)"),
    lambda d: d["story_of_week"]["story"]["links"][0].update(url="http://news.example.com/plain-http"),
    lambda d: d["story_of_week"]["story"].update(cves=["CVE-2026-1&apiKey=x"]),
    lambda d: d["story_of_week"]["story"].update(score="high"),
    lambda d: d["story_of_week"]["story"].update(title="x" * 5000),
    lambda d: d.update(pending={"not-a-cve": "2026-11-02"}),
    lambda d: d.update(version=2),
])
def test_tampered_state_fails_closed(tmp_path, cfg, tamper):
    data = _valid_state_json(cfg)
    tamper(data)
    (tmp_path / "state.json").write_text(json.dumps(data))
    with pytest.raises(StateError):
        load_state(tmp_path / "state.json")


def test_oversized_or_garbage_state_fails_closed(tmp_path):
    p = tmp_path / "state.json"
    p.write_bytes(b"{" + b" " * 2_000_001 + b"}")
    with pytest.raises(StateError, match="larger"):
        load_state(p)
    p.write_text("not json")
    with pytest.raises(StateError):
        load_state(p)


def test_symlinked_state_rejected(tmp_path):
    (tmp_path / "real.json").write_text("{}")
    (tmp_path / "state.json").symlink_to(tmp_path / "real.json")
    with pytest.raises(StateError, match="regular file"):
        load_state(tmp_path / "state.json")


# --- New Threats (FR-10) ------------------------------------------------------------

def story(*articles) -> Story:
    return Story(articles=list(articles))


def test_official_zero_day(cfg):
    s = story(make_article(source="CISA", tier="official", text="Exploited as a zero-day.", cves=["CVE-2026-1"]))
    assert is_zero_day(s, cfg)


def test_one_news_outlet_is_not_enough(cfg):
    s = story(make_article(text="A 0-day!", cves=["CVE-2026-1"]),
              make_article(source="Krebs", url="https://k.com/a", text="Patched bug.", cves=["CVE-2026-1"]))
    assert not is_zero_day(s, cfg)


def test_two_outlets_agree(cfg):
    s = story(make_article(text="A 0-day!", cves=["CVE-2026-1"]),
              make_article(source="Krebs", url="https://k.com/a", text="No patch available.", cves=["CVE-2026-1"]))
    assert is_zero_day(s, cfg)


def test_zero_day_needs_a_cve(cfg):
    assert not is_zero_day(story(make_article(source="CISA", tier="official", text="zero-day")), cfg)


def test_rank_uses_official_priority(cfg):
    a = make_article("Low coverage but critical", url="https://a.com/1", cves=["CVE-2026-1", "CVE-2026-2"])
    b = make_article("Unrelated story without CVEs", url="https://b.com/1")
    infos = {"CVE-2026-1": CveInfo("CVE-2026-1", "scored", cvss=9.8, kev=True, epss=0.9),
             "CVE-2026-2": CveInfo("CVE-2026-2", "pending")}
    ranked = rank(dedupe([b, a], cfg), cfg, infos)
    assert ranked[0].title == "Low coverage but critical"
    assert [i.id for i in ranked[0].cve_infos] == ["CVE-2026-1", "CVE-2026-2"]  # highest priority first
    assert ranked[0].kev and ranked[0].priority == pytest.approx(infos["CVE-2026-1"].priority(cfg))
