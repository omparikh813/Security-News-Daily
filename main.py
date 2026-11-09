"""MalNews: collect -> rank -> summarize -> render -> publish.

  python main.py                     full run -> site/, state.json
  python main.py --max-requests 10   cap AI requests for a test run (T3)

Keys come from the environment (GitHub secrets in CI, a git-ignored .env locally).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from malnews.collect import collect
from malnews.enrich import Enricher
from malnews.errors import ConfigError, MalNewsError
from malnews.publish import write_site
from malnews.rank import cves_by_importance, dedupe, rank
from malnews.render import (
    FIXED_WORDS, build_edition, record_summary, record_view, render_pdf, same_event, story_view, usable, weekly_view,
)
from malnews.safety import SafeFetcher
from malnews.settings import load_config, load_sources
from malnews.state import load_state, save_state
from malnews.summarize import OpenRouterClient, Summarizer, resolve_model
from malnews.weekly import remember, to_record, update_story_of_week

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config"
SECRET_ENV = ("OPENROUTER_API_KEY", "NVD_API_KEY")
log = logging.getLogger("malnews")


class RedactSecrets(logging.Filter):
    """SR-5: never let a key value reach a log line, even inside an exception message."""

    def __init__(self):
        super().__init__()
        self.secrets = [v for k in SECRET_ENV if len(v := os.environ.get(k, "")) >= 8]

    def filter(self, record: logging.LogRecord) -> bool:
        if self.secrets:
            msg = record.getMessage()
            for s in self.secrets:
                msg = msg.replace(s, "[REDACTED]")
            record.msg, record.args = msg, None
        return True


def setup_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactSecrets())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    for noisy in ("urllib3", "trafilatura", "fontTools", "weasyprint"):
        logging.getLogger(noisy).setLevel(logging.ERROR)


def write_job_summary(lines: list[str]) -> None:
    """FR-22. Public on a public repo: counts only, never secrets or article text."""
    text = "\n".join(lines) + "\n"
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)
    print(text)


def run(max_requests: int | None, out_dir: Path, state_path: Path) -> int:
    cfg = load_config(CONFIG / "config.yaml")
    sources = load_sources(CONFIG / "sources.yaml")
    if not os.environ.get("GITHUB_ACTIONS"):
        from dotenv import load_dotenv  # local runs only; CI uses repository secrets

        load_dotenv(ROOT / ".env", override=True)  # .env beats a stale exported key
        setup_logging()  # pick up keys loaded from .env for redaction

    # Fail before any network use (FR-11, SR-7).
    model = resolve_model(os.environ.get("OPENROUTER_MODEL"), cfg.ai)
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise ConfigError("OPENROUTER_API_KEY is not set")
    nvd_key = os.environ.get("NVD_API_KEY", "").strip() or None
    state = load_state(state_path)

    c = cfg.collection
    fetcher = SafeFetcher(user_agent=c.user_agent, timeout=c.timeout_seconds, retries=c.retries,
                          max_redirects=c.max_redirects, max_bytes=c.max_response_bytes)
    now = datetime.now(timezone.utc)
    today = now.astimezone(timezone(timedelta(hours=cfg.edition.utc_offset_hours))).date()

    # Collect, merge, and score with official data (FR-1 to FR-10).
    articles, report = collect(sources, fetcher, now, cfg)
    stories = dedupe(articles, cfg)
    enricher = Enricher(fetcher, cfg, nvd_key)
    pending = [cve for cve, seen in state.pending.items() if (today - seen).days <= cfg.enrich.pending_days]
    weekly_cves = state.story_of_week.story.cves if state.story_of_week else []
    infos = enricher.lookup(cves_by_importance(stories) + weekly_cves + pending)
    stories = rank(stories, cfg, infos)

    # Story of the Week (FR-15, FR-16).
    per_day = cfg.story_of_week.records_per_day
    outcome = update_story_of_week(state, [to_record(s, today, cfg) for s in stories[:per_day]], today, cfg)
    sotw = state.story_of_week
    summarizer = Summarizer(OpenRouterClient(api_key=key, model=model, cfg=cfg.ai), cfg.ai, max_requests)
    if sotw and not usable(sotw.content):
        sotw.content = summarizer.weekly(sotw.story)  # None: no box today, retried next run
    replaced_summary = record_summary(outcome.replaced, outcome.replaced_content) if outcome.replaced else None

    # Summarize in rank order. A story with no AI summary is left out and the next one moves up.
    # Once the word budget is full, only zero-days (New Threats) are still summarized.
    words = FIXED_WORDS + (weekly_view(sotw, infos, cfg)["words"] if sotw and usable(sotw.content) else 0)
    if replaced_summary:
        words += record_view(outcome.replaced, infos, cfg, replaced_summary)["words"]
    shown = 0
    for s in stories:
        if sotw and same_event(s, sotw.story, cfg):
            continue
        if shown >= cfg.ranking.news_of_the_day and not s.zero_day and words >= cfg.layout.max_words:
            continue
        s.summary = summarizer.summarize(s)
        if s.summary:
            shown += 1
            words += story_view(s)["words"]

    edition = build_edition(stories, cfg, now, [s.name for s in sources], sotw, outcome.replaced, infos,
                            replaced_summary)
    result = render_pdf(edition)
    if result.blocked:
        log.warning("renderer blocked %d resource request(s)", len(result.blocked))
    write_site(result.pdf, out_dir, today.isoformat())  # only reached when every step succeeded

    # Remember today for the rest of the week, and track CVEs NVD has not scored yet (FR-9).
    remember(state, [to_record(s, today, cfg) for s in stories[:per_day]], today, cfg)
    for cve, info in infos.items():
        if info.status == "pending":
            state.pending.setdefault(cve, today)
        elif info.status == "scored":
            state.pending.pop(cve, None)
    state.pending = {k: v for k, v in state.pending.items() if (today - v).days <= cfg.enrich.pending_days}
    save_state(state, state_path)

    st = summarizer.stats
    rate = st.json_valid_rate
    counts = Counter(i.status for i in infos.values())
    write_job_summary([
        f"## MalNews {today}",
        f"- Sources OK: {', '.join(report.ok) or 'none'}",
        f"- Sources failed: {', '.join(report.failed) or 'none'}",
        f"- Articles: {report.articles} ({report.full_text} with full text)",
        f"- Stories after dedupe: {len(stories)}; summarized: {shown} ({edition.dropped} dropped for length)",
        f"- CVEs: {counts['scored']} scored, {counts['pending']} pending, {counts['unavailable']} unavailable; "
        f"NVD lookups: {enricher.lookups}{' (NVD down)' if enricher.nvd_down else ''}"
        f"{'; KEV unavailable' if not enricher.kev_ok else ''}",
        f"- New Threats: {len(edition.context['new_threats'])}; pending CVEs tracked: {len(state.pending)}",
        f"- Story of the Week: {outcome.status}" + (f" ({sotw.story.title[:80]})" if sotw else "")
        + ("" if not sotw or usable(sotw.content) else "; no AI write-up yet, box hidden today"),
        f"- Model: {model}; requests used: {st.requests}",
        f"- AI summaries: {st.valid_first} first try, {st.valid_retry} after retry, "
        f"{st.failed} left out (no usable summary), {st.flagged} left out (moderation), "
        f"{st.skipped} left out (request cap)"
        + (f" ({rate:.0%} usable)" if rate is not None else ""),
        f"- Words: {edition.words}; PDF: {len(result.pdf) / 1024:.0f} KB",
    ])
    return 0


def main(argv: list[str] | None = None, out_dir: Path = ROOT / "site",
         state_path: Path = ROOT / "state.json") -> int:
    p = argparse.ArgumentParser(description="Build the MalNews daily edition.")
    p.add_argument("--max-requests", type=int, default=None, help="cap AI requests for this run")
    args = p.parse_args(argv)
    setup_logging()
    try:
        if args.max_requests is not None and args.max_requests < 0:
            raise ConfigError("--max-requests must be 0 or more")
        return run(args.max_requests, out_dir, state_path)
    except MalNewsError as e:
        log.error("%s: %s (nothing published)", type(e).__name__, e)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
