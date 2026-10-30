"""MalNews: collect -> rank -> summarize -> render -> publish.

  python main.py --dry-run            fixtures only, no network or AI (T2) -> site/
  python main.py --max-requests 10    real feeds and model, keys from .env (T3) -> out/
  python main.py --no-ai              real feeds, excerpts instead of summaries -> out/
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from malnews.collect import collect
from malnews.errors import ConfigError, MalNewsError
from malnews.fixtures import FixtureAIClient, load_fixtures
from malnews.publish import write_site
from malnews.rank import rank
from malnews.render import build_edition, render_pdf
from malnews.safety import SafeFetcher
from malnews.settings import load_config, load_sources
from malnews.summarize import OpenRouterClient, Summarizer, resolve_model

ROOT = Path(__file__).resolve().parent
SECRET_ENV = ("OPENROUTER_API_KEY", "NVD_API_KEY")
log = logging.getLogger("malnews")


class RedactSecrets(logging.Filter):
    """SR-5 defense in depth: never let a key value reach a log line."""

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
        logging.getLogger(noisy).setLevel(logging.WARNING)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build the MalNews daily edition.")
    p.add_argument("--dry-run", action="store_true", help="use fixtures/, no network or AI")
    p.add_argument("--max-requests", type=int, default=None, help="cap AI requests for this run")
    p.add_argument("--no-ai", action="store_true", help="skip the model; print excerpts")
    p.add_argument("--out", type=Path, default=None, help="output folder")
    p.add_argument("--fixtures", type=Path, default=ROOT / "fixtures")
    p.add_argument("--force-429", action="store_true", help="dry run only: simulate a 429 (FR-14 test)")
    return p.parse_args(argv)


def write_job_summary(lines: list[str]) -> None:
    """FR-22. Public on a public repo: counts only, never secrets or article text."""
    text = "\n".join(lines) + "\n"
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)
    print(text)


def run(args: argparse.Namespace) -> int:
    cfg = load_config(ROOT / "config.yaml")
    sources = load_sources(ROOT / "sources.yaml")
    if args.force_429 and not args.dry_run:
        raise ConfigError("--force-429 only works with --dry-run")
    if args.max_requests is not None and args.max_requests < 0:
        raise ConfigError("--max-requests must be 0 or more")

    if args.dry_run:
        now, fetcher, ai_fixtures = load_fixtures(args.fixtures)
        client = None if args.no_ai else FixtureAIClient(ai_fixtures, force_429=args.force_429)
        model = "fixtures"
        out_dir = args.out or ROOT / "site"
    else:
        if not os.environ.get("GITHUB_ACTIONS"):
            from dotenv import load_dotenv  # local runs only; CI uses repository secrets

            load_dotenv(ROOT / ".env", override=False)
        model = resolve_model(os.environ.get("OPENROUTER_MODEL"), cfg.ai)  # FR-11, before any network
        client = None
        if not args.no_ai:
            key = os.environ.get("OPENROUTER_API_KEY", "")
            if not key:
                raise ConfigError("OPENROUTER_API_KEY is not set (use --no-ai to run without it)")
            client = OpenRouterClient(api_key=key, model=model, cfg=cfg.ai)
        c = cfg.collection
        fetcher = SafeFetcher(
            user_agent=c.user_agent, timeout=c.timeout_seconds, retries=c.retries,
            max_redirects=c.max_redirects,
            max_bytes={"feed": c.max_text_bytes, "html": c.max_text_bytes,
                       "robots": 512_000, "image": c.max_image_bytes},
            allow_env_proxy=os.environ.get("MALNEWS_ALLOW_PROXY") == "1",
        )
        now = datetime.now(timezone.utc)
        out_dir = args.out or ROOT / "out"

    articles, report = collect(sources, fetcher, now, cfg)
    stories = rank(articles, cfg)
    summarizer = Summarizer(client, cfg.ai, max_requests=args.max_requests)
    summarizer.summarize_all(stories)

    edition = build_edition(stories, cfg, now, [s.name for s in sources])
    result = render_pdf(edition)
    if result.blocked:
        log.warning("renderer blocked %d resource request(s)", len(result.blocked))

    day = now.astimezone(timezone(timedelta(hours=cfg.edition.utc_offset_hours))).date().isoformat()
    write_site(result.pdf, out_dir, day)

    st = summarizer.stats
    rate = st.json_valid_rate
    write_job_summary([
        f"## MalNews {day}",
        f"- Sources OK: {', '.join(report.ok) or 'none'}",
        f"- Sources failed: {', '.join(report.failed) or 'none'}",
        f"- Articles: {report.articles} ({report.full_text} with full text)",
        f"- Stories after dedupe: {len(stories)} ({edition.dropped} dropped for length)",
        f"- Model: {model}; requests used: {st.requests}",
        f"- Valid JSON: {st.valid_first} first try, {st.valid_retry} after retry, "
        f"{st.excerpts} excerpt fallbacks, {st.skipped} not sent"
        + (f" ({rate:.0%} valid)" if rate is not None else ""),
        f"- Words: {edition.words}; PDF: {len(result.pdf) / 1024:.0f} KB -> {out_dir}",
    ])
    return 0


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    try:
        return run(parse_args(argv))
    except MalNewsError as e:
        log.error("%s: %s (nothing published)", type(e).__name__, e)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
