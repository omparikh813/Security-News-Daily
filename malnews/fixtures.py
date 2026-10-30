"""Offline stand-ins for the network and the model, used by --dry-run and tests (T2)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import yaml

from .errors import RateLimitStop
from .safety import FetchResult, HTTPStatusError


class FixtureFetcher:
    """Serves saved files by URL. Unknown URLs return 404, like a missing page."""

    def __init__(self, root: Path, responses: dict[str, dict]):
        self.root = root.resolve()
        self.responses = responses

    def get(self, url: str, kind: str) -> FetchResult:
        entry = self.responses.get(url)
        if entry is None:
            raise HTTPStatusError(404, url)
        path = (self.root / entry["file"]).resolve()
        if not path.is_relative_to(self.root):
            raise ValueError(f"fixture path escapes fixtures/: {entry['file']}")
        return FetchResult(url, path.read_bytes(), entry["type"])


class FixtureAIClient:
    """Replays recorded model responses keyed by article title.

    Each title maps to a list of responses, returned in order (the last one repeats).
    """

    def __init__(self, responses: dict[str, list[str]], force_429: bool = False):
        self.responses = {k: list(v) for k, v in responses.items()}
        self.force_429 = force_429
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        if self.force_429:
            raise RateLimitStop("forced 429 (fixture)")
        for title, queue in self.responses.items():
            if queue and f"<article>\n{title}\n" in user:
                return queue.pop(0) if len(queue) > 1 else queue[0]
        return "not json"


def load_fixtures(root: Path) -> tuple[datetime, FixtureFetcher, dict[str, list[str]]]:
    manifest = yaml.safe_load((root / "manifest.yaml").read_text(encoding="utf-8"))
    now = datetime.fromisoformat(manifest["now"].replace("Z", "+00:00"))
    ai = yaml.safe_load((root / manifest["ai"]).read_text(encoding="utf-8")) or {}
    return now, FixtureFetcher(root, manifest["responses"]), ai
