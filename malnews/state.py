"""state.json: Story of the Week and pending CVEs between runs (FR-9, FR-15, SR-7).

The file is validated against a strict schema on load. Anything unexpected
(unknown fields, wrong types, unsafe links, oversized content) stops the run
before it publishes, instead of being trusted.
"""

from __future__ import annotations

import os
import tempfile
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .enrich import CVE_ID_RE
from .errors import MalNewsError
from .safety import safe_href

MAX_STATE_BYTES = 2_000_000


class StateError(MalNewsError):
    """state.json is missing pieces, malformed, or tampered with. Publish nothing."""

    exit_code = 7


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _check_cves(v: list[str]) -> list[str]:
    for c in v:
        if not CVE_ID_RE.match(c):
            raise ValueError(f"bad CVE ID {c[:40]!r}")
    return v


class LinkRecord(_Strict):
    publisher: str = Field(min_length=1, max_length=60)
    url: str = Field(max_length=2048)

    @field_validator("url")
    @classmethod
    def _safe(cls, v: str) -> str:
        if safe_href(v) != v:
            raise ValueError("link is not a plain https URL")
        return v


class StoryRecord(_Strict):
    id: str = Field(min_length=1, max_length=2048)
    day: date
    title: str = Field(min_length=1, max_length=300)
    score: float = Field(ge=0, le=1)
    links: list[LinkRecord] = Field(min_length=1, max_length=20)
    cves: list[str] = Field(default_factory=list, max_length=50)
    text: str = Field(default="", max_length=10_000)
    summary: str | None = Field(default=None, max_length=2000)

    @field_validator("cves")
    @classmethod
    def _cve_ids(cls, v: list[str]) -> list[str]:
        return _check_cves(v)


class WeeklyContent(_Strict):
    what_happened: str = Field(min_length=1, max_length=1500)
    who_affected: str | None = Field(default=None, max_length=1500)
    what_changed: str | None = Field(default=None, max_length=1500)
    mitigation: str | None = Field(default=None, max_length=1500)
    is_excerpt: bool = False


class StoryOfWeek(_Strict):
    story: StoryRecord
    content: WeeklyContent | None = None
    set_on: date
    updated_on: date | None = None  # set when it replaced an earlier pick this week


class State(_Strict):
    version: Literal[1] = 1
    week_start: date | None = None
    story_of_week: StoryOfWeek | None = None
    history: list[StoryRecord] = Field(default_factory=list, max_length=300)
    pending: dict[str, date] = Field(default_factory=dict, max_length=1000)

    @field_validator("pending")
    @classmethod
    def _pending_ids(cls, v: dict[str, date]) -> dict[str, date]:
        _check_cves(list(v))
        return v


def load_state(path: Path) -> State:
    if not path.exists():
        return State()
    if path.is_symlink() or not path.is_file():
        raise StateError(f"{path.name} is not a regular file")
    raw = path.read_bytes()
    if len(raw) > MAX_STATE_BYTES:
        raise StateError(f"{path.name} is larger than {MAX_STATE_BYTES} bytes")
    try:
        return State.model_validate_json(raw)
    except ValidationError as e:
        raise StateError(f"{path.name} failed validation ({e.error_count()} errors): {e.errors()[0]['msg']}") from e


def save_state(state: State, path: Path) -> None:
    """Write atomically, so a crash mid-write never leaves a half-written file."""
    data = state.model_dump_json(indent=1).encode()
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
