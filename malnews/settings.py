"""Strict, schema-validated loading of config.yaml and sources.yaml (SR-7)."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

MAX_CONFIG_BYTES = 64_000


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EditionCfg(_Strict):
    launch_date: date
    utc_offset_hours: int = Field(ge=-12, le=14)


class CollectionCfg(_Strict):
    window_hours: int = Field(gt=0, le=168)
    timeout_seconds: float = Field(gt=0, le=60)
    retries: int = Field(ge=0, le=5)
    user_agent: str = Field(min_length=5, max_length=200)
    max_redirects: int = Field(ge=0, le=10)
    max_response_bytes: int = Field(gt=0, le=20_000_000)
    max_article_chars: int = Field(gt=0, le=200_000)


class DedupeCfg(_Strict):
    title_similarity: int = Field(ge=50, le=100)
    min_title_tokens: int = Field(ge=1, le=20)


class RankingCfg(_Strict):
    publisher_weight: float = Field(ge=0, le=1)
    priority_weight: float = Field(ge=0, le=1)
    impact_weight: float = Field(ge=0, le=1)
    publisher_cap: int = Field(gt=0, le=20)
    official_multiplier: int = Field(ge=1, le=5)
    news_of_the_day: int = Field(ge=1, le=10)
    impact_keywords: list[str] = Field(max_length=50)


class PriorityCfg(_Strict):
    cvss: float = Field(ge=0, le=1)
    epss: float = Field(ge=0, le=1)
    kev: float = Field(ge=0, le=1)


class AICfg(_Strict):
    default_model: str
    allowed_models: list[str] = Field(min_length=1, max_length=5)
    endpoint: HttpUrl
    timeout_seconds: float = Field(gt=0, le=300)
    requests_per_minute: int = Field(gt=0, le=600)
    max_requests_per_run: int = Field(gt=0, le=1000)
    max_input_chars: int = Field(gt=0, le=50_000)
    max_output_tokens: int = Field(gt=0, le=4000)

    @field_validator("endpoint")
    @classmethod
    def _https_only(cls, v: HttpUrl) -> HttpUrl:
        if v.scheme != "https":
            raise ValueError("AI endpoint must use https")
        return v


class LayoutCfg(_Strict):
    max_words: int = Field(gt=100, le=5000)
    words_per_minute: int = Field(gt=50, le=1000)


class Config(_Strict):
    edition: EditionCfg
    collection: CollectionCfg
    dedupe: DedupeCfg
    ranking: RankingCfg
    priority: PriorityCfg
    ai: AICfg
    layout: LayoutCfg


class Source(_Strict):
    name: str = Field(min_length=1, max_length=60)
    url: HttpUrl
    type: Literal["rss"]
    tier: Literal["official", "news"]

    @field_validator("url")
    @classmethod
    def _https_only(cls, v: HttpUrl) -> HttpUrl:
        if v.scheme != "https":
            raise ValueError("source URLs must use https")
        return v


class SourceList(_Strict):
    sources: list[Source] = Field(min_length=1, max_length=20)


def _load_yaml(path: Path) -> object:
    raw = path.read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError(f"{path} is larger than {MAX_CONFIG_BYTES} bytes")
    return yaml.safe_load(raw)


def load_config(path: Path) -> Config:
    return Config.model_validate(_load_yaml(path))


def load_sources(path: Path) -> list[Source]:
    return SourceList.model_validate(_load_yaml(path)).sources
