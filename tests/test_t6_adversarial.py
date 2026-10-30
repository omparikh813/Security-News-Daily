"""T6: hostile content cannot make the renderer read local files (such as the
process environment holding the API keys) or reach the network (SR-2).
SSRF and oversized responses are covered in test_safety.py."""

from __future__ import annotations

import io
import re

import pypdf
import pytest

from malnews.models import Story, Summary
from malnews.render import build_edition, render_html_to_pdf, render_pdf
from malnews.safety import RenderURLFetcher

from .conftest import NOW, ROOT, make_article

HOSTILE = [
    '<img src="file:///etc/passwd">',
    '<link rel="attachment" href="file:///proc/self/environ">',
    '<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">',
    '<a href="javascript:alert(1)">x</a>',
]


def pdf_text(pdf: bytes) -> str:
    return " ".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)


def pdf_links(pdf: bytes) -> list[str]:
    return [str(a.get_object()["/A"]["/URI"])
            for p in pypdf.PdfReader(io.BytesIO(pdf)).pages for a in p.get("/Annots") or []]


def test_hostile_headline_and_summary_are_escaped(cfg, no_network):
    s = Story(articles=[make_article(title="Breaking " + " ".join(HOSTILE), url="https://news.example.com/a")],
              summary=Summary(" ".join(HOSTILE), None, is_excerpt=False))
    result = render_pdf(build_edition([s], cfg, NOW, ["Test"]))
    assert result.blocked == []  # escaped, so nothing was even requested
    assert '<img src="file:///etc/passwd">' in pdf_text(result.pdf)  # printed as text
    assert b"/EmbeddedFile" not in result.pdf
    assert pdf_links(result.pdf) == ["https://news.example.com/a"]  # only the feed's own link


def test_renderer_blocks_even_unescaped_html(no_network):
    """Defense in depth: if escaping ever regressed, the fetcher still refuses."""
    result = render_html_to_pdf("<html><body><p>x</p>" + "".join(HOSTILE) + "</body></html>")
    assert b"/EmbeddedFile" not in result.pdf and b"root:" not in result.pdf
    blocked = {re.sub(r"[?#].*", "", u) for u in result.blocked}
    assert blocked >= {"file:///etc/passwd", "http://169.254.169.254/latest/meta-data/"}
    # Attachments are dropped before writing, so the environ file is never even requested.
    assert "file:///proc/self/environ" not in blocked


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "file:///proc/self/environ", "http://example.com/x.css",
    "data:text/css,body{}", (ROOT / "templates" / ".." / "config.yaml").as_uri(),
])
def test_render_fetcher_allowlist(url):
    with pytest.raises(ValueError):
        RenderURLFetcher([ROOT / "templates", ROOT / "fonts"]).fetch(url)


def test_render_fetcher_allows_bundled_font():
    f = RenderURLFetcher([ROOT / "templates", ROOT / "fonts"])
    assert f.fetch((ROOT / "fonts" / "Caladea-Regular.ttf").as_uri()).status == 200
