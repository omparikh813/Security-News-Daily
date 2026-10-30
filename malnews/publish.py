"""Stage 6: write the site folder (FR-21). Deployment to Pages arrives in Phase 3."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from .render import TEMPLATES, jinja_env

_ARCHIVE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.pdf$")


def write_site(pdf: bytes, out_dir: Path, day: str) -> None:
    """Write latest.pdf, archive/<day>.pdf (re-running a day overwrites it) and index.html."""
    archive = out_dir / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    (archive / f"{day}.pdf").write_bytes(pdf)
    (out_dir / "latest.pdf").write_bytes(pdf)

    days = sorted((f.stem for f in archive.iterdir() if _ARCHIVE_RE.match(f.name)), reverse=True)
    html = jinja_env().get_template("index.html.j2").render(days=days)
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    shutil.copyfile(TEMPLATES / "index.css", out_dir / "index.css")
