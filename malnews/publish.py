"""Stage 6: write the site folder (FR-21). Deployment to Pages arrives in Phase 3."""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
from pathlib import Path

from .render import TEMPLATES, jinja_env

_ARCHIVE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.pdf$")


def write_site(pdf: bytes, out_dir: Path, day: str) -> Path:
    """Write latest.pdf, archive/<day>.pdf and index.html atomically.

    Everything is built in a temporary folder next to out_dir and swapped in
    only when complete, so a failed run never leaves a half-written site.
    """
    out_dir = out_dir.resolve()
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".malnews-", dir=out_dir.parent))
    tmp.chmod(0o755)
    try:
        if (out_dir / "archive").is_dir():
            shutil.copytree(out_dir / "archive", tmp / "archive")
        (tmp / "archive").mkdir(exist_ok=True)
        (tmp / "archive" / f"{day}.pdf").write_bytes(pdf)  # re-running a day overwrites it
        (tmp / "latest.pdf").write_bytes(pdf)

        editions = []
        for f in sorted((tmp / "archive").iterdir(), reverse=True):
            if _ARCHIVE_RE.match(f.name):
                editions.append({"day": f.stem, "href": f"archive/{f.name}",
                                 "sha256": hashlib.sha256(f.read_bytes()).hexdigest()})
        html = jinja_env().get_template("index.html.j2").render(editions=editions)
        (tmp / "index.html").write_text(html, encoding="utf-8")
        shutil.copyfile(TEMPLATES / "index.css", tmp / "index.css")

        if out_dir.exists():
            shutil.rmtree(out_dir)
        tmp.rename(out_dir)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out_dir
