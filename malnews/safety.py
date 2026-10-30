"""Security controls shared by the pipeline (PRD §3).

SR-2  safe_href, RenderURLFetcher   rendering cannot read files or reach the network
SR-6  SafeFetcher, RobotsCache      outbound HTTP cannot reach internal addresses
"""

from __future__ import annotations

import html
import ipaddress
import logging
import mimetypes
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from urllib import robotparser
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

import requests
from weasyprint.urls import URLFetcher, URLFetcherResponse

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cves(text: str) -> set[str]:
    """FR-7: CVE IDs come from source text by regex, never from AI."""
    return {m.upper() for m in CVE_RE.findall(text)}


# --------------------------------------------------------------------------
# Text and links
# --------------------------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]*>")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")
_WS_RE = re.compile(r"\s+")


def clean_text(value: str | None, limit: int | None = None) -> str:
    """Feed HTML to plain text. Output is still untrusted and is escaped at render time."""
    text = html.unescape(_TAG_RE.sub(" ", value or ""))
    text = _WS_RE.sub(" ", _CTRL_RE.sub("", text)).strip()
    return text[:limit] if limit else text


_TRACKING_PARAMS = re.compile(r"^(utm_\w+|fbclid|gclid|mc_cid|mc_eid|ref|source)$", re.I)
_HOST_RE = re.compile(r"^[a-z0-9.-]+$")


def safe_href(url: str | None) -> str | None:
    """Return an https URL safe to print as a link, or None (SR-2).

    Rejects javascript:, data:, file: and anything that is not http(s);
    upgrades http to https; rejects credentials, odd hosts and control chars.
    """
    if not url or len(url) > 2048 or _CTRL_RE.search(url) or re.search(r"\s", url):
        return None
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    if not host or not _HOST_RE.match(host) or "." not in host or parts.username or parts.password:
        return None
    if port not in (None, 80, 443):
        return None
    return urlunsplit(("https", host, parts.path or "/", parts.query, parts.fragment))


def canonical_url(url: str) -> str:
    """FR-4: canonical form for de-duplication (no tracking params, fragment or trailing slash)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().removeprefix("www.")
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query) if not _TRACKING_PARAMS.match(k)])
    return urlunsplit(("https", host, parts.path.rstrip("/") or "/", query, ""))


# --------------------------------------------------------------------------
# SR-6: outbound fetching
# --------------------------------------------------------------------------

class FetchError(Exception):
    pass


class BlockedURL(FetchError):
    pass


class HTTPStatusError(FetchError):
    def __init__(self, status: int, url: str):
        super().__init__(f"HTTP {status} for {url}")
        self.status = status


def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_url(url: str) -> None:
    """http(s) only, no credentials, and the host must resolve only to public addresses."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise BlockedURL(f"URL not allowed: {url[:80]}")
    try:
        literal = is_public_ip(parts.hostname)
    except ValueError:
        literal = None  # a hostname, not an IP address
    if literal is False:
        raise BlockedURL(f"{parts.hostname} is a non-public address")
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(parts.hostname, parts.port or 443)}
    except socket.gaierror as e:
        raise FetchError(f"cannot resolve {parts.hostname}: {e}") from e
    if not addrs or not all(is_public_ip(a) for a in addrs):
        raise BlockedURL(f"{parts.hostname} resolves to a non-public address")


@dataclass
class FetchResult:
    url: str
    content: bytes


class SafeFetcher:
    """The only way the pipeline reads from the internet (SR-6).

    Every URL, including each redirect hop, must be http(s) and resolve to a
    public address. Responses are size-capped and TLS is always verified.
    """

    def __init__(self, *, user_agent: str, timeout: float, retries: int, max_redirects: int, max_bytes: int):
        self.timeout = timeout
        self.retries = retries
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes
        self.session = requests.Session()
        self.session.trust_env = False  # ignore proxy and CA-bundle overrides from the environment
        self.session.verify = True
        self.session.headers["User-Agent"] = user_agent

    def get(self, url: str) -> FetchResult:
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(2 ** (attempt - 1))
            try:
                return self._get_once(url)
            except HTTPStatusError as e:
                if e.status < 500:
                    raise
                last = e
            except (requests.ConnectionError, requests.Timeout) as e:
                last = e
        raise FetchError(f"giving up on {url[:120]}: {last}")

    def _get_once(self, url: str) -> FetchResult:
        for _ in range(self.max_redirects + 1):
            check_url(url)
            with self.session.get(url, stream=True, allow_redirects=False, timeout=self.timeout) as resp:
                if resp.is_redirect:
                    url = urljoin(url, resp.headers.get("location", ""))
                    continue
                if resp.status_code != 200:
                    raise HTTPStatusError(resp.status_code, url)
                body = b""
                for chunk in resp.iter_content(65536):
                    body += chunk
                    if len(body) > self.max_bytes:
                        raise FetchError(f"response larger than {self.max_bytes} bytes")
                return FetchResult(url, body)
        raise FetchError(f"more than {self.max_redirects} redirects")


class RobotsCache:
    """FR-2: honor robots.txt. 404 means allowed; any other failure means not allowed."""

    def __init__(self, fetcher, user_agent: str):
        self.fetcher = fetcher
        self.agent = user_agent.split("/")[0]
        self._cache: dict[str, robotparser.RobotFileParser | bool] = {}

    def allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self._cache:
            self._cache[origin] = self._load(origin)
        entry = self._cache[origin]
        return entry if isinstance(entry, bool) else entry.can_fetch(self.agent, url)

    def _load(self, origin: str) -> robotparser.RobotFileParser | bool:
        try:
            result = self.fetcher.get(origin + "/robots.txt")
        except HTTPStatusError as e:
            return e.status in (404, 410)
        except FetchError as e:
            log.info("robots.txt unavailable for %s (%s); not fetching articles", origin, e)
            return False
        parser = robotparser.RobotFileParser()
        parser.parse(result.content.decode("utf-8", "replace").splitlines())
        return parser


# --------------------------------------------------------------------------
# SR-2: renderer resource fetching
# --------------------------------------------------------------------------

class RenderURLFetcher(URLFetcher):
    """WeasyPrint may only read files inside the given directories.

    Everything else (file:// elsewhere, http(s), data:) is refused and recorded
    in self.blocked, so untrusted text in the PDF can never embed runner files
    such as /proc/self/environ (which holds the API keys) or make requests.
    """

    def __init__(self, allowed_dirs: list[Path]):
        super().__init__(allowed_protocols={"file"})
        self.allowed = [d.resolve() for d in allowed_dirs]
        self.blocked: list[str] = []

    def fetch(self, url, headers=None):
        parts = urlsplit(url)
        path = Path(unquote(parts.path)).resolve() if parts.scheme == "file" else None
        if path is None or parts.netloc not in ("", "localhost") or not any(
            path.is_relative_to(d) for d in self.allowed
        ) or not path.is_file():
            self.blocked.append(url[:200])
            raise ValueError(f"blocked resource: {url[:200]}")
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        return URLFetcherResponse(url, body=path.read_bytes(), headers={"Content-Type": ctype})
