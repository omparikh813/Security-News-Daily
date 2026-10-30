"""Security controls shared by the pipeline (PRD §3).

SR-1  validate_ai_output, strip_urls      untrusted model output
SR-2  safe_href, RenderURLFetcher         rendering
SR-6  SafeFetcher, RobotsCache            outbound HTTP

Everything fetched from the internet, and everything the model returns, is
untrusted. These helpers are the only way such data reaches the network,
the renderer, or the published PDF.
"""

from __future__ import annotations

import html
import ipaddress
import json
import logging
import mimetypes
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from urllib import robotparser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util import connection as u3conn
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
# SR-1: AI output validation
# --------------------------------------------------------------------------

class InvalidOutput(ValueError):
    pass


_URL_RE = re.compile(r"(https?://|hxxps?://|ftp://|www\.)", re.I)
# Bare domains. PDF viewers auto-link these, so they are rejected too. .zip/.mov
# are left out on purpose: they collide with file names in normal security prose.
_DOMAIN_RE = re.compile(
    r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\."
    r"(com|net|org|io|co|ru|cn|xyz|top|info|biz|me|app|dev|site|online|ly|gg|su|tk|onion|link|click)\b",
    re.I,
)
_MARKUP_RE = re.compile(r"(<\s*[a-z/!?]|\]\(|```|\[[^\]]+\]\[)", re.I)


def strip_urls(text: str) -> str:
    """Remove anything link-like from text we print without AI validation (excerpts)."""
    text = re.sub(r"\S*(https?://|hxxps?://|www\.)\S*", "[link removed]", text, flags=re.I)
    return _DOMAIN_RE.sub("[link removed]", text)


def parse_first_json(raw: str) -> dict:
    """FR-12 tolerant parsing: strip code fences, take the first JSON object."""
    text = re.sub(r"```(?:json)?", "", raw or "", flags=re.I)
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            obj, _ = decoder.raw_decode(text, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    raise InvalidOutput("no JSON object in response")


def validate_ai_output(raw: str, source_text: str, fields: dict[str, tuple[int, bool]]) -> dict:
    """SR-1: accept model output only if it is exactly the expected shape and harmless.

    fields maps name -> (max_chars, nullable). Raises InvalidOutput with the reason.
    """
    data = parse_first_json(raw)
    extra = set(data) - set(fields)
    missing = set(fields) - set(data)
    if extra or missing:
        raise InvalidOutput(f"unexpected keys (extra={sorted(extra)}, missing={sorted(missing)})")

    allowed_cves = extract_cves(source_text)
    out: dict[str, str | None] = {}
    for name, (max_chars, nullable) in fields.items():
        value = data[name]
        if value is None or (isinstance(value, str) and value.strip().lower() in ("", "null", "none")):
            if not nullable:
                raise InvalidOutput(f"{name} is empty")
            out[name] = None
            continue
        if not isinstance(value, str):
            raise InvalidOutput(f"{name} is not a string")
        value = _WS_RE.sub(" ", _CTRL_RE.sub("", value)).strip()
        if len(value) > max_chars:
            raise InvalidOutput(f"{name} longer than {max_chars} chars")
        if _URL_RE.search(value) or _DOMAIN_RE.search(value):
            raise InvalidOutput(f"{name} contains a URL or domain")
        if _MARKUP_RE.search(value):
            raise InvalidOutput(f"{name} contains HTML or Markdown")
        unknown = extract_cves(value) - allowed_cves
        if unknown:
            raise InvalidOutput(f"{name} cites CVEs not in the source: {sorted(unknown)}")
        out[name] = value
    return out


# --------------------------------------------------------------------------
# SR-6: hardened outbound fetching
# --------------------------------------------------------------------------

class FetchError(Exception):
    pass


class BlockedURL(FetchError):
    pass


class HTTPStatusError(FetchError):
    def __init__(self, status: int, url: str):
        super().__init__(f"HTTP {status} for {url}")
        self.status = status


_BLOCKED_HOSTNAMES = ("localhost", "metadata.google.internal")
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_hostname(host: str) -> None:
    host = host.lower().rstrip(".")
    if host in _BLOCKED_HOSTNAMES or host.endswith(_BLOCKED_SUFFIXES):
        raise BlockedURL(f"blocked host {host}")
    try:
        if not is_public_ip(host):
            raise BlockedURL(f"blocked address {host}")
    except ValueError:
        pass  # not an IP literal


def resolve_public(host: str, port: int) -> str:
    """Resolve host and return one address, only if every address is public."""
    check_hostname(host)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise FetchError(f"cannot resolve {host}: {e}") from e
    addrs = [info[4][0] for info in infos]
    bad = [a for a in addrs if not is_public_ip(a)]
    if not addrs or bad:
        raise BlockedURL(f"{host} resolves to non-public address {bad or addrs}")
    return addrs[0]


class _GuardedConnMixin:
    """Connect to the address we validated, closing the DNS-rebinding window.

    TLS still uses the hostname for SNI and certificate checks.
    """

    def _new_conn(self):  # type: ignore[override]
        ip = resolve_public(self._dns_host, self.port)
        try:
            return u3conn.create_connection(
                (ip, self.port), self.timeout,
                source_address=self.source_address, socket_options=self.socket_options,
            )
        except socket.timeout as e:
            raise ConnectTimeoutError(self, f"connect to {self.host} timed out") from e
        except OSError as e:
            raise NewConnectionError(self, f"failed to connect to {self.host}: {e}") from e


class _GuardedHTTPConnection(_GuardedConnMixin, HTTPConnection):
    pass


class _GuardedHTTPSConnection(_GuardedConnMixin, HTTPSConnection):
    pass


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class _GuardedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _GuardedHTTPPool, "https": _GuardedHTTPSPool}


CONTENT_TYPES = {
    "feed": ("xml", "rss", "atom"),
    "html": ("text/html", "application/xhtml+xml"),
    "image": ("image/jpeg", "image/png", "image/webp"),
    "robots": ("text/plain",),
}


@dataclass
class FetchResult:
    url: str
    content: bytes
    content_type: str


class SafeFetcher:
    """The only way the pipeline reads from the internet (SR-6).

    http(s) only, no credentials, ports 80/443, every redirect hop re-checked,
    private/loopback/link-local/reserved addresses blocked at connect time,
    TLS always verified, response size and Content-Type enforced.

    A corporate proxy (local development only) is used when allow_env_proxy is
    True; the proxy then resolves DNS, so only hostname and IP-literal checks apply.
    """

    def __init__(self, *, user_agent: str, timeout: float, retries: int, max_redirects: int,
                 max_bytes: dict[str, int], allow_env_proxy: bool = False,
                 session: requests.Session | None = None):
        self.timeout = timeout
        self.retries = retries
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes
        self.proxied = allow_env_proxy
        if session is None:
            session = requests.Session()
            session.trust_env = allow_env_proxy
            adapter = _GuardedAdapter(max_retries=0)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
        session.headers.update({"User-Agent": user_agent})
        session.verify = True
        self.session = session

    def _check_url(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise BlockedURL(f"scheme not allowed: {url[:80]}")
        if not parts.hostname or parts.username or parts.password:
            raise BlockedURL(f"bad host or credentials in URL: {url[:80]}")
        if parts.port not in (None, 80, 443):
            raise BlockedURL(f"port not allowed: {url[:80]}")
        check_hostname(parts.hostname)
        if not self.proxied:
            resolve_public(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))

    def get(self, url: str, kind: str) -> FetchResult:
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(2 ** (attempt - 1))
            try:
                return self._get_once(url, kind)
            except (BlockedURL, HTTPStatusError) as e:
                if isinstance(e, HTTPStatusError) and e.status >= 500:
                    last = e
                    continue
                raise
            except (requests.ConnectionError, requests.Timeout) as e:
                last = e
        raise FetchError(f"giving up on {url[:120]}: {last}")

    def _get_once(self, url: str, kind: str) -> FetchResult:
        for _ in range(self.max_redirects + 1):
            self._check_url(url)
            resp = self.session.get(url, stream=True, allow_redirects=False, timeout=self.timeout)
            try:
                if resp.is_redirect:
                    url = urljoin(url, resp.headers.get("location", ""))
                    continue
                if resp.status_code != 200:
                    raise HTTPStatusError(resp.status_code, url)
                ctype = resp.headers.get("content-type", "").lower()
                if not any(t in ctype for t in CONTENT_TYPES[kind]):
                    raise FetchError(f"unexpected Content-Type {ctype!r} for {kind}")
                return FetchResult(url, self._read_capped(resp, self.max_bytes[kind]), ctype)
            finally:
                resp.close()
        raise FetchError(f"more than {self.max_redirects} redirects")

    @staticmethod
    def _read_capped(resp: requests.Response, cap: int) -> bytes:
        declared = resp.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > cap:
            raise FetchError(f"response larger than {cap} bytes")
        chunks, size = [], 0
        for chunk in resp.iter_content(65536):
            size += len(chunk)
            if size > cap:
                raise FetchError(f"response larger than {cap} bytes")
            chunks.append(chunk)
        return b"".join(chunks)


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
            result = self.fetcher.get(origin + "/robots.txt", "robots")
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

    Everything else (file:// elsewhere, http(s), data:, attachments) is refused
    and recorded in self.blocked, so the PDF can never embed runner files or
    make network requests on behalf of untrusted content.
    """

    def __init__(self, allowed_dirs: list[Path]):
        super().__init__(allowed_protocols={"file"})
        self.allowed = [d.resolve() for d in allowed_dirs]
        self.blocked: list[str] = []

    def fetch(self, url, headers=None):
        parts = urlsplit(url)
        path = Path(requests.utils.unquote(parts.path)).resolve() if parts.scheme == "file" else None
        if path is None or parts.netloc not in ("", "localhost") or not any(
            path.is_relative_to(d) for d in self.allowed
        ) or not path.is_file():
            self.blocked.append(url[:200])
            raise ValueError(f"blocked resource: {url[:200]}")
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        return URLFetcherResponse(url, body=path.read_bytes(), headers={"Content-Type": ctype})
