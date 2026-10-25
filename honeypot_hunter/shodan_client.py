"""Minimal, passive Shodan REST client.

Design rules carried over from the original artifact:

* Only ``api.shodan.io`` is ever contacted. The base URL is a constant and
  every request URL is re-checked against it before it is sent.
* The API key stays server-side. It is read from the environment (or a
  ``.env`` file), appended to the query string at send time, and scrubbed
  from every error message so it can never leak into the UI, logs or DB.
* Requests are paced (~1.1 s apart) to respect Shodan's 1 req/s limit.
* A 429 is a hard stop: it is reported to the caller and never retried.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional

SHODAN_BASE = "https://api.shodan.io"
ALLOWED_HOST = "api.shodan.io"
USER_AGENT = "honeypot-hunter/2.0 (+passive; shodan-only)"
MIN_INTERVAL_S = 1.1
DEFAULT_FACETS = "country:10,org:10,port:10,city:10,product:10"
MAX_BODY_BYTES = 32_000_000  # larger responses are reported as truncated, never parsed


class ShodanError(Exception):
    """A Shodan call failed. ``status`` is the HTTP status (0 = transport)."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class RateLimited(ShodanError):
    """Shodan returned 429. Callers must stop, not retry."""


class MissingKey(ShodanError):
    pass


# A transport takes a fully-built URL and returns (status, body_bytes).
Transport = Callable[[str, float], "tuple[int, bytes]"]


def _urllib_transport(url: str, timeout: float) -> "tuple[int, bytes]":
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Read one byte past the cap so the client can tell "exactly full" from "cut off".
            return resp.status, resp.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(64_000)
        except Exception:
            pass
        return exc.code, body


def load_dotenv(path: Path) -> None:
    """Tiny .env reader (KEY=VALUE lines). Never overrides real env vars."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def resolve_key() -> Optional[str]:
    from .paths import DATA_DIR
    for candidate in (Path.cwd() / ".env", DATA_DIR / ".env", Path(__file__).resolve().parent.parent / ".env"):
        load_dotenv(candidate)
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    return key or None


class ShodanClient:
    def __init__(self, api_key: Optional[str] = None, transport: Optional[Transport] = None, min_interval: float = MIN_INTERVAL_S, timeout: float = 45.0):
        self._key = api_key if api_key is not None else resolve_key()
        self._transport = transport or _urllib_transport
        self._min_interval = min_interval
        self._timeout = timeout
        self._lock = threading.Lock()
        self._last_call = 0.0
        self.calls: list[str] = []  # path log (no key) — handy for tests and audit

    @property
    def has_key(self) -> bool:
        return bool(self._key)

    def _redact(self, text: str) -> str:
        return text.replace(self._key, "***") if self._key else text

    def _get(self, path: str, params: dict[str, Any]) -> Any:
        if not self._key:
            raise MissingKey("No Shodan API key configured. Set SHODAN_API_KEY in your environment or .env file.")
        clean = {k: v for k, v in params.items() if v is not None}
        url = f"{SHODAN_BASE}{path}?" + urllib.parse.urlencode({**clean, "key": self._key})
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != ALLOWED_HOST:
            raise ShodanError("Refusing to contact a host other than api.shodan.io.")
        with self._lock:
            wait = self._last_call + self._min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
            self.calls.append(path)
            try:
                status, body = self._transport(url, self._timeout)
            except Exception as exc:  # network failure
                raise ShodanError(self._redact(f"Shodan could not be reached: {exc.__class__.__name__}"), 0) from None
        if status == 429:
            raise RateLimited("Shodan's request limit was reached. Nothing was retried — wait and try again.", 429)
        if status in (401, 403):
            raise ShodanError(self._shodan_message(body) or "Shodan refused this request for your key or plan.", status)
        if status == 404:
            raise ShodanError(self._shodan_message(body) or "Shodan has no data for this request.", 404)
        if status < 200 or status >= 300:
            raise ShodanError(self._shodan_message(body) or f"Shodan returned HTTP {status}.", status)
        if len(body) > MAX_BODY_BYTES:
            raise ShodanError(
                f"Shodan's response was larger than {MAX_BODY_BYTES // 1_000_000} MB and was cut off before parsing. "
                "Narrow the query so each page returns less data.", status)
        try:
            return json.loads(body.decode("utf-8") or "null")
        except ValueError:
            raise ShodanError(f"Shodan returned a response that was not JSON ({len(body):,} bytes, HTTP {status}).", status) from None

    def _shodan_message(self, body: bytes) -> Optional[str]:
        try:
            data = json.loads(body.decode("utf-8"))
            if isinstance(data, dict) and isinstance(data.get("error"), str):
                return self._redact(data["error"])[:300]
        except Exception:
            pass
        return None

    # ---- endpoints -------------------------------------------------------

    def api_info(self) -> dict:
        """Plan + remaining credits. Free."""
        return self._get("/api-info", {}) or {}

    def count(self, query: str, facets: Optional[str] = DEFAULT_FACETS) -> dict:
        """/shodan/host/count — free, never consumes query credits."""
        return self._get("/shodan/host/count", {"query": query, "facets": facets}) or {}

    def search(self, query: str, page: int = 1) -> dict:
        """/shodan/host/search — costs 1 query credit per page when filters are used."""
        return self._get("/shodan/host/search", {"query": query, "page": page, "minify": "false"}) or {}

    def host(self, ip: str, history: bool = False) -> dict:
        """/shodan/host/{ip} — host lookup; history=true returns every stored banner."""
        return self._get("/shodan/host/" + urllib.parse.quote(ip), {"history": "true" if history else "false", "minify": "false"}) or {}

