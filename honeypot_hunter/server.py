"""Local web console — a small JSON API plus a single static page.

Security posture (the server holds your Shodan key and can spend credits):

* Binds to 127.0.0.1 by default.
* Rejects requests whose Host header isn't the address it was started on
  (blocks DNS-rebinding attacks from web pages you visit).
* Every state-changing call must be a JSON POST carrying the
  ``X-Honeypot-Hunter`` header. Browsers can't send a custom header
  cross-origin without a CORS preflight, which this server never approves,
  so another website can't make your browser spend your credits.
* The API key never appears in any response.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import traceback
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .hunt import CONFIRM_ABOVE, MAX_POOL, PRESETS, REFERENCE_SENSORS, Hunter, HuntError, build_stages
from .scoring import POSSIBLE, STRONG

STATIC = Path(__file__).resolve().parent / "static"
CSRF_HEADER = "X-Honeypot-Hunter"
MAX_BODY = 256_000


def make_handler(hunter: Hunter, allowed_hosts: set[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"honeypot-hunter/{__version__}"

        def log_message(self, fmt: str, *args: Any) -> None:  # quieter, and never log query strings
            sys.stderr.write(f"[hh] {self.command} {urlparse(self.path).path} → {args[1] if len(args) > 1 else ''}\n")

        # ---- plumbing -------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str, extra: "dict[str, str] | None" = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj: Any, status: int = 200) -> None:
            self._send(status, json.dumps(obj, default=str).encode("utf-8"), "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            if host not in allowed_hosts:
                self._json({"error": "Host not allowed."}, 403)
                return False
            return True

        def _body(self) -> dict:
            if self.headers.get(CSRF_HEADER) != "1" or "application/json" not in (self.headers.get("Content-Type") or ""):
                raise PermissionError("Missing CSRF header or JSON content type.")
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc.lower() not in allowed_hosts:
                raise PermissionError("Cross-origin request refused.")
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise HuntError("Request too large.")
            raw = self.rfile.read(n) if n else b"{}"
            data = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(data, dict):
                raise HuntError("Expected a JSON object.")
            return data

        # ---- routes --------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            if not self._host_ok():
                return
            u = urlparse(self.path)
            path = u.path
            try:
                if path in ("/", "/index.html"):
                    return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
                if path == "/api/bootstrap":
                    return self._json({
                        "version": __version__, "hasKey": hunter.client.has_key, "presets": PRESETS,
                        "referenceSensors": REFERENCE_SENSORS, "limits": {"maxPool": MAX_POOL, "confirmAbove": CONFIRM_ABOVE},
                        "bands": {"strong": STRONG, "possible": POSSIBLE},
                    })
                if path == "/api/info":
                    return self._json(hunter.info())
                if path == "/api/hunts":
                    return self._json({"hunts": hunter.store.list_hunts()})
                m = re.fullmatch(r"/api/hunts/(\d+)", path)
                if m:
                    h = hunter.store.get_hunt(int(m.group(1)))
                    return self._json(h or {"hunt": None, "candidates": []}, 200 if h else 404)
                m = re.fullmatch(r"/api/hunts/(\d+)/export", path)
                if m:
                    fmt = (parse_qs(u.query).get("format") or ["md"])[0]
                    hid = int(m.group(1))
                    if fmt == "json":
                        body = json.dumps(hunter.export_json(hid), indent=2, default=str).encode("utf-8")
                        return self._send(200, body, "application/json; charset=utf-8", {"Content-Disposition": f'attachment; filename="honeypot-hunt-{hid}.json"'})
                    fname, text = hunter.export_markdown(hid)
                    return self._send(200, text.encode("utf-8"), "text/markdown; charset=utf-8", {"Content-Disposition": f'attachment; filename="{fname}"'})
                self._json({"error": "Not found."}, 404)
            except HuntError as e:
                self._json({"error": str(e)}, 400)
            except Exception:
                traceback.print_exc()
                self._json({"error": "Internal error."}, 500)

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok():
                return
            path = urlparse(self.path).path
            try:
                b = self._body()
                if path == "/api/stages":
                    return self._json({"stages": build_stages(b.get("profile") or {})})
                if path == "/api/explore":
                    return self._json(hunter.explore(str(b.get("query") or "")))
                if path == "/api/ladder":
                    stages = b.get("stages")
                    if not isinstance(stages, list):
                        raise HuntError("stages must be a list")
                    return self._json({"stages": hunter.count_ladder(stages)})
                if path == "/api/hunt":
                    return self._json(hunter.run_hunt(
                        str(b.get("name") or ""), str(b.get("query") or ""), b.get("profile") or {},
                        b.get("ladder") if isinstance(b.get("ladder"), list) else None,
                        b.get("windowStart"), b.get("windowEnd"), bool(b.get("confirmed")),
                    ))
                if path == "/api/inspect":
                    cid = b.get("candidateId")
                    return self._json(hunter.inspect(str(b.get("ip") or ""), int(cid) if cid is not None else None))
                m = re.fullmatch(r"/api/hunts/(\d+)/inspect-top", path)
                if m:
                    return self._json(hunter.inspect_top(int(m.group(1)), int(b.get("n") or 10)))
                m = re.fullmatch(r"/api/hunts/(\d+)/delete", path)
                if m:
                    hunter.store.delete_hunt(int(m.group(1)))
                    return self._json({"ok": True})
                if path == "/api/verdict":
                    ok = hunter.store.set_verdict(int(b["candidateId"]), str(b.get("verdict")), b.get("notes") if isinstance(b.get("notes"), str) else None)
                    return self._json({"ok": ok}, 200 if ok else 404)
                self._json({"error": "Not found."}, 404)
            except PermissionError as e:
                self._json({"error": str(e)}, 403)
            except (HuntError, ValueError, KeyError, TypeError) as e:
                self._json({"error": str(e) or "Bad request."}, 400)
            except Exception:
                traceback.print_exc()
                self._json({"error": "Internal error."}, 500)

        def do_OPTIONS(self) -> None:  # noqa: N802 — never approve CORS preflights
            self._json({"error": "CORS not supported."}, HTTPStatus.FORBIDDEN)

    return Handler


def build_server(hunter: Hunter, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    allowed = {f"{h}:{port}" for h in ("127.0.0.1", "localhost", "[::1]")}
    if host not in ("127.0.0.1", "localhost", "::1"):
        allowed.add(f"{host}:{port}")
    httpd = ThreadingHTTPServer((host, port), make_handler(hunter, allowed))
    httpd.daemon_threads = True
    return httpd


def serve(hunter: Hunter, host: str = "127.0.0.1", port: int = 8787, open_browser: bool = True) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: binding to {host} exposes a console that can spend your Shodan credits to your network.", file=sys.stderr)
    httpd = build_server(hunter, host, port)
    url = f"http://127.0.0.1:{port}/" if host in ("127.0.0.1", "0.0.0.0") else f"http://{host}:{port}/"
    print(f"Honeypot Hunter {__version__} → {url}")
    print("Shodan key:", "loaded" if hunter.client.has_key else "MISSING — set SHODAN_API_KEY")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
