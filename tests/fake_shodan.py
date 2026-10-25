"""Offline stand-in for api.shodan.io used by the tests and the demo server.

It is plugged in as the ShodanClient *transport*, so the real client code —
URL building, host allow-listing, key handling, pacing, error mapping —
runs unchanged. Data is synthetic but shaped like real Shodan responses.
"""

from __future__ import annotations

import json
import zlib
from urllib.parse import parse_qs, urlparse

TS_IN = "2026-10-23T08:32:44.123456"
HEADERS_HASH = -1150823112  # same Apache/PHP config on every fixture host

# The profile the fixtures are built to match (test-only; shipped presets are placeholders).
TEST_PRESET = {
    "profile": {"org": "Amazon Technologies Inc.", "port": "80", "product": "Apache httpd", "serverVersion": "2.4.99",
                "langBanner": "PHP/8.9.9", "cms": 'http.component:"WordPress"', "country": "IE", "city": "", "vuln": "CVE-2099-12345",
                "hostname": "", "title": ""},
    "windowStart": "2026-10-22", "windowEnd": "2026-10-24",
}


def _banner(ip, port, *, ts=TS_IN, product="Apache httpd", version="2.4.99", title=None, org="Amazon Technologies Inc.",
            hostnames=None, domains=None, tags=None, vulns=None, country="IE", city="Dublin", data="HTTP/1.1 200 OK\r\nServer: Apache/2.4.99 (Debian)\r\nX-Powered-By: PHP/8.9.9"):
    b = {
        "ip_str": ip, "port": port, "transport": "tcp", "timestamp": ts, "org": org, "isp": org, "asn": "AS64501",
        "hostnames": hostnames if hostnames is not None else [f"ec2-{ip.replace('.', '-')}.eu-west-1.compute.amazonaws.com"],
        "domains": domains if domains is not None else ["amazonaws.com"],
        "location": {"country_code": country, "city": city, "region_code": "L"},
        "product": product, "version": version, "data": data,
        "cpe23": ["cpe:2.3:a:apache:http_server:2.4.99", "cpe:2.3:a:php:php:8.9.9"],
        "vulns": {v: {"cvss": 9.8} for v in (vulns if vulns is not None else ["CVE-2099-12345", "CVE-2099-12346"])},
        "tags": tags if tags is not None else ["cloud"],
    }
    if title is not None:
        # Shodan hashes the page body; a fixed title stands in for a fixed page here.
        b["http"] = {"title": title, "server": f"{product}/{version}", "html_hash": zlib.crc32(title.encode()) - 2**31, "headers_hash": HEADERS_HASH}
    return b


HOSTS = {
    # Campaign-fleet sensor (reference #1 shape)
    "203.0.113.10": {"current": [_banner("203.0.113.10", 80, title="Internal Dashboard – Team &amp; Project Updates")],
                      "history": [_banner("203.0.113.10", 80, title="Internal Dashboard – Team &amp; Project Updates")]},
    # Reference #2
    "203.0.113.20": {"current": [_banner("203.0.113.20", 80, ts="2026-10-23T15:52:49.000000", title="Staff Portal", country="JP", city="Tokyo",
                                         hostnames=["ec2-203-0-113-20.ap-northeast-1.compute.amazonaws.com"])],
                     "history": [_banner("203.0.113.20", 80, ts="2026-10-23T15:52:49.000000", title="Staff Portal", country="JP", city="Tokyo")]},
    # Production-looking host: real domain, SSH + several ports, long churning history
    "198.51.100.20": {"current": [_banner("198.51.100.20", 80, title="Acme Corp — Careers", hostnames=["www.acme-example.com"], domains=["acme-example.com"]),
                                 _banner("198.51.100.20", 443, product="nginx", version="1.27.0", title="Acme Corp — Careers", hostnames=["www.acme-example.com"], domains=["acme-example.com"]),
                                 _banner("198.51.100.20", 22, product="OpenSSH", version="9.6p1", hostnames=["www.acme-example.com"], domains=["acme-example.com"]),
                                 _banner("198.51.100.20", 8080, product="Jetty", version="12.0", hostnames=["www.acme-example.com"], domains=["acme-example.com"])],
                     "history": [_banner("198.51.100.20", 80, ts="2025-11-02T10:00:00.000000", version="2.4.62", title="Acme Corp"),
                                 _banner("198.51.100.20", 80, ts="2026-04-02T10:00:00.000000", version="2.4.66", title="Acme Corp — Jobs"),
                                 _banner("198.51.100.20", 80, ts=TS_IN, title="Acme Corp — Careers")]},
    # Persistent-fleet sensor: frozen banner for ~10 months, still vuln-flagged, first seen before the window
    "198.51.100.9": {"current": [_banner("198.51.100.9", 80, title="Internal Portal")],
                  "history": [_banner("198.51.100.9", 80, ts=t, title="Internal Portal") for t in
                              ("2025-12-20T03:00:00.000000", "2026-03-11T03:00:00.000000", "2026-06-30T03:00:00.000000", "2026-09-01T03:00:00.000000", TS_IN)]},
    # Research-network host with placeholder rDNS: Shodan reports the domain as the bare TLD "invalid"
    "192.0.2.102": {"current": [_banner("192.0.2.102", 80, title="Example Garden Notes", org="Example Research Network", country="NL", city="Exampleville", tags=[],
                                            hostnames=["192.0.2.EARLY-REGISTRATION.of.example-nren.invalid"], domains=["invalid"])],
                        "history": [_banner("192.0.2.102", 80, title="Example Garden Notes", org="Example Research Network", country="NL", city="Exampleville", tags=[],
                                            hostnames=["192.0.2.EARLY-REGISTRATION.of.example-nren.invalid"], domains=["invalid"])]},
    # Noise host answering on everything
    "198.51.100.99": {"current": [_banner("198.51.100.99", p, title="Welcome to nginx!") for p in range(8000, 8045)],
                   "history": [_banner("198.51.100.99", 80, title="Welcome to nginx!")]},
}

# Ports that "match" the test query (search only returns matching banners!)
SEARCH_MATCHES = [h["current"][0] for h in HOSTS.values()]


class FakeShodan:
    def __init__(self, counts: "dict[str, int] | None" = None, fail_on: "dict[str, int] | None" = None):
        self.counts = counts or {}
        self.fail_on = fail_on or {}   # path prefix -> HTTP status to return
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float):
        self.urls.append(url)
        u = urlparse(url)
        assert u.hostname == "api.shodan.io", u.hostname
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        assert q.get("key") == "TESTKEY"
        for rule, status in self.fail_on.items():
            # rule is a path prefix, or "history" for host lookups with history=true
            hit = (q.get("history") == "true" and u.path.startswith("/shodan/host/")) if rule == "history" else u.path.startswith(rule)
            if hit:
                return status, json.dumps({"error": f"fake {status} for TESTKEY"}).encode()
        if u.path == "/api-info":
            return 200, json.dumps({"plan": "dev", "query_credits": 80, "scan_credits": 100, "unlocked": True}).encode()
        if u.path == "/shodan/host/count":
            query = q.get("query", "")
            total = self.counts.get(query, self._default_count(query))
            body = {"total": total, "matches": []}
            if q.get("facets"):
                body["facets"] = {
                    "org": [{"value": "Amazon Technologies Inc.", "count": max(1, total // 2)}, {"value": "Hetzner Online GmbH", "count": max(1, total // 5)}],
                    "country": [{"value": "IE", "count": max(1, total // 3)}, {"value": "JP", "count": max(1, total // 4)}],
                    "port": [{"value": 80, "count": total}],
                    "city": [{"value": "Dublin", "count": max(1, total // 3)}, {"value": "Tokyo", "count": max(1, total // 4)}],
                    "product": [{"value": "Apache httpd", "count": total}],
                }
            return 200, json.dumps(body).encode()
        if u.path == "/shodan/host/search":
            return 200, json.dumps({"total": len(SEARCH_MATCHES), "matches": SEARCH_MATCHES}).encode()
        if u.path.startswith("/shodan/host/"):
            ip = u.path.rsplit("/", 1)[1]
            if ip not in HOSTS:
                return 404, b'{"error": "No information available for that IP."}'
            h = HOSTS[ip]
            data = h["history"] if q.get("history") == "true" else h["current"]
            ports = sorted({b["port"] for b in h["current"]})
            first = h["current"][0]
            vulns = sorted({v for b in h["current"] for v in b["vulns"]})
            return 200, json.dumps({"ip_str": ip, "org": first["org"], "isp": first["isp"], "asn": first["asn"], "os": None,
                                    "ports": ports, "hostnames": first["hostnames"], "domains": first["domains"], "tags": first["tags"],
                                    "vulns": vulns, "country_code": first["location"]["country_code"], "city": first["location"]["city"],
                                    "last_update": max(b["timestamp"] for b in h["current"]), "data": data}).encode()
        return 404, b'{"error":"unknown"}'

    @staticmethod
    def _default_count(query: str) -> int:
        # Each extra filter shrinks the pool — mimics a narrowing ladder.
        n = query.count(":") + query.count('"') // 2
        return max(5, 4000 // (3 ** max(0, n - 2)))
