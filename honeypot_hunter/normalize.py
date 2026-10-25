"""Turn raw Shodan JSON into the compact shapes the scorer and UI use."""

from __future__ import annotations

import html
from typing import Any

# Product / banner substrings of well-known open-source honeypot software.
# Matching is case-insensitive substring; a hit is strong evidence on its own.
HONEYPOT_SOFTWARE = [
    "honeypot", "cowrie", "kippo", "dionaea", "conpot", "glastopf", "honeypy",
    "elastichoney", "opencanary", "t-pot", "tpot", "hellpot", "mailoney",
    "amun", "heralding", "honeytrap", "gaspot", "citrixhoneypot", "wordpot",
    "snare", "tanner", "adbhoney", "redishoneypot", "ciscoasa_honeypot",
]


def _s(value: Any, limit: int) -> "str | None":
    return value[:limit] if isinstance(value, str) and value.strip() else None


def _vuln_ids(raw: Any) -> list[str]:
    # Banners carry vulns as {CVE: {...}}; host records as [CVE, ...].
    if isinstance(raw, dict):
        return [k[:40] for k in raw.keys() if isinstance(k, str)]
    if isinstance(raw, list):
        return [v[:40] for v in raw if isinstance(v, str)]
    return []


# Content / infrastructure fingerprints Shodan computes per banner. They are
# what a cloned deployment shares even when its IPs, orgs and domains differ.
FP_KINDS = ("html", "title", "headers", "favicon", "robots", "cert", "jarm", "ssh", "hassh")


def _fp_value(v: Any) -> "str | None":
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str) and v.strip():
        return v.strip()[:128]
    return None


def banner_fingerprints(b: dict) -> dict:
    """{kind: value} for one raw Shodan banner (missing kinds are omitted)."""
    http = b.get("http") if isinstance(b.get("http"), dict) else {}
    fav = http.get("favicon") if isinstance(http.get("favicon"), dict) else {}
    ssl = b.get("ssl") if isinstance(b.get("ssl"), dict) else {}
    cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
    certfp = cert.get("fingerprint") if isinstance(cert.get("fingerprint"), dict) else {}
    ssh = b.get("ssh") if isinstance(b.get("ssh"), dict) else {}
    title = http.get("title")
    raw = {
        "html": http.get("html_hash"), "headers": http.get("headers_hash"), "favicon": fav.get("hash"),
        "robots": http.get("robots_hash"),
        "title": html.unescape(title.strip())[:200] if isinstance(title, str) and title.strip() else None,
        "cert": certfp.get("sha256"), "jarm": ssl.get("jarm"),
        "ssh": ssh.get("fingerprint"), "hassh": ssh.get("hassh"),
    }
    return {k: v for k, v in ((k, _fp_value(v)) for k, v in raw.items()) if v is not None}


def add_fingerprints(into: dict, fps: dict) -> None:
    for k, v in fps.items():
        vals = into.setdefault(k, [])
        if v not in vals and len(vals) < 8:
            vals.append(v)


def software_hints(*texts: "str | None") -> list[str]:
    hits: list[str] = []
    for t in texts:
        if not t:
            continue
        low = t.lower()
        for name in HONEYPOT_SOFTWARE:
            if name in low and name not in hits:
                hits.append(name)
    return hits


def empty_candidate(ip: str) -> dict:
    return {
        "ip": ip, "org": None, "asn": None, "country": None, "city": None,
        "ports": [], "ports_verified": False, "hostnames": [], "domains": [], "tags": [], "vulns": [],
        "title": None, "product": None, "version": None, "os": None,
        "last_seen": None, "banner_count": 0, "software_hints": [], "fp": {},
    }


def merge_search_matches(matches: list[Any], limit: int = 100) -> list[dict]:
    """Collapse per-banner search matches into one row per IP.

    Caveat that drives the two-phase scoring: a search only returns banners
    that *match the query*, so ``ports`` here is "ports that matched", not
    the host's full port list. ``ports_verified`` stays False until the host
    is inspected.
    """
    by_ip: dict[str, dict] = {}
    for m in matches:
        if not isinstance(m, dict) or not isinstance(m.get("ip_str"), str):
            continue
        ip = m["ip_str"]
        row = by_ip.setdefault(ip, empty_candidate(ip))
        row["banner_count"] += 1
        for key, limit_ in (("org", 160), ("asn", 40), ("os", 80)):
            if row[key] is None:
                row[key] = _s(m.get(key), limit_)
        loc = m.get("location") if isinstance(m.get("location"), dict) else {}
        if row["country"] is None:
            row["country"] = _s(loc.get("country_code"), 8)
        if row["city"] is None:
            row["city"] = _s(loc.get("city"), 80)
        port = m.get("port")
        if isinstance(port, int) and port not in row["ports"]:
            row["ports"].append(port)
        for key in ("hostnames", "domains", "tags"):
            for v in m.get(key) or []:
                if isinstance(v, str) and v[:253] not in row[key]:
                    row[key].append(v[:253])
        for v in _vuln_ids(m.get("vulns")):
            if v not in row["vulns"]:
                row["vulns"].append(v)
        http = m.get("http") if isinstance(m.get("http"), dict) else {}
        if row["title"] is None and isinstance(http.get("title"), str) and http["title"].strip():
            row["title"] = html.unescape(http["title"].strip())[:200]
        if row["product"] is None and isinstance(m.get("product"), str):
            row["product"] = m["product"][:80]
            row["version"] = _s(m.get("version"), 40)
        ts = m.get("timestamp")
        if isinstance(ts, str) and (row["last_seen"] is None or ts > row["last_seen"]):
            row["last_seen"] = ts[:40]
        add_fingerprints(row["fp"], banner_fingerprints(m))
        for hint in software_hints(_s(m.get("product"), 120), _s(m.get("data"), 2000), row["title"]):
            if hint not in row["software_hints"]:
                row["software_hints"].append(hint)
    rows = list(by_ip.values())
    for row in rows:
        row["ports"].sort()
        row["vulns"] = row["vulns"][:60]
    return rows[:limit]


def _service_row(b: dict) -> dict:
    http = b.get("http") if isinstance(b.get("http"), dict) else {}
    ssl = b.get("ssl") if isinstance(b.get("ssl"), dict) else {}
    cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
    subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
    title = http.get("title")
    return {
        "port": b.get("port") if isinstance(b.get("port"), int) else None,
        "transport": b.get("transport") if isinstance(b.get("transport"), str) else "tcp",
        "product": _s(b.get("product"), 80),
        "version": _s(b.get("version"), 40),
        "cpe": [c[:120] for c in (b.get("cpe23") or b.get("cpe") or []) if isinstance(c, str)][:12],
        "title": html.unescape(title.strip())[:200] if isinstance(title, str) and title.strip() else None,
        "server": _s(http.get("server"), 120),
        "cert_subject": _s(subject.get("CN"), 200),
        "cert_expired": cert.get("expired") if isinstance(cert.get("expired"), bool) else None,
        "cert_self_signed": (cert.get("issuer") == cert.get("subject")) if isinstance(cert.get("issuer"), dict) and isinstance(cert.get("subject"), dict) else None,
        "timestamp": _s(b.get("timestamp"), 40),
        "fp": banner_fingerprints(b),
    }


def _face(b: dict) -> str:
    """What the service 'looks like' at one observation — product + version."""
    prod = b.get("product") if isinstance(b.get("product"), str) else ""
    ver = b.get("version") if isinstance(b.get("version"), str) else ""
    return (prod + (" " + ver if ver else "")).strip()[:100]


def normalize_host(current: dict, history: "dict | None", history_error: "str | None", ip: str) -> dict:
    banners = [b for b in (current.get("data") or []) if isinstance(b, dict)]
    latest: dict[int, dict] = {}
    for b in banners:
        p = b.get("port")
        if isinstance(p, int) and (p not in latest or str(b.get("timestamp", "")) > str(latest[p].get("timestamp", ""))):
            latest[p] = b
    services = [_service_row(latest[p]) for p in sorted(latest)]

    timeline: list[dict] = []
    if isinstance(history, dict):
        by_port: dict[int, dict] = {}
        for b in history.get("data") or []:
            if not isinstance(b, dict):
                continue
            p, ts = b.get("port"), b.get("timestamp")
            if not isinstance(p, int) or not isinstance(ts, str):
                continue
            slot = by_port.setdefault(p, {"port": p, "first_seen": ts, "last_seen": ts, "observations": 0, "products": [], "titles": []})
            slot["observations"] += 1
            slot["first_seen"] = min(slot["first_seen"], ts)
            slot["last_seen"] = max(slot["last_seen"], ts)
            face = _face(b)
            if face and face not in slot["products"]:
                slot["products"].append(face)
            http = b.get("http") if isinstance(b.get("http"), dict) else {}
            t = http.get("title")
            if isinstance(t, str) and t.strip():
                t = html.unescape(t.strip())[:120]
                if t not in slot["titles"]:
                    slot["titles"].append(t)
        timeline = [by_port[p] for p in sorted(by_port)]

    loc = current.get("location") if isinstance(current.get("location"), dict) else {}
    if not loc and banners:
        loc = banners[0].get("location") if isinstance(banners[0].get("location"), dict) else {}
    hints: list[str] = []
    for b in banners:
        for h in software_hints(_s(b.get("product"), 120), _s(b.get("data"), 2000)):
            if h not in hints:
                hints.append(h)
    return {
        "ip": current.get("ip_str") or ip,
        "org": _s(current.get("org"), 160),
        "isp": _s(current.get("isp"), 160),
        "asn": _s(current.get("asn"), 40),
        "os": _s(current.get("os"), 80),
        "country": _s(loc.get("country_code") or current.get("country_code"), 8),
        "city": _s(loc.get("city") or current.get("city"), 80),
        "region": _s(loc.get("region_code") or current.get("region_code"), 40),
        "ports": sorted({p for p in (current.get("ports") or []) if isinstance(p, int)} | set(latest.keys())),
        "hostnames": [h[:253] for h in (current.get("hostnames") or []) if isinstance(h, str)][:12],
        "domains": [d[:253] for d in (current.get("domains") or []) if isinstance(d, str)][:12],
        "tags": [t[:60] for t in (current.get("tags") or []) if isinstance(t, str)][:20],
        "vulns": _vuln_ids(current.get("vulns"))[:80],
        "last_update": _s(current.get("last_update"), 40),
        "services": services,
        "timeline": timeline,
        "history_error": history_error,
        "software_hints": hints,
    }


def candidate_from_detail(detail: dict, previous: "dict | None" = None) -> dict:
    """Rebuild candidate fields from a full host record (ports now verified)."""
    prev = previous or {}
    title = next((s["title"] for s in detail["services"] if s.get("title")), None) or prev.get("title")
    main = next((s for s in detail["services"] if s.get("product")), None)
    stamps = [s["timestamp"] for s in detail["services"] if s.get("timestamp")]
    hints = list(dict.fromkeys((prev.get("software_hints") or []) + (detail.get("software_hints") or [])))
    fp: dict = {}
    for s in detail["services"]:
        add_fingerprints(fp, s.get("fp") or {})
    for k, vals in (prev.get("fp") or {}).items():  # keep search-phase values the host record lacks
        if k not in fp:
            fp[k] = vals
    return {
        "ip": detail["ip"],
        "org": detail["org"] or prev.get("org"),
        "asn": detail["asn"] or prev.get("asn"),
        "country": detail["country"] or prev.get("country"),
        "city": detail["city"] or prev.get("city"),
        "ports": detail["ports"],
        "ports_verified": True,
        "hostnames": detail["hostnames"],
        "domains": detail["domains"],
        "tags": detail["tags"],
        "vulns": detail["vulns"],
        "title": title,
        "product": prev.get("product") or (main or {}).get("product"),
        "version": prev.get("version") or (main or {}).get("version"),
        "os": detail["os"] or prev.get("os"),
        "last_seen": max(stamps) if stamps else prev.get("last_seen"),
        "banner_count": len(detail["services"]),
        "software_hints": hints,
        "fp": fp,
        "cert_subjects": sorted({s["cert_subject"] for s in detail["services"] if s.get("cert_subject")})[:6],
        "cert_self_signed": any(s.get("cert_self_signed") for s in detail["services"]),
    }
