"""The hunt workflow — cold-start facets → count ladder → gated search →
behaviour scoring → host inspection (re-score) → verdicts → report.

Everything is passive: only Shodan's database is read.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .paths import DATA_DIR
from .normalize import FP_KINDS, candidate_from_detail, merge_search_matches, normalize_host
from .scoring import NOISE_CAP, band_for, clean_profile, evasion_cost, score_hunt, score_inspected
from .shodan_client import MissingKey, RateLimited, ShodanClient, ShodanError
from .store import Store

MAX_POOL = 300        # refuse searches above this — narrow the ladder instead
CONFIRM_ABOVE = 100   # explicit confirmation needed above this (only first 100 are pulled)
PAGE_SIZE = 100
FACET_KEYS = ("country", "org", "port", "city", "product")

EMPTY_PROFILE = {k: "" for k in ("org", "port", "product", "serverVersion", "langBanner", "cms", "country", "city", "vuln", "hostname", "title")}

PRESETS: dict[str, dict[str, Any]] = {
    # A template showing the shape of a web-sensor profile. Every value is a placeholder: replace them with the
    # stack, org and CVE from your own advisory or facet breakdown before running a ladder.
    "web_sensor_example": {
        "label": "Example web-sensor profile (placeholders: replace every field)",
        "name": "Example web-sensor hunt",
        "profile": {**EMPTY_PROFILE, "org": "Example Cloud Inc.", "port": "80", "product": "Apache httpd", "serverVersion": "2.4.99",
                    "langBanner": "PHP/8.9.9", "cms": 'http.component:"WordPress"', "vuln": "CVE-2099-12345"},
        "windowStart": "", "windowEnd": "",
    },
    "shodan_tagged": {
        "label": "Shodan-tagged honeypots (calibration)",
        "name": "Shodan honeypot tag",
        "profile": {**EMPTY_PROFILE},
        "rawQuery": "tag:honeypot",
        "windowStart": "", "windowEnd": "",
    },
}

def load_reference_sensors(path: Optional[Path] = None) -> list[dict]:
    """Your own confirmed sensors, kept out of the code: <data dir>/references.json.

    Format: [{"ip": "...", "label": "...", "note": "..."}]. See references.example.json.
    """
    path = path or (DATA_DIR / "references.json")
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict) or not isinstance(r.get("ip"), str):
            continue
        try:
            ip = str(ipaddress.ip_address(r["ip"].strip()))
        except ValueError:
            continue
        out.append({"ip": ip, "label": str(r.get("label") or "")[:80], "note": str(r.get("note") or "")[:400]})
    return out[:20]


REFERENCE_SENSORS = load_reference_sensors()

CVE_RE = re.compile(r"^cve-\d{4}-\d{4,}$", re.I)
INT_FP_RE = re.compile(r"^-?\d{1,20}$")
HEX_FP_RE = re.compile(r"^[0-9a-fA-F:]{8,128}$")
PIVOT_FILTERS = {"html": "http.html_hash", "headers": "http.headers_hash", "favicon": "http.favicon.hash", "robots": "http.robots_hash",
                 "cert": "ssl.cert.fingerprint", "jarm": "ssl.jarm", "hassh": "ssh.hassh"}
_UNSET = object()
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class HuntError(Exception):
    pass


def quote(value: str) -> str:
    return '"' + value.replace('"', "") + '"'


def build_stages(p: dict) -> list[dict]:
    """The narrowing ladder: stack → +cloud org → +region → +persona & vuln flags."""
    p = clean_profile(p)
    stack: list[str] = []
    if p["product"]:
        stack.append(f"product:{quote(p['product'])}")
    if p["serverVersion"]:
        stack.append(f"version:{quote(p['serverVersion'])}")
    if p["langBanner"]:
        stack.append(quote(p["langBanner"]))
    if p["port"]:
        stack.append(f"port:{re.sub(r'[^0-9,]', '', p['port'])}")
    if p["hostname"]:
        stack.append(f"hostname:{quote(p['hostname'])}")

    stages: list[dict] = []

    def push(label: str, parts: list[str]) -> None:
        q = " ".join(x for x in parts if x)
        if q and (not stages or stages[-1]["query"] != q):
            stages.append({"label": label, "query": q, "total": None})

    push("Stack fingerprint", stack)
    with_org = stack + ([f"org:{quote(p['org'])}"] if p["org"] else [])
    push("+ Cloud org", with_org)
    with_region = with_org + ([f"country:{re.sub(r'[^A-Za-z,]', '', p['country']).upper()}"] if p["country"] else []) + ([f"city:{quote(p['city'])}"] if p["city"] else [])
    push("+ Region", with_region)
    full = with_region + ([p["cms"]] if p["cms"] else []) + ([f"vuln:{p['vuln'].upper()}"] if p["vuln"] else []) + ([f"http.title:{quote(p['title'])}"] if p["title"] else [])
    push("+ Persona & vuln flags", full)
    return stages


def seed_to_query(seed: str) -> str:
    seed = seed.strip()
    if CVE_RE.match(seed):
        return f"vuln:{seed.upper()}"
    if ":" in seed or seed.startswith('"'):
        return seed  # already a Shodan query
    return quote(seed)


def valid_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HuntError("Not a valid IP address.") from None


def _date_or_none(v: Optional[str]) -> Optional[str]:
    v = (v or "").strip()
    if not v:
        return None
    if not DATE_RE.match(v):
        raise HuntError("Campaign window dates must be YYYY-MM-DD.")
    return v


def pivot_query(kind: str, value: str) -> Optional[str]:
    """Shodan query that finds every host sharing one fingerprint (None if the value looks malformed)."""
    if kind == "title":
        return f"http.title:{quote(value[:120])}" if value.strip() else None
    if kind == "ssh":
        return quote(value) if HEX_FP_RE.match(value) else None  # host-key fingerprint appears in the banner text
    f = PIVOT_FILTERS.get(kind)
    if not f:
        return None
    ok = INT_FP_RE.match(value) if kind in ("html", "headers", "favicon", "robots") else HEX_FP_RE.match(value)
    return f"{f}:{value}" if ok else None


def _facets(body: dict) -> dict:
    raw = body.get("facets") if isinstance(body.get("facets"), dict) else {}
    out = {}
    for k in FACET_KEYS:
        rows = raw.get(k) if isinstance(raw.get(k), list) else []
        out[k] = [{"value": str(r.get("value"))[:80], "count": int(r.get("count", 0))} for r in rows[:10] if isinstance(r, dict)]
    return out


class Hunter:
    def __init__(self, client: ShodanClient, store: Store):
        self.client = client
        self.store = store

    # ---- free calls ---------------------------------------------------------

    def info(self) -> dict:
        if not self.client.has_key:
            return {"ok": False, "error": "No Shodan API key configured (set SHODAN_API_KEY).", "plan": None, "query_credits": None, "scan_credits": None}
        try:
            b = self.client.api_info()
            return {"ok": True, "error": None, "plan": b.get("plan"), "query_credits": b.get("query_credits"), "scan_credits": b.get("scan_credits"), "unlocked": b.get("unlocked")}
        except ShodanError as e:
            return {"ok": False, "error": str(e), "plan": None, "query_credits": None, "scan_credits": None}

    def explore(self, seed_or_query: str) -> dict:
        query = seed_to_query(seed_or_query)
        if not query or len(query) > 1200:
            raise HuntError("Query must be 1–1200 characters.")
        try:
            body = self.client.count(query)
            return {"query": query, "total": int(body.get("total", 0)), "error": None, "facets": _facets(body)}
        except ShodanError as e:
            return {"query": query, "total": None, "error": str(e), "facets": None}

    def count_ladder(self, stages: list[dict]) -> list[dict]:
        if not 1 <= len(stages) <= 6:
            raise HuntError("A ladder has 1–6 stages.")
        out = []
        stop: Optional[str] = None
        for st in stages:
            label, query = str(st.get("label", ""))[:80], str(st.get("query", ""))[:1200]
            if stop:
                out.append({"label": label, "query": query, "total": None, "error": stop, "facets": None})
                continue
            try:
                body = self.client.count(query)
                out.append({"label": label, "query": query, "total": int(body.get("total", 0)), "error": None, "facets": _facets(body)})
            except (RateLimited, MissingKey) as e:
                stop = str(e)
                out.append({"label": label, "query": query, "total": None, "error": stop, "facets": None})
            except ShodanError as e:
                out.append({"label": label, "query": query, "total": None, "error": str(e), "facets": None})
        return out

    # ---- credit-spending call (gated) ------------------------------------

    def run_hunt(self, name: str, query: str, profile: dict, ladder: Optional[list] = None, window_start: Optional[str] = None, window_end: Optional[str] = None, confirmed: bool = False, auto_pivot: bool = True) -> dict:
        query = (query or "").strip()
        if not query or len(query) > 1200:
            raise HuntError("Query must be 1–1200 characters.")
        profile = clean_profile(profile)
        ws, we = _date_or_none(window_start), _date_or_none(window_end)
        try:
            total = int(self.client.count(query, facets=None).get("total", 0))
        except ShodanError as e:
            return {"status": "error", "message": str(e), "total": None, "huntId": None, "returned": None}
        if total > MAX_POOL:
            return {"status": "too_broad", "message": f"This profile still matches {total:,} hosts. Narrow it further down the ladder before searching (limit {MAX_POOL}).", "total": total, "huntId": None, "returned": None}
        if total > CONFIRM_ABOVE and not confirmed:
            return {"status": "needs_confirm", "message": f"This search will pull the first {PAGE_SIZE} of {total:,} matching hosts and costs 1 query credit. Confirm to run it.", "total": total, "huntId": None, "returned": None}
        matches: list = []
        if total > 0:
            try:
                body = self.client.search(query, page=1)
            except ShodanError as e:
                return {"status": "error", "message": str(e), "total": total, "huntId": None, "returned": None}
            matches = body.get("matches") if isinstance(body.get("matches"), list) else []
        rows = merge_search_matches(matches, limit=PAGE_SIZE)
        results = score_hunt([{"key": i, "data": row, "detail": None} for i, row in enumerate(rows)], profile, ws, we, query)
        scored = [{"data": row, **results[i]} for i, row in enumerate(rows)]
        scored.sort(key=lambda s: (-s["score"], s["data"]["ip"]))
        clean_ladder = [{"label": str(s.get("label", ""))[:80], "query": str(s.get("query", ""))[:1200], "total": s.get("total")} for s in (ladder or [])][:6] or None
        hunt_id = self.store.create_hunt((name or "Untitled hunt").strip()[:120], query, profile, clean_ladder, ws, we, total, scored)
        out = {"status": "ok", "message": None, "total": total, "huntId": hunt_id, "returned": len(scored)}
        if auto_pivot and scored:
            out["pivot"] = self._auto_pivot(hunt_id)
        return out

    # ---- inspection (free host lookups) ------------------------------------

    def inspect(self, ip: str, candidate_id: Optional[int] = None, rescore_hunt: bool = True) -> dict:
        ip = valid_ip(ip)
        try:
            current = self.client.host(ip, history=False)
        except ShodanError as e:
            return {"ok": False, "error": str(e), "detail": None, "rateLimited": isinstance(e, RateLimited)}
        history, history_error = None, None
        try:
            history = self.client.host(ip, history=True)
        except RateLimited as e:
            history_error = str(e)
        except ShodanError as e:
            history_error = "Host history was unavailable on this Shodan plan." if e.status in (401, 403) else f"Host history could not be retrieved: {e}"
        detail = normalize_host(current, history, history_error, ip)

        rescored = None
        if candidate_id is not None:
            cand = self.store.get_candidate(candidate_id)
            if cand and cand["ip"] == ip:
                meta = self.store.hunt_meta(cand["huntId"]) or {}
                data = candidate_from_detail(detail, cand["data"])
                rescored = score_inspected(data, detail, clean_profile(meta.get("profile")), meta.get("windowStart"), meta.get("windowEnd"))
                self.store.update_inspection(candidate_id, data, detail, rescored["score"], rescored["band"], rescored["signals"])
                if rescore_hunt:
                    self.rescore(cand["huntId"])
                    after = self.store.get_candidate(candidate_id) or {}
                    rescored = {**rescored, "score": after.get("score", rescored["score"]), "band": after.get("band", rescored["band"]), "signals": after.get("signals", rescored["signals"])}
        else:
            # Loose inspection: score against an empty profile for calibration.
            data = candidate_from_detail(detail)
            rescored = score_inspected(data, detail, clean_profile({}), None, None)
        return {"ok": True, "error": None, "detail": detail, "score": rescored, "rateLimited": False}

    def inspect_top(self, hunt_id: int, n: int = 10, only_uninspected: bool = True, progress: Optional[Callable[[int, int, str], None]] = None, auto_pivot: bool = True) -> dict:
        h = self.store.get_hunt(hunt_id)
        if not h:
            raise HuntError("Hunt not found.")
        todo = [c for c in h["candidates"] if not (only_uninspected and c["detail"])][: max(1, min(n, 100))]
        done, errors = 0, []
        for i, c in enumerate(todo):
            if progress:
                progress(i + 1, len(todo), c["ip"])
            r = self.inspect(c["ip"], c["id"], rescore_hunt=False)
            if r["ok"]:
                done += 1
            else:
                errors.append(f"{c['ip']}: {r['error']}")
                if r.get("rateLimited"):
                    errors.append("Stopped: Shodan rate limit reached (not retried).")
                    break
        if done:
            self.rescore(hunt_id)
        out = {"inspected": done, "attempted": len(todo), "errors": errors}
        if done and auto_pivot and not any(e.startswith("Stopped") for e in errors):
            out["pivot"] = self._auto_pivot(hunt_id, only_new=True)
        return out

    def _auto_pivot(self, hunt_id: int, only_new: bool = False) -> dict:
        """Free pivot run after a hunt or batch inspection. Never fails the caller."""
        try:
            r = self.pivot(hunt_id, only_new=only_new)
        except HuntError as e:
            return {"counted": 0, "rare": [], "errors": [str(e)]}
        rare = [{"kind": p["kind"], "value": p["value"], "huntHosts": p["huntHosts"], "total": p["total"]}
                for p in r["pivots"] if p["total"] is not None and p["total"] <= max(1000, 10 * p["huntHosts"])]
        return {"counted": len(r["pivots"]), "rare": rare, "errors": r["errors"], "queryCredits": 0}

    # ---- offline re-scoring, free pivots, scoring audit ---------------------

    def rescore(self, hunt_id: int, window_start: Any = _UNSET, window_end: Any = _UNSET) -> dict:
        """Re-score every candidate from stored records (no API calls). Optionally move the campaign window first."""
        h = self.store.get_hunt(hunt_id)
        if not h:
            raise HuntError("Hunt not found.")
        hunt = h["hunt"]
        ws = hunt["windowStart"] if window_start is _UNSET else _date_or_none(window_start)
        we = hunt["windowEnd"] if window_end is _UNSET else _date_or_none(window_end)
        if (ws, we) != (hunt["windowStart"], hunt["windowEnd"]):
            self.store.set_window(hunt_id, ws, we)
        prevalence = {(p["kind"], p["value"]): p["total"] for p in self.store.get_pivots(hunt_id) if p["total"] is not None}
        cands = h["candidates"]
        results = score_hunt([{"key": c["id"], "data": c["data"], "detail": c["detail"]} for c in cands], hunt["profile"], ws, we, hunt["query"], prevalence)
        self.store.update_scores([(c["id"], results[c["id"]]["score"], results[c["id"]]["band"], results[c["id"]]["signals"], not c["detail"]) for c in cands])
        moves = [{"ip": c["ip"], "from": c["band"], "to": results[c["id"]]["band"], "score": [c["score"], results[c["id"]]["score"]]}
                 for c in cands if c["band"] != results[c["id"]]["band"]]
        bands: dict = {}
        for r in results.values():
            bands[r["band"]] = bands.get(r["band"], 0) + 1
        return {"huntId": hunt_id, "windowStart": ws, "windowEnd": we, "bands": bands, "bandChanges": moves, "apiCalls": 0}

    def pivot(self, hunt_id: int, max_values: int = 8, progress: Optional[Callable[[int, int, str], None]] = None, only_new: bool = False) -> dict:
        """Free global counts for the fingerprints this hunt's hosts share, then re-score with their rarity."""
        h = self.store.get_hunt(hunt_id)
        if not h:
            raise HuntError("Hunt not found.")
        hosts: dict = {}
        for c in h["candidates"]:
            d = c["data"]
            fp = dict(d.get("fp") or {})
            if d.get("title") and "title" not in fp:
                fp["title"] = [d["title"]]
            for kind in FP_KINDS:
                for v in fp.get(kind) or []:
                    hosts.setdefault((kind, v), set()).add(c["ip"])
        shared = sorted(((k, v, n) for (k, v), n in ((kv, len(s)) for kv, s in hosts.items()) if n >= 2), key=lambda x: (-x[2], x[0]))
        done_before = {(p["kind"], p["value"]) for p in self.store.get_pivots(hunt_id)} if only_new else set()
        todo = [(k, v, n, q) for k, v, n in shared if (k, v) not in done_before and (q := pivot_query(k, v))][: max(1, min(max_values, 20))]
        out, errors = [], []
        for i, (kind, value, n, query) in enumerate(todo):
            if progress:
                progress(i + 1, len(todo), f"{kind} {value[:40]}")
            try:
                body = self.client.count(query, facets="org:5,country:5")
                raw = body.get("facets") if isinstance(body.get("facets"), dict) else {}
                facets = {k: [{"value": str(r.get("value"))[:80], "count": int(r.get("count", 0))} for r in (raw.get(k) or [])[:5] if isinstance(r, dict)] for k in ("org", "country")}
                total, err = int(body.get("total", 0)), None
            except (RateLimited, MissingKey) as e:
                errors.append(f"Stopped: {e}")
                break
            except ShodanError as e:
                total, facets, err = None, None, str(e)
                errors.append(f"{kind} {value[:40]}: {e}")
            self.store.save_pivot(hunt_id, kind, value, query, n, total, facets, err)
            out.append({"kind": kind, "value": value, "query": query, "huntHosts": n, "total": total, "facets": facets, "error": err})
        rescored = self.rescore(hunt_id) if out else None
        return {"pivots": out, "errors": errors, "sharedFingerprints": len(shared), "queryCredits": 0, "rescore": rescored}

    def audit(self, hunt_id: int) -> dict:
        """Cross-check a hunt's scores the way a fleet operator would attack them (offline).

        * load-bearing signals: how many hosts change band if one signal were defeated
        * evasion cost: fewest signals to defeat before a host falls to weak
        * evidence mix: hosts resting mostly on fleet-level evidence vs on per-host evidence
        """
        h = self.store.get_hunt(hunt_id)
        if not h:
            raise HuntError("Hunt not found.")
        cands = h["candidates"]
        per_signal: dict = {}
        fragile, mix_cluster, mix_host = [], [], []
        cost_hist: dict = {}
        for c in cands:
            sigs = c["signals"]
            capped = any(s["key"] == "answers_everything" for s in sigs) and not any(s["key"] == "noise_gate_lifted" for s in sigs)
            for s in sigs:
                row = per_signal.setdefault(s["key"], {"key": s["key"], "label": s["label"], "hosts": 0, "points": 0, "bandDrops": 0})
                row["hosts"] += 1
                row["points"] += s["points"]
                if s["points"] > 0:
                    rest = [x for x in sigs if x is not s]
                    raw = sum(x["points"] for x in rest)
                    sc = max(0, min(100, raw))
                    if capped:
                        sc = min(sc, NOISE_CAP)
                    if band_for(sc) != c["band"]:
                        row["bandDrops"] += 1
            if c["band"] != "weak":
                n, removed = evasion_cost(sigs, capped)
                cost_hist[n] = cost_hist.get(n, 0) + 1
                if n <= 1:
                    fragile.append({"ip": c["ip"], "score": c["score"], "band": c["band"], "defeat": removed})
                cl = sum(s["points"] for s in sigs if s.get("phase") == "cluster" and s["points"] > 0)
                if c["score"] and cl * 2 >= c["score"]:
                    mix_cluster.append(c["ip"])
                elif cl == 0:
                    mix_host.append(c["ip"])
        gaps = []
        n_insp = sum(1 for c in cands if c["detail"])
        if n_insp < len(cands):
            gaps.append(f"{len(cands) - n_insp} candidates are not inspected: their port and timing signals are provisional.")
        if not self.store.get_pivots(hunt_id):
            gaps.append("No pivots yet: shared-persona signals can't tell a rare fleet template from a popular page. Run `pivot`.")
        if not any(s["key"] in ("cloned_host_key", "cloned_cert") for c in cands for s in c["signals"]) and not any((c["data"].get("fp") or {}).get("ssh") or (c["data"].get("fp") or {}).get("cert") for c in cands):
            gaps.append("No SSH or TLS fingerprints on record, so cloned-image detection had nothing to work with.")
        if any("fp" not in c["data"] for c in cands):
            gaps.append("Some candidates were stored before fingerprints were recorded. Re-inspect them to capture page/cert/key hashes.")
        return {
            "huntId": hunt_id, "candidates": len(cands),
            "signals": sorted(per_signal.values(), key=lambda r: (-r["bandDrops"], -r["hosts"])),
            "evasionCost": dict(sorted(cost_hist.items())),
            "fragile": fragile,
            "restsOnFleetEvidence": mix_cluster,
            "noFleetEvidence": mix_host,
            "gaps": gaps,
        }

    # ---- reports -----------------------------------------------------------

    def export_json(self, hunt_id: int) -> dict:
        h = self.store.get_hunt(hunt_id)
        if not h:
            raise HuntError("Hunt not found.")
        return {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source": "Shodan (passive; no candidate host contacted)", **h}

    def export_markdown(self, hunt_id: int) -> "tuple[str, str]":
        h = self.store.get_hunt(hunt_id)
        if not h:
            raise HuntError("Hunt not found.")
        hunt, cands = h["hunt"], h["candidates"]
        L: list[str] = []
        L += [f"# Honeypot Hunt — {hunt['name']}", "",
              f"Run: {hunt['created_at']} · Source: Shodan (passive scan data only; no candidate host was contacted)", "",
              "## Profile", ""]
        stages = build_stages(hunt["profile"])
        if stages and stages[-1]["query"] != hunt["query"]:
            L.append("- _The final query below overrides this profile; the profile fields only drive the CVE and window signals._")
        for k, v in hunt["profile"].items():
            if v:
                L.append(f"- **{k}**: {v}")
        L.append(f"- **Final query**: `{hunt['query']}`")
        if hunt["windowStart"] or hunt["windowEnd"]:
            L.append(f"- **Campaign window (UTC)**: {hunt['windowStart'] or '?'} → {hunt['windowEnd'] or '?'}")
        L.append("")
        if hunt["ladder"]:
            L += ["## Count ladder", ""]
            for st in hunt["ladder"]:
                n = "—" if st.get("total") is None else format(st["total"], ",")
                L.append(f"- {st['label']}: {n} hosts — `{st['query']}`")
            L.append("")
        pivots = self.store.get_pivots(hunt["id"])
        if pivots:
            L += ["## Fingerprint pivots (free global counts)", "", "| Fingerprint | Value | Hunt hosts | On all of Shodan | Top orgs |", "|---|---|---:|---:|---|"]
            for p in pivots:
                orgs = ", ".join(f"{o['value']} ({o['count']})" for o in ((p.get("facets") or {}).get("org") or [])[:3]).replace("|", "/")
                tot = "error" if p["total"] is None else format(p["total"], ",")
                L.append(f"| {p['kind']} | `{p['value'][:60].replace('|', '/')}` | {p['huntHosts']} | {tot} | {orgs or '—'} |")
            L.append("")
        likely = sum(1 for c in cands if c["verdict"] == "likely_sensor")
        inspected = sum(1 for c in cands if c["detail"])
        L += [f"## Candidates ({len(cands)} scored of {hunt['total']:,} matching · {inspected} inspected · {likely} marked likely sensor)", ""]
        L += ["| IP | Score | Band | Verdict | Org | Ports | Inspected |", "|---|---:|---|---|---|---|---|"]
        for c in cands:
            d = c["data"]
            L.append(f"| {d['ip']} | {c['score']} | {c['band']} | {c['verdict']} | {(d.get('org') or '—').replace('|', '/')} | {', '.join(map(str, d.get('ports') or [])) or '—'}{'' if d.get('ports_verified') else ' (matched)'} | {'yes' if c['detail'] else 'no'} |")
        L.append("")
        for c in cands:
            d = c["data"]
            L.append(f"### {d['ip']} — behaviour score {c['score']}/100 ({c['band']}) — verdict: {c['verdict']}")
            L.append("")
            L.append(f"- Org: {d.get('org') or '—'} ({d.get('asn') or '—'}) · {d.get('city') or ''} {d.get('country') or ''}")
            L.append(f"- Ports: {', '.join(map(str, d.get('ports') or [])) or '—'}{' (verified)' if d.get('ports_verified') else ' (matched banners only — not verified)'} · Hostnames: {', '.join(d.get('hostnames') or []) or '—'} · Domains: {', '.join(d.get('domains') or []) or '—'}")
            L.append(f"- Service: {d.get('product') or '—'} {d.get('version') or ''} · Title: {d.get('title') or '—'} · Last observed: {d.get('last_seen') or '—'} UTC")
            vulns = d.get("vulns") or []
            if vulns:
                L.append(f"- Vuln flags: {', '.join(vulns[:12])}{f' (+{len(vulns) - 12} more)' if len(vulns) > 12 else ''}")
            if c["notes"]:
                L.append(f"- Analyst notes: {c['notes']}")
            if c["searchScore"] is not None and c["detail"]:
                L.append(f"- Search-phase score {c['searchScore']} → inspected score {c['score']}")
            L.append("- Score breakdown:")
            for s in c["signals"]:
                L.append(f"  - {'+' if s['points'] >= 0 else ''}{s['points']} {s['label']}{' — ' + s['detail'] if s.get('detail') else ''}")
            det = c["detail"]
            if det:
                if det.get("timeline"):
                    L.append("- Port history (Shodan):")
                    for t in det["timeline"]:
                        L.append(f"  - Port {t['port']}: first seen {t['first_seen']}, last seen {t['last_seen']}, {t['observations']} observation(s); faces: {'; '.join(t.get('products') or []) or '—'}")
                elif det.get("history_error"):
                    L.append(f"- Port history: {det['history_error']}")
            L.append("")
        L += ["---",
              "Method: profile → free count ladder → gated search (refuse >300, confirm >100, first 100 only) → search-phase behaviour scoring "
              "(bare cloud hostname, no real domain, generic internal title, profile CVE flag, timing vs campaign window, cloud tenancy, Shodan honeypot tag, "
              "honeypot-software fingerprints; penalties for real domains, many ports, SSH). Port-shape signals are provisional at search time because a "
              "Shodan search only returns banners that matched the query. Inspecting a candidate re-scores it from the full host record and history: verified "
              "port count (with a 40+-port noise gate), first sighting inside the campaign window, single sighting, frozen banner across months while still "
              "vuln-flagged (persistent-fleet pattern), and long churning history (production-like penalty). Cluster signals then look across the whole hunt: "
              "a cloned persona (weighted by its global rarity from free pivot counts), cloned SSH keys or unowned TLS certs, a dense /24, and a deployment "
              "burst. A high score is a fingerprint match, not proof."]
        return f"honeypot-hunt-{hunt['id']}.md", "\n".join(L)
