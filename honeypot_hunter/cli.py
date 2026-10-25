"""Command-line interface.

    honeypot-hunter serve                      # local web console
    honeypot-hunter info                       # plan + remaining credits
    honeypot-hunter explore CVE-2099-12345     # free facet breakdown
    honeypot-hunter ladder --product 'Apache httpd' --server-version 2.4.99   # free count ladder
    honeypot-hunter hunt --query '...'          # gated search + scoring
    honeypot-hunter inspect 203.0.113.10       # host record + history
    honeypot-hunter pivot ID                   # free global counts for shared fingerprints
    honeypot-hunter rescore ID [--window-start] # re-score from stored records, no API calls
    honeypot-hunter audit ID                   # how an operator could dodge these scores
    honeypot-hunter list | show ID | inspect-top ID | verdict CID likely_sensor | export ID | delete ID
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .hunt import PRESETS, Hunter, HuntError, build_stages
from .paths import DATA_DIR
from .shodan_client import ShodanClient
from .store import VERDICTS, Store

DEFAULT_DB = os.environ.get("HONEYPOT_HUNTER_DB", str(DATA_DIR / "honeypot_hunter.db"))


def _profile_from_args(a: argparse.Namespace) -> "tuple[dict, str | None, str | None, str | None, str]":
    preset = PRESETS.get(a.preset) if getattr(a, "preset", None) else None
    profile = dict(preset["profile"]) if preset else {}
    ws = preset.get("windowStart") if preset else None
    we = preset.get("windowEnd") if preset else None
    raw = preset.get("rawQuery") if preset else None
    name = preset["name"] if preset else "CLI hunt"
    for key in ("org", "port", "product", "serverVersion", "langBanner", "cms", "country", "city", "vuln", "hostname", "title"):
        v = getattr(a, key, None)
        if v is not None:
            profile[key] = v
    if getattr(a, "window_start", None) is not None:
        ws = a.window_start
    if getattr(a, "window_end", None) is not None:
        we = a.window_end
    if getattr(a, "query", None):
        raw = a.query
    if getattr(a, "name", None):
        name = a.name
    return profile, ws or None, we or None, raw, name


def _add_profile_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--preset", choices=sorted(PRESETS), help="start from a saved profile")
    p.add_argument("--org"); p.add_argument("--port"); p.add_argument("--product", help="web server product, e.g. 'Apache httpd'")
    p.add_argument("--server-version", dest="serverVersion"); p.add_argument("--lang-banner", dest="langBanner", help="e.g. PHP/8.9.9")
    p.add_argument("--cms", help="raw query fragment, e.g. http.component:\"WordPress\"")
    p.add_argument("--country"); p.add_argument("--city"); p.add_argument("--vuln", help="CVE id")
    p.add_argument("--hostname"); p.add_argument("--title", help="page title pattern")
    p.add_argument("--window-start", help="campaign window start YYYY-MM-DD (UTC)")
    p.add_argument("--window-end", help="campaign window end YYYY-MM-DD (UTC)")
    p.add_argument("--query", help="override the final Shodan query")


def _out(obj, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, default=str))


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(prog="honeypot-hunter", description="Passive Shodan-based honeypot / sensor-fleet hunter.")
    ap.add_argument("--db", default=DEFAULT_DB, help=f"SQLite file (default {DEFAULT_DB})")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the local web console")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8787)
    s.add_argument("--no-browser", action="store_true")

    sub.add_parser("info", help="Shodan plan and remaining credits (free)")
    e = sub.add_parser("explore", help="free facet breakdown for a CVE, banner, or query")
    e.add_argument("seed")
    lad = sub.add_parser("ladder", help="free count at every narrowing stage"); _add_profile_args(lad)
    h = sub.add_parser("hunt", help="gated search (≤1 credit) + behaviour scoring"); _add_profile_args(h)
    h.add_argument("--name"); h.add_argument("--yes", action="store_true", help="confirm pools of 101–300 hosts")
    h.add_argument("--inspect-top", type=int, default=0, help="then inspect the top N candidates (free host lookups)")
    h.add_argument("--no-pivot", action="store_true", help="skip the automatic free fingerprint pivot")
    i = sub.add_parser("inspect", help="host record + history (free)")
    i.add_argument("ip"); i.add_argument("--candidate", type=int)
    it = sub.add_parser("inspect-top", help="inspect the top N uninspected candidates of a hunt")
    it.add_argument("hunt_id", type=int); it.add_argument("-n", type=int, default=10)
    it.add_argument("--refresh", action="store_true", help="also re-inspect candidates that were inspected before")
    it.add_argument("--no-pivot", action="store_true", help="skip the automatic free pivot of newly found fingerprints")
    rs = sub.add_parser("rescore", help="re-score a hunt from stored records (no API calls)")
    rs.add_argument("hunt_id", type=int)
    rs.add_argument("--window-start", help="move the campaign window start (YYYY-MM-DD, '' to clear)")
    rs.add_argument("--window-end", help="move the campaign window end (YYYY-MM-DD, '' to clear)")
    pv = sub.add_parser("pivot", help="free global counts for fingerprints the hunt's hosts share, then re-score")
    pv.add_argument("hunt_id", type=int); pv.add_argument("--max", type=int, default=8, help="fingerprints to count (1–20, default 8)")
    au = sub.add_parser("audit", help="adversarial check of a hunt's scores (offline)")
    au.add_argument("hunt_id", type=int)
    sub.add_parser("list", help="saved hunts")
    sh = sub.add_parser("show", help="candidates of a hunt"); sh.add_argument("hunt_id", type=int)
    v = sub.add_parser("verdict", help="set an analyst verdict"); v.add_argument("candidate_id", type=int); v.add_argument("verdict", choices=VERDICTS); v.add_argument("--notes")
    x = sub.add_parser("export", help="write a hunt report"); x.add_argument("hunt_id", type=int); x.add_argument("--format", choices=["md", "json"], default="md"); x.add_argument("-o", "--output")
    d = sub.add_parser("delete", help="delete a hunt"); d.add_argument("hunt_id", type=int)
    sub.add_parser("presets", help="list built-in presets")

    a = ap.parse_args(argv)
    if a.db != ":memory:":
        Path(a.db).parent.mkdir(parents=True, exist_ok=True)
    store = Store(a.db)
    hunter = Hunter(ShodanClient(), store)

    try:
        if a.cmd == "serve":
            from .server import serve
            serve(hunter, a.host, a.port, open_browser=not a.no_browser)
            return 0
        if a.cmd == "presets":
            for k, p in PRESETS.items():
                print(f"{k:15} {p['label']}")
            return 0
        if a.cmd == "info":
            r = hunter.info(); _out(r, a.json)
            if not a.json:
                print(r["error"] if not r["ok"] else f"Plan: {r['plan']} · query credits: {r['query_credits']} · scan credits: {r['scan_credits']}")
            return 0 if r["ok"] else 1
        if a.cmd == "explore":
            r = hunter.explore(a.seed); _out(r, a.json)
            if not a.json:
                if r["error"]:
                    print("Error:", r["error"]); return 1
                print(f"Pool for {r['query']}: {r['total']:,} hosts")
                for k, rows in r["facets"].items():
                    print(f"\n  {k}:")
                    for row in rows:
                        print(f"    {row['count']:>8,}  {row['value']}")
            return 0
        if a.cmd in ("ladder", "hunt"):
            profile, ws, we, raw, name = _profile_from_args(a)
            stages = build_stages(profile)
            if raw and (not stages or stages[-1]["query"] != raw):
                stages.append({"label": "Final query", "query": raw, "total": None})
            if not stages:
                print("Empty profile — pass --preset or profile flags, or --query."); return 2
            ladder = hunter.count_ladder(stages[:6])
            if not a.json or a.cmd == "ladder":
                if a.cmd == "ladder":
                    _out(ladder, a.json)
                if not a.json:
                    for st in ladder:
                        n = "—" if st["total"] is None else f"{st['total']:,}"
                        print(f"{st['label']:24} {n:>10}  {st['query']}" + (f"   [{st['error']}]" if st["error"] else ""))
            if a.cmd == "ladder":
                return 0
            query = raw or stages[-1]["query"]
            r = hunter.run_hunt(name, query, profile, ladder, ws, we, confirmed=a.yes, auto_pivot=not a.no_pivot)
            if r["status"] == "ok" and a.inspect_top:
                r["inspection"] = hunter.inspect_top(r["huntId"], a.inspect_top, progress=None if a.json else lambda i, n, ip: print(f"  inspecting {i}/{n} {ip}…"), auto_pivot=not a.no_pivot)
            _out(r, a.json)
            if not a.json:
                print(f"\n{r['status'].upper()}: {r['message'] or ''}".rstrip())
                if r["status"] == "ok":
                    print(f"Hunt #{r['huntId']}: {r['returned']} candidates scored of {r['total']:,} matching.")
                    _print_pivot(r.get("pivot")); _print_pivot((r.get("inspection") or {}).get("pivot"))
                    _print_hunt(hunter, r["huntId"])
            return 0 if r["status"] in ("ok", "needs_confirm") else 1
        if a.cmd == "inspect":
            r = hunter.inspect(a.ip, a.candidate); _out(r, a.json)
            if not a.json:
                if not r["ok"]:
                    print("Error:", r["error"]); return 1
                _print_detail(r["detail"], r["score"])
            return 0 if r["ok"] else 1
        if a.cmd == "inspect-top":
            r = hunter.inspect_top(a.hunt_id, a.n, only_uninspected=not a.refresh, progress=None if a.json else lambda i, n, ip: print(f"  inspecting {i}/{n} {ip}…"), auto_pivot=not a.no_pivot)
            _out(r, a.json)
            if not a.json:
                print(f"Inspected {r['inspected']}/{r['attempted']}."); [print("  !", e) for e in r["errors"]]
                _print_pivot(r.get("pivot"))
                _print_hunt(hunter, a.hunt_id)
            return 0
        if a.cmd == "rescore":
            kw = {}
            if a.window_start is not None:
                kw["window_start"] = a.window_start
            if a.window_end is not None:
                kw["window_end"] = a.window_end
            r = hunter.rescore(a.hunt_id, **kw); _out(r, a.json)
            if not a.json:
                print(f"Re-scored hunt #{a.hunt_id} (window {r['windowStart'] or '—'} → {r['windowEnd'] or '—'}, 0 API calls): {r['bands']}")
                for mv in r["bandChanges"]:
                    print(f"  {mv['ip']:<16} {mv['from']} → {mv['to']}  ({mv['score'][0]} → {mv['score'][1]})")
                _print_hunt(hunter, a.hunt_id)
            return 0
        if a.cmd == "pivot":
            r = hunter.pivot(a.hunt_id, a.max, progress=None if a.json else lambda i, n, what: print(f"  counting {i}/{n} {what}…"))
            _out(r, a.json)
            if not a.json:
                print(f"{r['sharedFingerprints']} fingerprints are shared by 2+ hunt hosts; counted {len(r['pivots'])} (free).")
                for p in r["pivots"]:
                    tot = "error" if p["total"] is None else f"{p['total']:,}"
                    orgs = ", ".join(f"{o['value']} ({o['count']})" for o in ((p.get("facets") or {}).get("org") or [])[:3])
                    print(f"  {p['kind']:<8} {p['huntHosts']:>4} in hunt / {tot:>10} on Shodan  {p['value'][:48]}  {orgs}")
                [print("  !", e) for e in r["errors"]]
            return 0 if not any(e.startswith("Stopped") for e in r["errors"]) else 1
        if a.cmd == "audit":
            r = hunter.audit(a.hunt_id); _out(r, a.json)
            if not a.json:
                print(f"Audit of hunt #{a.hunt_id} ({r['candidates']} candidates)\n")
                print(f"{'signal':<22} {'hosts':>5} {'band drops if defeated':>23}")
                for s in r["signals"]:
                    print(f"{s['key']:<22} {s['hosts']:>5} {s['bandDrops']:>23}")
                print(f"\nEvasion cost (signals to defeat before a host falls to weak): {r['evasionCost']}")
                print(f"Fragile (1 signal away from weak): {len(r['fragile'])} · rests mostly on fleet evidence: {len(r['restsOnFleetEvidence'])} · no fleet evidence: {len(r['noFleetEvidence'])}")
                for g in r["gaps"]:
                    print("  gap:", g)
            return 0
        if a.cmd == "list":
            rows = store.list_hunts(); _out(rows, a.json)
            if not a.json:
                if not rows:
                    print("No hunts saved yet.")
                for hh in rows:
                    print(f"#{hh['id']:<4} {hh['created_at']}  {hh['candidateCount']:>3} cand / {hh['total']:>4} pool  {hh['likelyCount']} likely  {hh['name']}")
            return 0
        if a.cmd == "show":
            hh = store.get_hunt(a.hunt_id)
            if not hh:
                print("Hunt not found."); return 1
            _out(hh, a.json)
            if not a.json:
                _print_hunt(hunter, a.hunt_id)
            return 0
        if a.cmd == "verdict":
            ok = store.set_verdict(a.candidate_id, a.verdict, a.notes)
            print("Saved." if ok else "Candidate not found."); return 0 if ok else 1
        if a.cmd == "export":
            if a.format == "md":
                fname, text = hunter.export_markdown(a.hunt_id)
            else:
                fname, text = f"honeypot-hunt-{a.hunt_id}.json", json.dumps(hunter.export_json(a.hunt_id), indent=2)
            path = Path(a.output or fname)
            path.write_text(text, encoding="utf-8")
            print(f"Wrote {path}"); return 0
        if a.cmd == "delete":
            store.delete_hunt(a.hunt_id); print("Deleted."); return 0
    except HuntError as exc:
        print("Error:", exc, file=sys.stderr)
        return 2
    return 0


def _print_pivot(pv: "dict | None") -> None:
    if not pv:
        return
    print(f"Pivot (free): counted {pv['counted']} shared fingerprint(s); {len(pv['rare'])} rare enough to be a fleet template.")
    for p in pv["rare"][:5]:
        print(f"  {p['kind']:<8} {p['huntHosts']:>4} in hunt / {p['total']:>8,} on Shodan  {str(p['value'])[:48]}")
    for e in pv["errors"]:
        print("  !", e)


def _print_hunt(hunter: Hunter, hunt_id: int) -> None:
    hh = hunter.store.get_hunt(hunt_id)
    if not hh:
        return
    print(f"\n{'ID':>5}  {'IP':<16} {'Score':>5}  {'Band':<9} {'Verdict':<14} {'Ports':<14} Org")
    for c in hh["candidates"]:
        d = c["data"]
        ports = ",".join(map(str, d.get("ports") or [])) + ("" if d.get("ports_verified") else "*")
        print(f"{c['id']:>5}  {d['ip']:<16} {c['score']:>5}  {c['band']:<9} {c['verdict']:<14} {ports:<14} {(d.get('org') or '')[:40]}")
    print("  * = matched ports only (not yet verified by inspection)")


def _print_detail(det: dict, score: "dict | None") -> None:
    print(f"{det['ip']}  {det.get('org') or '—'} ({det.get('asn') or '—'})  {det.get('city') or ''} {det.get('country') or ''}")
    print(f"Ports: {', '.join(map(str, det['ports'])) or '—'} · Hostnames: {', '.join(det['hostnames']) or '—'} · Domains: {', '.join(det['domains']) or '—'}")
    if det.get("tags"):
        print("Tags:", ", ".join(det["tags"]))
    print("Services:")
    for s in det["services"]:
        print(f"  :{s['port']} {s['product'] or '—'} {s['version'] or ''}" + (f" · “{s['title']}”" if s["title"] else ""))
    print("History:" if det["timeline"] else f"History: {det.get('history_error') or 'none returned'}")
    for t in det["timeline"]:
        print(f"  :{t['port']} first {t['first_seen']} · last {t['last_seen']} · {t['observations']} obs · {'; '.join(t['products']) or '—'}")
    if score:
        print(f"\nBehaviour score: {score['score']}/100 ({score['band']})")
        for s in score["signals"]:
            print(f"  {'+' if s['points'] >= 0 else ''}{s['points']:>3}  {s['label']}" + (f" — {s['detail']}" if s["detail"] else ""))


if __name__ == "__main__":
    sys.exit(main())
