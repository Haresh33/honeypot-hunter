"""Red-team the scoring: how would a fleet operator dodge it, and what fools it?

Each scenario builds a synthetic hunt (inspected hosts, no network) and scores
it with ``score_hunt``. Scenarios fall into three groups:

* EVASION   — an operator tweak that beats per-host scoring; asserts the
              cluster phase still catches it.
* LOOKALIKE — production patterns that resemble a fleet; asserts we don't
              over-score them.
* KNOWN GAP — cases passive Shodan data cannot settle. These tests pin the
              current behaviour so the gap stays visible: if one starts
              failing, the gap was closed (or moved) and README needs updating.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_shodan import TEST_PRESET, FakeShodan  # noqa: E402

from honeypot_hunter.hunt import PRESETS, Hunter, build_stages  # noqa: E402
from honeypot_hunter.scoring import evasion_cost, score_hunt  # noqa: E402
from honeypot_hunter.shodan_client import ShodanClient  # noqa: E402
from honeypot_hunter.store import Store  # noqa: E402

PROFILE = TEST_PRESET["profile"]
WS, WE = "2026-10-22", "2026-10-24"
NOW = 1793232000.0  # 2026-10-25T00:00Z


def host(ip, *, ports=(80,), title="Example Garden Notes", html="-424242", domains=(), hostnames=(),
         first="2026-10-23T06:00:00", obs=1, vulns=("CVE-2099-12345",), ssh=None, cert=None, cert_subjects=(), self_signed=False, org="Example Research Network"):
    fp = {}
    if html:
        fp["html"] = [html]
    if title:
        fp["title"] = [title]
    if ssh:
        fp["ssh"] = [ssh]
    if cert:
        fp["cert"] = [cert]
    data = {"ip": ip, "org": org, "asn": "AS64500", "country": "NL", "city": "Exampleville", "ports": sorted(ports), "ports_verified": True,
            "hostnames": list(hostnames), "domains": list(domains), "tags": [], "vulns": list(vulns), "title": title,
            "product": "Apache httpd", "version": "2.4.99", "os": None, "last_seen": first, "banner_count": len(ports),
            "software_hints": [], "fp": fp, "cert_subjects": list(cert_subjects), "cert_self_signed": self_signed}
    detail = {"vulns": list(vulns), "timeline": [{"port": p, "first_seen": first, "last_seen": first, "observations": obs,
                                                  "products": ["Apache httpd 2.4.99"], "titles": [title] if title else []} for p in ports]}
    return {"key": ip, "data": data, "detail": detail}


def score(entries, query="", prevalence=None):
    return score_hunt(entries, PROFILE, WS, WE, query, prevalence, now=NOW)


def keys(result):
    return {s["key"] for s in result["signals"]}


def fleet(n=10, **kw):
    return [host(f"192.0.2.{10 + i}", **kw) for i in range(n)]


class Baseline(unittest.TestCase):
    def test_plain_fleet_is_strong_with_fleet_evidence(self):
        r = score(fleet())
        for res in r.values():
            self.assertEqual(res["band"], "strong")
            self.assertTrue({"shared_persona", "dense_block", "deployment_burst"} <= keys(res), keys(res))

    def test_lone_host_gets_no_cluster_signals(self):
        r = score([host("192.0.2.4")])
        self.assertFalse(any(s["phase"] == "cluster" for s in r["192.0.2.4"]["signals"]))


class Evasion(unittest.TestCase):
    def test_decoy_ssh_and_extra_ports_on_a_cloned_image(self):
        # Operator adds SSH + 443 to every sensor to look like a normal server.
        r = score(fleet(ports=(22, 80, 443), ssh="aa:bb:cc:dd:ee:ff:00:11"))
        res = r["192.0.2.10"]
        self.assertIn("ssh_open", keys(res))
        self.assertIn("cloned_host_key", keys(res))
        self.assertEqual(res["band"], "strong")

    def test_throwaway_domains_and_ssh(self):
        # Each sensor gets its own cheap domain (-15) and SSH (-10): per-host evidence alone is weak.
        es = [host(f"192.0.2.{10 + i}", domains=[f"garden-notes-{i}.xyz"], ports=(22, 80)) for i in range(10)]
        res = score(es)["192.0.2.10"]
        host_only = sum(s["points"] for s in res["signals"] if s["phase"] != "cluster")
        self.assertLess(host_only, 35)
        self.assertIn(res["band"], ("possible", "strong"))

    def test_port_spoofer_front_cannot_hide_behind_the_noise_gate(self):
        # 3 of 10 sensors answer on 45 ports to trip the noise gate and cap themselves at weak.
        es = fleet(7) + [host(f"192.0.2.{50 + i}", ports=tuple(range(8000, 8045)) + (80,)) for i in range(3)]
        res = score(es)["192.0.2.50"]
        self.assertIn("answers_everything", keys(res))
        self.assertIn("noise_gate_lifted", keys(res))
        self.assertGreater(res["score"], 34)

    def test_all_spoofers_stay_capped_until_pivot_shows_rarity(self):
        es = [host(f"192.0.2.{50 + i}", ports=tuple(range(8000, 8045)) + (80,)) for i in range(5)]
        self.assertLessEqual(score(es)["192.0.2.50"]["score"], 34)
        rare = score(es, prevalence={("html", "-424242"): 12})["192.0.2.50"]
        self.assertIn("noise_gate_lifted", keys(rare))

    def test_spread_across_providers_and_weeks(self):
        # Different /24s and orgs, deployments staggered over two months: block and burst signals vanish,
        # but the cloned persona remains.
        es = [host(f"198.18.{i}.5", org=f"Provider {i}", first=f"2026-{8 + i // 5:02d}-{1 + 5 * (i % 5):02d}T00:00:00") for i in range(10)]
        res = score(es)["198.18.0.5"]
        self.assertIn("shared_persona", keys(res))
        self.assertNotIn("dense_block", keys(res))
        self.assertNotIn("deployment_burst", keys(res))


class Lookalike(unittest.TestCase):
    def test_default_pages_are_not_a_persona(self):
        es = fleet(title="Welcome to nginx!", html="777")
        self.assertNotIn("shared_persona", keys(score(es)["192.0.2.10"]))

    def test_globally_common_page_earns_nothing(self):
        r = score(fleet(), prevalence={("html", "-424242"): 50_000, ("title", "Example Garden Notes"): 50_000})
        sig = [s for s in r["192.0.2.10"]["signals"] if s["key"] == "shared_persona"][0]
        self.assertEqual(sig["points"], 0)

    def test_rare_page_earns_more_than_unknown(self):
        unknown = [s for s in score(fleet())["192.0.2.10"]["signals"] if s["key"] == "shared_persona"][0]
        rare = [s for s in score(fleet(), prevalence={("html", "-424242"): 92})["192.0.2.10"]["signals"] if s["key"] == "shared_persona"][0]
        self.assertGreater(rare["points"], unknown["points"])

    def test_load_balanced_real_domain_cert_is_not_cloned_image(self):
        es = fleet(ports=(80, 443), cert="ab" * 32, cert_subjects=["www.shop-example.com"])
        self.assertNotIn("cloned_cert", keys(score(es)["192.0.2.10"]))
        es = fleet(ports=(80, 443), cert="ab" * 32, cert_subjects=["localhost"], self_signed=True)
        self.assertIn("cloned_cert", keys(score(es)["192.0.2.10"]))

    def test_redirect_and_empty_pages_are_not_a_persona(self):
        # Seen on a large site operator's production servers: 30 hosts with an empty body (hash 0), 14 with the same 301 page.
        self.assertNotIn("shared_persona", keys(score(fleet(title=None, html="0"))["192.0.2.10"]))
        self.assertNotIn("shared_persona", keys(score(fleet(title="301 Moved Permanently", html="-2100514759"))["192.0.2.10"]))

    def test_shared_domain_estate_is_not_decoy_domains(self):
        # One owner's servers all carry the same family of domains (CDN edge): not one throwaway domain each.
        es = [host(f"198.51.100.{10 + i}", domains=["bigcorp.org", "bigcorp-cdn.net", f"bigcorp{i % 2}.org"], title="Edge page") for i in range(8)]
        self.assertNotIn("decoy_domains", keys(score(es)["198.51.100.10"]))

    def test_long_lived_hosts_at_the_history_horizon_are_not_a_burst(self):
        # A plan's history starts at a fixed horizon, so long-lived hosts all look "first seen" together.
        es = [host(f"198.51.100.{10 + i}", obs=400, first="2026-07-31T00:00:00", title="Edge page") for i in range(10)]
        self.assertNotIn("deployment_burst", keys(score(es)["198.51.100.10"]))

    def test_persona_in_the_query_is_not_evidence(self):
        r = score(fleet(), query='http.title:"Example Garden Notes" http.html_hash:-424242')
        self.assertNotIn("shared_persona", keys(r["192.0.2.10"]))


class MultiHoneypotHosts(unittest.TestCase):
    """Found by validating against public Log4Pot (CVE-2021-44228) installs: T-Pot style hosts were penalised."""

    ZOO = ["Apache httpd", "OpenSSH", "Exim smtpd", "MS-SQL Server 2000 SP1+", "Redis key-value store", "VNC", "MQTT", "PPTP", "Microsoft RPC"]

    def zoo(self, ip, ports, products, domains=(), hostnames=()):
        e = host(ip, ports=ports, title="SAP NetWeaver Portal", domains=domains, hostnames=hostnames, obs=40, first="2026-08-01T00:00:00")
        e["detail"]["services"] = [{"port": p, "product": products[i % len(products)]} for i, p in enumerate(ports)]
        return e

    def test_service_zoo_is_evidence_and_not_noise(self):
        es = [self.zoo(f"198.18.{100 + i}.9", tuple(range(1000, 1045)), self.ZOO) for i in range(4)]
        res = score_hunt(es, {}, None, None, now=NOW)["198.18.100.9"]
        self.assertTrue({"service_zoo", "emulated_legacy"} <= keys(res), keys(res))
        self.assertFalse(res["capped"])
        self.assertNotEqual(res["band"], "weak")

    def test_ssh_is_not_penalised_outside_web_hunts(self):
        e = self.zoo("198.18.100.9", (22, 80), ["OpenSSH", "Apache httpd"])
        self.assertNotIn("ssh_open", keys(score_hunt([e], {}, None, None, now=NOW)["198.18.100.9"]))
        self.assertIn("ssh_open", keys(score_hunt([e], PROFILE, WS, WE, now=NOW)["198.18.100.9"]))

    def test_tarpit_with_one_banner_everywhere_stays_capped(self):
        e = self.zoo("198.18.100.9", tuple(range(1000, 1045)), ["nginx"])
        res = score_hunt([e], {}, None, None, now=NOW)["198.18.100.9"]
        self.assertTrue(res["capped"])
        self.assertLessEqual(res["score"], 34)

    def test_busy_production_server_with_real_domain_stays_weak(self):
        prod = ["Apache httpd", "OpenSSH", "Postfix smtpd", "MySQL", "Redis key-value store", "ProFTPD"]
        e = self.zoo("198.18.100.9", (21, 22, 25, 80, 3306, 6379), prod, domains=["acme-shop.de"], hostnames=["mail.acme-shop.de"])
        e["data"]["title"] = "Acme Shop"; e["data"]["fp"]["title"] = ["Acme Shop"]
        self.assertEqual(score_hunt([e], {}, None, None, now=NOW)["198.18.100.9"]["band"], "weak")

    def test_reserved_and_provider_domains_are_not_owned(self):
        from honeypot_hunter.scoring import is_placeholder_domain, is_provider_ptr, owned_domains
        self.assertTrue(is_placeholder_domain("example.com"))
        self.assertTrue(is_placeholder_domain("zerofot."))
        self.assertTrue(is_provider_ptr("ip12.ip-198-51-100.hoster-example.net", "198.51.100.12"))
        self.assertTrue(is_provider_ptr("cpe-192-0-2-4.dyn.isp-example.net", "192.0.2.4"))
        self.assertTrue(is_provider_ptr("pc0000207.dip0.isp-example.de", "192.0.2.7"))
        self.assertFalse(is_provider_ptr("mail.acme-shop.de", "192.0.2.4"))
        d = {"ip": "192.0.2.4", "hostnames": ["cpe-192-0-2-4.dyn.isp-example.net", "www.acme-shop.de"], "domains": ["isp-example.net", "acme-shop.de", "example.com"]}
        self.assertEqual(owned_domains(d), ["acme-shop.de"])


class KnownGap(unittest.TestCase):
    def test_gap_unique_personas_spread_out_are_invisible_to_cluster_phase(self):
        # Per-host unique page, own domain, SSH, own key, different provider, staggered: nothing links the fleet.
        es = [host(f"198.19.{i}.9", title=f"Blog {i}", html=str(1000 + i), domains=[f"blog{i}.example-shop.com"], ports=(22, 80),
                   ssh=f"{i:02x}:aa:bb:cc:dd:ee:ff:00", org=f"Provider {i}", first=f"2026-{7 + i // 4:02d}-{1 + 7 * (i % 4):02d}T00:00:00")
              for i in range(8)]
        res = score(es)["198.19.0.9"]
        self.assertFalse(any(s["phase"] == "cluster" for s in res["signals"]))
        self.assertEqual(res["band"], "weak")

    def test_gap_identical_lab_deployments_look_like_a_fleet(self):
        # e.g. a university course where every student deploys the same WordPress lab in one /24.
        # Passive data can't tell this from a sensor fleet; only analyst context (or a real domain) can.
        self.assertEqual(score(fleet())["192.0.2.10"]["band"], "strong")


class ReferenceSensors(unittest.TestCase):
    def test_loaded_from_user_file_not_code(self):
        import json
        import tempfile
        from honeypot_hunter.hunt import load_reference_sensors
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "references.json"
            self.assertEqual(load_reference_sensors(p), [])  # missing file -> none
            p.write_text(json.dumps([{"ip": "203.0.113.10", "label": "mine"}, {"ip": "not-an-ip"}]), encoding="utf-8")
            self.assertEqual([r["ip"] for r in load_reference_sensors(p)], ["203.0.113.10"])


class AuditAndPivotWorkflow(unittest.TestCase):
    def setUp(self):
        self.fake = FakeShodan({build_stages(PROFILE)[-1]["query"]: 6})
        self.h = Hunter(ShodanClient("TESTKEY", transport=self.fake, min_interval=0), Store(":memory:"))
        stages = build_stages(PROFILE)
        r = self.h.run_hunt("t", stages[-1]["query"], PROFILE, stages, WS, WE)
        self.hid = r["huntId"]

    def test_rescore_makes_no_api_calls_and_moves_window(self):
        before = len(self.fake.urls)
        r = self.h.rescore(self.hid, window_start="2026-10-01")
        self.assertEqual(len(self.fake.urls), before)
        self.assertEqual(r["windowStart"], "2026-10-01")
        self.assertEqual(self.h.store.hunt_meta(self.hid)["windowStart"], "2026-10-01")

    def test_pivot_uses_only_free_counts_and_feeds_rarity(self):
        before = len(self.fake.urls)
        r = self.h.pivot(self.hid)
        new = self.fake.urls[before:]
        self.assertTrue(new)
        self.assertTrue(all("/shodan/host/count" in u for u in new), new)
        self.assertTrue(any(p["kind"] == "headers" for p in r["pivots"]))
        self.assertEqual(r["queryCredits"], 0)
        self.assertTrue(self.h.store.get_pivots(self.hid))

    def test_hunt_pivots_automatically_for_free(self):
        pv = self.h.store.get_pivots(self.hid)
        self.assertTrue(pv)
        self.assertEqual(sum("/shodan/host/search" in u for u in self.fake.urls), 1)  # still exactly one paid call

    def test_no_pivot_opt_out(self):
        stages = build_stages(PROFILE)
        before = len(self.fake.urls)
        r = self.h.run_hunt("t2", stages[-1]["query"], PROFILE, stages, WS, WE, auto_pivot=False)
        self.assertNotIn("pivot", r)
        self.assertEqual(len(self.fake.urls) - before, 2)  # one count + one search, nothing else

    def test_inspect_top_only_pivots_new_fingerprints(self):
        counted = {(p["kind"], p["value"]) for p in self.h.store.get_pivots(self.hid)}
        before = len(self.fake.urls)
        r = self.h.inspect_top(self.hid, 2)
        new_counts = [u for u in self.fake.urls[before:] if "/shodan/host/count" in u]
        self.assertEqual(len(new_counts), r.get("pivot", {}).get("counted", 0))
        self.assertTrue(counted <= {(p["kind"], p["value"]) for p in self.h.store.get_pivots(self.hid)})

    def test_rate_limit_during_pivot_does_not_fail_the_hunt(self):
        inner = FakeShodan({build_stages(PROFILE)[-1]["query"]: 6})
        seen = {"count": 0}

        def transport(url, timeout):
            if "/shodan/host/count" in url:
                seen["count"] += 1
                if seen["count"] > 1:  # the hunt's own count passes; the pivot's first count hits 429
                    return 429, b'{"error": "rate limited"}'
            return inner(url, timeout)
        h = Hunter(ShodanClient("TESTKEY", transport=transport, min_interval=0), Store(":memory:"))
        stages = build_stages(PROFILE)
        r = h.run_hunt("t", stages[-1]["query"], PROFILE, stages, WS, WE)
        self.assertEqual(r["status"], "ok")
        self.assertTrue(any(e.startswith("Stopped") for e in r["pivot"]["errors"]))
        self.assertEqual(seen["count"], 2)  # stopped after the first 429, never retried

    def test_audit_reports_fragility_and_gaps(self):
        a = self.h.audit(self.hid)
        self.assertIn("evasionCost", a)
        self.assertTrue(any("not inspected" in g for g in a["gaps"]))

    def test_evasion_cost_counts_signals_to_weak(self):
        res = score(fleet())["192.0.2.10"]
        n, removed = evasion_cost(res["signals"], res["capped"])
        self.assertGreaterEqual(n, 2)
        self.assertEqual(len(removed), n)


if __name__ == "__main__":
    unittest.main()
