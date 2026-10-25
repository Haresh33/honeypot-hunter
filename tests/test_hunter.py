import json
import sys
import threading
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_shodan import TEST_PRESET, FakeShodan  # noqa: E402

from honeypot_hunter.hunt import PRESETS, Hunter, HuntError, build_stages, seed_to_query  # noqa: E402
from honeypot_hunter.normalize import merge_search_matches  # noqa: E402
from honeypot_hunter.scoring import is_cloud_hostname, is_placeholder_domain, parse_ts, score_search  # noqa: E402
from honeypot_hunter.server import build_server  # noqa: E402
from honeypot_hunter.shodan_client import MAX_BODY_BYTES, MissingKey, RateLimited, ShodanClient, ShodanError  # noqa: E402
from honeypot_hunter.store import Store  # noqa: E402

TEST = TEST_PRESET


def make(counts=None, fail_on=None):
    fake = FakeShodan(counts, fail_on)
    client = ShodanClient("TESTKEY", transport=fake, min_interval=0)
    return Hunter(client, Store(":memory:")), fake


def run_test_hunt(h, confirmed=False):
    stages = build_stages(TEST["profile"])
    return h.run_hunt("t", stages[-1]["query"], TEST["profile"], stages, TEST["windowStart"], TEST["windowEnd"], confirmed)


class ClientTests(unittest.TestCase):
    def test_key_never_leaks_into_errors(self):
        fake = FakeShodan(fail_on={"/shodan/host/count": 401})
        c = ShodanClient("TESTKEY", transport=fake, min_interval=0)
        with self.assertRaises(ShodanError) as cm:
            c.count("x")
        self.assertNotIn("TESTKEY", str(cm.exception))
        self.assertEqual(cm.exception.status, 401)

    def test_429_is_hard_stop_no_retry(self):
        fake = FakeShodan(fail_on={"/shodan/host/count": 429})
        c = ShodanClient("TESTKEY", transport=fake, min_interval=0)
        with self.assertRaises(RateLimited):
            c.count("x")
        self.assertEqual(len(fake.urls), 1)

    def test_missing_key(self):
        c = ShodanClient("", transport=FakeShodan(), min_interval=0)
        with self.assertRaises(MissingKey):
            c.api_info()

    def test_only_shodan_host(self):
        c = ShodanClient("TESTKEY", transport=FakeShodan(), min_interval=0)
        c.host("203.0.113.10")  # fake asserts hostname == api.shodan.io

    def test_oversized_body_reported_as_truncated(self):
        calls = []
        def big(url, timeout):
            calls.append(url)
            return 200, b'{"matches": [' + b"x" * MAX_BODY_BYTES
        c = ShodanClient("TESTKEY", transport=big, min_interval=0)
        with self.assertRaises(ShodanError) as cm:
            c.search("x")
        self.assertIn("cut off", str(cm.exception))
        self.assertNotIn("TESTKEY", str(cm.exception))
        self.assertEqual(len(calls), 1)  # never retried

    def test_non_json_body_reports_size(self):
        c = ShodanClient("TESTKEY", transport=lambda url, timeout: (200, b"<html>busy</html>"), min_interval=0)
        with self.assertRaises(ShodanError) as cm:
            c.search("x")
        self.assertIn("not JSON (17 bytes, HTTP 200)", str(cm.exception))

    def test_pacing(self):
        import time
        c = ShodanClient("TESTKEY", transport=FakeShodan(), min_interval=0.2)
        t = time.monotonic(); c.api_info(); c.api_info(); c.api_info()
        self.assertGreaterEqual(time.monotonic() - t, 0.39)


class LadderTests(unittest.TestCase):
    def test_build_stages_matches_original(self):
        st = build_stages(TEST["profile"])
        self.assertEqual([s["label"] for s in st], ["Stack fingerprint", "+ Cloud org", "+ Region", "+ Persona & vuln flags"])
        self.assertEqual(st[0]["query"], 'product:"Apache httpd" version:"2.4.99" "PHP/8.9.9" port:80')
        self.assertEqual(st[-1]["query"], 'product:"Apache httpd" version:"2.4.99" "PHP/8.9.9" port:80 org:"Amazon Technologies Inc." country:IE http.component:"WordPress" vuln:CVE-2099-12345')

    def test_dedupes_and_title_only(self):
        st = build_stages({"title": "Staff Portal"})
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0]["query"], 'http.title:"Staff Portal"')

    def test_seed(self):
        self.assertEqual(seed_to_query("cve-2099-12345"), "vuln:CVE-2099-12345")
        self.assertEqual(seed_to_query("PHP/8.9.9"), '"PHP/8.9.9"')
        self.assertEqual(seed_to_query("tag:honeypot"), "tag:honeypot")

    def test_ladder_counts_free_and_stops_after_429(self):
        h, fake = make(fail_on={"/shodan/host/count": 429})
        out = h.count_ladder(build_stages(TEST["profile"]))
        self.assertEqual(len(fake.urls), 1)  # stopped after first 429
        self.assertTrue(all(s["error"] for s in out))


class GateTests(unittest.TestCase):
    def test_too_broad_refused_without_search(self):
        h, fake = make(counts={build_stages(TEST["profile"])[-1]["query"]: 301})
        r = run_test_hunt(h, confirmed=True)
        self.assertEqual(r["status"], "too_broad")
        self.assertFalse(any("/search" in u for u in fake.urls))

    def test_needs_confirm_then_runs(self):
        h, fake = make(counts={build_stages(TEST["profile"])[-1]["query"]: 150})
        self.assertEqual(run_test_hunt(h)["status"], "needs_confirm")
        self.assertFalse(any("/search" in u for u in fake.urls))
        r = run_test_hunt(h, confirmed=True)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(sum("/search" in u for u in fake.urls), 1)

    def test_zero_pool_no_search(self):
        h, fake = make(counts={build_stages(TEST["profile"])[-1]["query"]: 0})
        r = run_test_hunt(h)
        self.assertEqual((r["status"], r["returned"]), ("ok", 0))
        self.assertFalse(any("/search" in u for u in fake.urls))

    def test_bad_dates(self):
        h, _ = make()
        with self.assertRaises(HuntError):
            h.run_hunt("t", "x", {}, None, "10/22/2026", None)


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.h, self.fake = make(counts={build_stages(TEST["profile"])[-1]["query"]: 5})
        r = run_test_hunt(self.h)
        self.assertEqual(r["status"], "ok")
        self.hunt = self.h.store.get_hunt(r["huntId"])
        self.by_ip = {c["ip"]: c for c in self.hunt["candidates"]}

    def test_search_phase_port_signal_is_provisional(self):
        c = self.by_ip["203.0.113.10"]
        sp = [s for s in c["signals"] if s["key"] == "single_port"][0]
        self.assertTrue(sp["provisional"])
        self.assertEqual(sp["points"], 9)
        self.assertFalse(c["data"]["ports_verified"])

    def test_html_entities_unescaped(self):
        self.assertEqual(self.by_ip["203.0.113.10"]["data"]["title"], "Internal Dashboard – Team & Project Updates")

    def test_reference_sensor_scores_strong_after_inspection(self):
        c = self.by_ip["203.0.113.10"]
        r = self.h.inspect(c["ip"], c["id"])
        self.assertTrue(r["ok"])
        after = self.h.store.get_candidate(c["id"])
        keys = {s["key"] for s in after["signals"]}
        self.assertIn("first_seen_in_window", keys)
        self.assertIn("single_sighting", keys)
        self.assertNotIn("in_window", keys)  # replaced by first-seen timing
        self.assertTrue(after["data"]["ports_verified"])
        self.assertEqual(after["band"], "strong")
        self.assertEqual(after["searchScore"], c["score"])

    def test_production_host_drops_after_inspection(self):
        c = self.by_ip["198.51.100.20"]
        self.h.inspect(c["ip"], c["id"])
        after = self.h.store.get_candidate(c["id"])
        keys = {s["key"] for s in after["signals"]}
        self.assertTrue({"real_domain", "ssh_open", "many_ports"} <= keys, keys)
        self.assertLess(after["score"], c["score"])
        self.assertEqual(after["band"], "weak")

    def test_placeholder_domain_is_not_real(self):
        self.assertTrue(is_placeholder_domain("invalid"))
        self.assertTrue(is_placeholder_domain("192.0.2.EARLY-REGISTRATION.of.example-nren.invalid."))
        self.assertFalse(is_placeholder_domain("acme-example.com"))
        c = self.by_ip["192.0.2.102"]
        self.h.inspect(c["ip"], c["id"])
        for cand in (c, self.h.store.get_candidate(c["id"])):
            sig = {s["key"]: s for s in cand["signals"]}
            self.assertNotIn("real_domain", sig)
            self.assertIn("placeholder", sig["no_real_domain"]["detail"])

    def test_persistent_fleet_gets_stability(self):
        c = self.by_ip["198.51.100.9"]
        self.h.inspect(c["ip"], c["id"])
        after = self.h.store.get_candidate(c["id"])
        st = [s for s in after["signals"] if s["key"] == "banner_stability"]
        self.assertTrue(st and st[0]["points"] == 18, after["signals"])
        self.assertNotIn("first_seen_in_window", {s["key"] for s in after["signals"]})

    def test_inspection_skips_retired_honeyscore(self):
        c = self.by_ip["203.0.113.10"]
        self.h.inspect(c["ip"], c["id"])
        self.assertFalse(any("/labs/honeyscore" in u for u in self.fake.urls))

    def test_noise_gate(self):
        c = self.by_ip["198.51.100.99"]
        self.h.inspect(c["ip"], c["id"])
        after = self.h.store.get_candidate(c["id"])
        self.assertIn("answers_everything", {s["key"] for s in after["signals"]})
        self.assertEqual(after["band"], "weak")
        self.assertLessEqual(after["score"], 34)

    def test_reinspect_is_idempotent(self):
        c = self.by_ip["203.0.113.10"]
        self.h.inspect(c["ip"], c["id"]); s1 = self.h.store.get_candidate(c["id"])["score"]
        self.h.inspect(c["ip"], c["id"]); s2 = self.h.store.get_candidate(c["id"])["score"]
        self.assertEqual(s1, s2)

    def test_history_unavailable_falls_back(self):
        h, _ = make(counts={build_stages(TEST["profile"])[-1]["query"]: 5}, fail_on={"history": 403})
        r = run_test_hunt(h)
        c = [x for x in h.store.get_hunt(r["huntId"])["candidates"] if x["ip"] == "203.0.113.10"][0]
        res = h.inspect(c["ip"], c["id"])
        self.assertTrue(res["ok"])
        self.assertIn("unavailable", res["detail"]["history_error"])
        self.assertIn("in_window", {s["key"] for s in h.store.get_candidate(c["id"])["signals"]})

    def test_inspect_top_and_export(self):
        r = self.h.inspect_top(self.hunt["hunt"]["id"], 3)
        self.assertEqual(r["inspected"], 3)
        self.h.store.set_verdict(self.by_ip["203.0.113.10"]["id"], "likely_sensor", "matches reference")
        fname, md = self.h.export_markdown(self.hunt["hunt"]["id"])
        self.assertIn("## Count ladder", md)
        self.assertIn("likely_sensor", md)
        self.assertIn("matches reference", md)
        self.assertNotIn("TESTKEY", md)
        js = json.dumps(self.h.export_json(self.hunt["hunt"]["id"]))
        self.assertNotIn("TESTKEY", js)

    def test_honeypot_software_and_tag(self):
        m = [{"ip_str": "192.0.2.4", "port": 22, "product": "Cowrie SSH honeypot", "tags": ["honeypot"], "hostnames": [], "domains": []}]
        row = merge_search_matches(m)[0]
        s = score_search(row, {}, None, None)
        keys = {x["key"] for x in s["signals"]}
        self.assertTrue({"honeypot_software", "honeypot_tag"} <= keys)

    def test_helpers(self):
        self.assertTrue(is_cloud_hostname("ec2-1-2-3-4.eu-west-1.compute.amazonaws.com"))
        self.assertFalse(is_cloud_hostname("notamazonaws.com"))
        self.assertEqual(parse_ts("2026-10-23T08:32:44.123456"), parse_ts("2026-10-23T08:32:44.123456Z"))


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h, _ = make(counts={build_stages(TEST["profile"])[-1]["query"]: 5})
        cls.srv = build_server(cls.h, "127.0.0.1", 0)
        port = cls.srv.server_address[1]
        # rebuild allowed host set for the ephemeral port
        cls.srv.server_close()
        cls.srv = build_server(cls.h, "127.0.0.1", port)
        cls.base = f"http://127.0.0.1:{port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def req(self, path, body=None, headers=None):
        h = {"Content-Type": "application/json", "X-Honeypot-Hunter": "1"} if body is not None else {}
        h.update(headers or {})
        r = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, headers=h, method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_index_and_bootstrap(self):
        st, body = self.req("/")
        self.assertEqual(st, 200); self.assertIn(b"Honeypot Hunter", body)
        st, body = self.req("/api/bootstrap")
        self.assertNotIn(b"TESTKEY", body)
        self.assertTrue(json.loads(body)["hasKey"])

    def test_csrf_header_required(self):
        st, _ = self.req("/api/explore", {"query": "x"}, headers={"X-Honeypot-Hunter": ""})
        self.assertEqual(st, 403)
        st, _ = self.req("/api/explore", {"query": "x"}, headers={"Origin": "https://evil.example"})
        self.assertEqual(st, 403)

    def test_bad_host_header(self):
        st, _ = self.req("/api/bootstrap", headers={"Host": "evil.example:80"})
        self.assertEqual(st, 403)

    def test_full_flow(self):
        stages = self.req("/api/stages", {"profile": TEST["profile"]})
        q = json.loads(stages[1])["stages"][-1]["query"]
        st, body = self.req("/api/hunt", {"name": "srv", "query": q, "profile": TEST["profile"], "windowStart": "2026-10-22", "windowEnd": "2026-10-24"})
        r = json.loads(body); self.assertEqual(r["status"], "ok")
        st, body = self.req(f"/api/hunts/{r['huntId']}")
        cands = json.loads(body)["candidates"]
        st, body = self.req("/api/inspect", {"ip": cands[0]["ip"], "candidateId": cands[0]["id"]})
        self.assertTrue(json.loads(body)["ok"])
        st, body = self.req("/api/verdict", {"candidateId": cands[0]["id"], "verdict": "ruled_out"})
        self.assertEqual(st, 200)
        st, body = self.req(f"/api/hunts/{r['huntId']}/export?format=md")
        self.assertEqual(st, 200); self.assertIn(b"ruled_out", body)
        st, _ = self.req("/api/verdict", {"candidateId": cands[0]["id"], "verdict": "bogus"})
        self.assertEqual(st, 400)
        st, _ = self.req("/api/inspect", {"ip": "not-an-ip"})
        self.assertEqual(st, 400)


if __name__ == "__main__":
    unittest.main()
