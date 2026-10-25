"""Run the console against the offline fake Shodan (no key, no network):
    python3 tests/demo_server.py [port]
"""
import sys
from pathlib import Path
sys.path[:0] = [str(Path(__file__).resolve().parent.parent), str(Path(__file__).resolve().parent)]
from fake_shodan import FakeShodan
from fake_shodan import TEST_PRESET
from honeypot_hunter.hunt import Hunter, build_stages
from honeypot_hunter.server import serve
from honeypot_hunter.shodan_client import ShodanClient
from honeypot_hunter.store import Store

final = build_stages(TEST_PRESET["profile"])[-1]["query"]
hunter = Hunter(ShodanClient("TESTKEY", transport=FakeShodan({final: 5}), min_interval=0.05), Store(":memory:"))
serve(hunter, "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8787, open_browser=False)
