# Honeypot Hunter: notes for Claude Code (developing this repo)

Using the tool is covered by [SKILL.md](SKILL.md) and its hard rules, which apply here too: passive only, never
read `.env`, ask before `hunt`, stop on 429, keep the safeguards. These notes are for changing the code.

## Commands

```bash
python3 -m unittest discover -s tests          # offline test suite (fake Shodan), run after every change
python3 tests/demo_server.py 8787              # console with synthetic data, no key needed
```

## Layout

- `honeypot_hunter/shodan_client.py`: the HTTP client (allow-list, pacing, 429 hard stop, key redaction, 32 MB
  response cap). Endpoints: api-info, host/count, host/search, host/{ip}.
- `paths.py`: the per-user data folder (`~/.honeypot-hunter`, `HONEYPOT_HUNTER_HOME`). Nothing user-specific lives
  in the repo.
- `normalize.py`: raw Shodan JSON to candidate rows and host detail (services, per-port timeline, fingerprints in
  `data["fp"]`). A search returns only *matched* banners, so `ports_verified=False` until the host is inspected.
- `scoring.py`: per-host score, then `cluster_signals` across the hunt. `score_hunt` is the single entry point.
  Bands are 55 and 35. The 40+-port noise gate caps at 34 unless a service zoo or a rare fleet persona lifts it.
- `hunt.py`: workflow (`build_stages`, `explore`, `count_ladder`, gated `run_hunt`, `inspect`, `inspect_top`,
  `rescore`, `pivot`, `audit`, exports), presets, and the `references.json` loader.
- `store.py`: SQLite with `PRAGMA user_version` migrations. To change the schema, **append** to `MIGRATIONS`;
  never edit an existing entry.
- `server.py` + `static/index.html`: localhost JSON API and a vanilla-JS UI. Render Shodan text with `textContent`
  only, never `innerHTML`.
- `tests/fake_shodan.py`: offline transport. `tests/test_adversarial.py`: evasion, lookalike and known-gap scenarios.

## Changing the scoring

Every signal is `{key, label, points, detail, phase, provisional}` (`phase` is search, inspection or cluster), so a
new signal needs a clear label and detail string. After adding or reweighting one: add a fixture host to
`tests/fake_shodan.py` if needed, a test to `tests/test_hunter.py`, an evasion or lookalike scenario to
`tests/test_adversarial.py`, and update the tables in README.md. Say whether a change is a general fix or tuned on
one data set; tuned changes need a holdout before their numbers are quoted.

**Test data:** use only documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15),
documentation ASNs (AS64496–AS64511) and fictional org, domain and persona names. Never commit real IPs, reports or
databases.
