# Honeypot Hunter

A Claude Code skill (and standalone CLI / local web console) that hunts for honeypot and sensor fleets using only
data from the Shodan API. Pure Python standard library, 3.9+, no dependencies.

> **Passive only.** The tool never connects to a candidate host. Every signal comes from data Shodan has already
> collected, read through `api.shodan.io`; no other host is ever contacted.

## Install as a Claude Code skill

```bash
git clone <this repo> ~/.claude/skills/honeypot-hunter      # personal skill, available in every project
# or, for one project only:
git clone <this repo> .claude/skills/honeypot-hunter
```

Then set up your data folder (kept outside the skill so the repo never holds your data):

```bash
mkdir -p ~/.honeypot-hunter
echo 'SHODAN_API_KEY=your-key-here' > ~/.honeypot-hunter/.env     # do this yourself, so the key never passes through a chat
chmod 600 ~/.honeypot-hunter/.env
cp ~/.claude/skills/honeypot-hunter/references.example.json ~/.honeypot-hunter/references.json   # optional
```

Ask Claude things like *"hunt for bait servers for CVE-2026-12345, disclosed 2026-11-02"*, *"does 203.0.113.10
look like a honeypot?"* or *"write up hunt 3"*. The skill ([SKILL.md](SKILL.md)) follows its hard rules: passive
only, never reads your key, and stops for your yes before spending a query credit.

| Workflow | What it does |
|---|---|
| [hunt](workflows/hunt.md) | Free facets → free count ladder → your OK → 1-credit search → free inspection, pivot and audit → summary |
| [cve-check](workflows/cve-check.md) | New-CVE check run as an out-of-sample test: prediction first, frozen scoring, comparison with earlier hunts, a re-check ~2 weeks later |
| [inspect](workflows/inspect.md) | Explain one IP's score |
| [report](workflows/report.md) | Export a hunt with an executive summary |
| [validate](workflows/validate.md) | Red-team the scoring, audit a hunt, or measure it against labelled hosts |

### Data folder (`~/.honeypot-hunter`, or `HONEYPOT_HUNTER_HOME`)

| File | Purpose |
|---|---|
| `.env` | `SHODAN_API_KEY=...` (or export the variable instead) |
| `honeypot_hunter.db` | Saved hunts, scores, verdicts, pivots (`HONEYPOT_HUNTER_DB` overrides the path) |
| `references.json` | Optional: your own confirmed sensors, used for calibration (`[{"ip", "label", "note"}]`) |
| `cve-checks/`, `reports/` | Written by the cve-check and report workflows |

These contain real IPs and your key. Never commit them; `.gitignore` excludes them if you keep them in the repo
folder by mistake.

## Standalone use

```bash
export SHODAN_API_KEY=...                         # or ~/.honeypot-hunter/.env
python3 -m honeypot_hunter serve                  # local console at http://127.0.0.1:8787
python3 -m honeypot_hunter --json info            # CLI; add --json to any command
# or: pip install . && honeypot-hunter serve
```

```bash
honeypot-hunter info                               # plan + credits
honeypot-hunter explore CVE-2099-12345             # free facets
honeypot-hunter ladder --product 'Apache httpd' --server-version 2.4.99 --org 'Example Cloud Inc.'   # free counts
honeypot-hunter hunt --product 'Apache httpd' --server-version 2.4.99 --inspect-top 10   # 1 credit, asks above 100 hosts
honeypot-hunter hunt --query 'product:"Apache httpd" org:"Example Cloud"' --yes
honeypot-hunter inspect 203.0.113.10
honeypot-hunter list | show 3 | inspect-top 3 -n 20 [--refresh]
honeypot-hunter pivot 3                            # free fingerprint counts (automatic after hunt)
honeypot-hunter rescore 3 --window-start 2026-10-21 # re-score from stored data, 0 API calls
honeypot-hunter audit 3                            # how an operator could dodge these scores
honeypot-hunter verdict 17 likely_sensor --notes "matches reference"
honeypot-hunter export 3 --format md -o report.md
```

## Workflow

1. **Cold start (facet explorer).** One free count for a CVE, a banner or any query, broken down by org, city,
   product, port and country. Look for an anomaly, such as one cloud or city holding many identical hosts.
2. **Hunt profile.** Up to 11 fields: cloud org, port, country, city, web server, server version, language banner,
   CMS/persona fragment, CVE, hostname and page title, plus a campaign window (UTC days). Presets: *web_sensor_example*
   (a template with placeholder values to replace) and *Shodan-tagged honeypots* (counts only on plans below Corporate).
3. **Count ladder.** Free counts at each narrowing stage (stack → + cloud org → + region → + persona & vuln flags).
4. **Run hunt.** The only call that costs credits, and it is gated: pools over **300** are refused, pools over
   **100** need explicit confirmation, and it fetches **one page (at most 100 hosts, 1 query credit)**.
5. **Inspect.** Host record and full history, one candidate or a batch. Free. Re-scores the candidate and the hunt.
6. **Pivot (free, automatic).** For every fingerprint two or more hunt hosts share (page hash, title, headers,
   favicon, robots.txt, TLS cert, JARM, SSH host key, HASSH), one free count shows how many hosts on all of Shodan
   carry it and in which orgs. A rare fingerprint is a fleet template, and its count is a ready-made next query.
7. **Audit (offline).** Load-bearing signals, evasion cost per host, and data gaps.
8. **Verdicts and notes**, then **export** a Markdown or JSON report.

## Behaviour score (0–100)

| Signal | Pts | When |
|---|---:|---|
| Bare cloud hostname only | +18 | search |
| No owned domain / owned domain attached (placeholder and reserved names such as `.invalid` or `example.com`, and the ISP's or hoster's own reverse-DNS names that embed the IP, don't count as owned) | +10 / −15 | search |
| Single open port | +9 provisional → +18 verified | search → inspection |
| Very few ports | +2 provisional → +4 verified | search → inspection |
| Many open ports (>3) | −12 | either |
| SSH (22) exposed (web-persona hunts only; multi-honeypot hosts run SSH honeypots) | −10 | either |
| Answers on 40+ ports: noise gate, **score capped at 34 (weak)**, unless it runs a service zoo | −30 | inspection |
| Service zoo: 6+ unrelated service families with real banners on one host (T-Pot-style multi-honeypot) | +15 | inspection |
| Out-of-support product that honeypots emulate by default (MS-SQL Server 2000) | +8 | inspection |
| Generic / internal page title, or no title | +10 / +4 | search |
| Flagged for the profile CVE, or ≥5 CVEs | +15 / +3 | search |
| Cloud tenancy · Shodan `cloud` tag | +5 · +3 | search |
| Shodan `honeypot` tag | +20 | search |
| Known honeypot software fingerprint (Cowrie, Kippo, Dionaea, Conpot…) | +25 | search |
| Last observed inside the window / fresh (<14 d) | +15 / +6 | search (fallback) |
| **First** sighted inside the campaign window | +15 | inspection |
| Single Shodan sighting ever | +4 | inspection |
| Frozen banner ≥180 d / ≥90 d / ≥30 d while still vuln-flagged (persistent fleet) | +18 / +14 / +7 | inspection |
| ≥180 d history with changing banners or titles (production-like) | −12 | inspection |

### Fleet (cluster) signals

Per-host signals can be dodged one host at a time. These look across every candidate in the hunt for what a fleet
can't cheaply avoid. They are recomputed after every search, inspection, pivot and `rescore`.

| Signal | Pts |
|---|---:|
| Cloned persona: the same non-default page hash or title on ≥3 hunt hosts | +10 (rarity unknown) / +15 (rare on Shodan) / 0 (common on Shodan) |
| Same page under ≥3 different owned domains, one per host (decoy domains; offsets the −15) | +15 |
| SSH host key cloned across IPs (one disk image) | +12 |
| Self-signed or domainless TLS certificate cloned across IPs | +8 |
| Dense /24: ≥5 hosts and ≥25% of the hunt in one block | +5 |
| Deployment burst: ≥5 hosts and ≥25% of inspected hosts first seen within 48 h | +6 |
| Noise gate lifted: a 40+-port host serving the fleet's rare persona is uncapped, and its −30 becomes −12 | — |

A persona already in the query (`http.title:`, `http.html_hash:`, `--title`) doesn't count, since every host shares it
by construction. Default, empty and HTTP-status pages never count, and hosts with more than 5 Shodan sightings are
left out of the burst (long-lived hosts all look "first seen" at the start of Shodan's history window).

Bands: **≥55 strong**, **≥35 possible**, otherwise weak. A high score means the host matches the fingerprint. It does
not prove the host is a sensor.

### Red-teaming the score

`tests/test_adversarial.py` models what a fleet operator would do to stay hidden, and what production setups look
like a fleet:

| Scenario | Result |
|---|---|
| Decoy SSH and extra ports on every sensor | caught (cloned host key, persona, block, burst) |
| A throwaway domain per sensor, plus SSH | caught as *possible* (decoy-domains offset) |
| Port-spoofer front to trip the noise gate | caught (gate lifted when the persona matches the fleet) |
| Spread across providers and weeks | partly caught: the persona remains, block and burst vanish |
| Multi-honeypot host (many unrelated emulated services) | caught (service zoo, emulated legacy product) |
| Default pages, globally common pages, load-balanced owned-domain certs | not over-scored |
| Empty or redirect pages, a multi-domain CDN estate, long-lived hosts at the history horizon | not over-scored |
| A busy production server with several services and an owned domain | not over-scored |
| **Gap:** unique page per host + own domain + own key + spread out | invisible to the cluster phase; scores weak |
| **Gap:** identical lab or classroom deployments in one block | look exactly like a fleet; only analyst context helps |

### Validation against independently labelled hosts (Oct 2026)

Scored with no profile and no window, with `honeypot_tag` and `honeypot_software` removed so the label can't leak in:

| Set | Label source | Possible or strong |
|---|---|---:|
| 68 production servers of a large public-website operator | ownership | **0%** (scores 0–5) |
| 34 Log4Pot hosts (CVE-2021-44228) | a string hard-coded in Log4Pot's default fake page; 28 also Shodan-tagged | 26% → **56%** after the service-zoo, SSH and domain fixes (in-sample) |
| **Holdout:** 99 Conpot hosts (default plant name), scoring frozen | Conpot's default config; all Shodan-tagged | 7% without `pivot` → **68% with `pivot`** (99% if Shodan's own "Conpot" product name is allowed) |

What carries detection outside web-persona fleets is the fleet signals plus `pivot` rarity (in the holdout, one
template on a few hundred hosts worldwide and one SSH key cloned on over a hundred). Per-host signals alone catch
about 5% of non-web honeypots, and almost none reach *strong* without the honeypot-software name. **Make sure `pivot`
has run before judging a hunt** (it runs automatically after `hunt` and `inspect-top`). The Log4Pot improvement is
in-sample; the remaining misses mostly carry the many-ports penalty, and a few lose points to a hoster's VPS name
that doesn't embed the IP.

## Safety and security

- API calls are restricted to `https://api.shodan.io`, checked on every request. Calls are spaced about 1.1 s apart,
  and a 429 is reported, never retried.
- The key is read from the environment or a `.env` file and scrubbed from every error message. It never appears in
  the UI, the database or reports.
- The console listens on `127.0.0.1` only. It rejects requests with an unexpected Host header (DNS rebinding), and
  every state-changing request needs a custom header with no CORS preflight approved, so other websites can't spend
  your credits.
- All Shodan-derived text is rendered with `textContent`, because a honeypot's page title is attacker-controlled.
- Reports and the database name third-party IPs, possibly someone's deception infrastructure. Think before sharing
  them publicly.

## Tests

```bash
python3 -m unittest discover -s tests       # offline (fake Shodan transport), incl. the adversarial suite
python3 tests/demo_server.py                # the console with synthetic data, no key needed
```

Test fixtures use only documentation addresses (RFC 5737 / RFC 2544) and ASNs (RFC 5398).

## Notes

- Filters such as `vuln:` and `tag:` need a paid Shodan plan for searches; counts with them work on lower plans.
  Host history and some pivot filters may not be available on every plan. If they aren't, inspection still works
  and says what was missing.
- Use this for defensive research, such as mapping deception infrastructure and checking your own sensors'
  exposure, within Shodan's terms of service.
