# Guided hunt

Input: a preset, CVE, banner/product version, or Shodan query, plus any profile flags the user gave.
For a brand-new CVE that should be tracked over time, use [cve-check.md](cve-check.md) instead.

Follow the hard rules in [SKILL.md](../SKILL.md). Use `python3 -m honeypot_hunter --json ...` and parse the output.

1. Run `info` to confirm the key is loaded and see the remaining query credits. If the key isn't loaded, stop and
   tell the user to put `SHODAN_API_KEY=...` in `~/.honeypot-hunter/.env` themselves.
2. Work out the starting point:
   - If the input names a preset (`presets` lists them), use `--preset`. `web_sensor_example` is only a template:
     replace its placeholder values with real ones before running a ladder. `shodan_tagged` only works for free counts
     on plans below Corporate: a *search* with `tag:` is refused.
   - Otherwise run `explore "<input>"` (free) and show the facet breakdown. Point out any anomalous cluster, such as
     one org, city or product holding a big share of identical hosts. Propose profile flags built from it.
3. Run `ladder` with that profile (free). Show each stage's count as a short table.
   - If the final pool is over 300, suggest which field would narrow it and run the ladder again. Do not search.
   - Prefer a final query without `vuln:` or `tag:` when the plan may refuse those in searches.
4. **Stop and ask** before spending a credit. Show the final query, the pool size and the credits left. Only add
   `--yes` if the pool is 101–300 and the user explicitly agrees.
5. When approved, run `hunt ... --inspect-top 10` (or more, up to the pool size). Inspections and the automatic
   pivot are free. Stop on any 429.
6. Run `audit <hunt_id>` (offline) and act on its gaps: `pivot <hunt_id>` if pivots are missing, `inspect-top` if
   many candidates are uninspected.
7. Run `show <hunt_id>` and summarise:
   - Top candidates ranked by inspected score, with their key signals.
   - Fleet evidence: shared persona and its global count from the pivot (rare template vs common page), cloned SSH
     keys or certs, dense /24, deployment burst. Name any pivot that points outside the hunt (other orgs with the
     same fingerprint) as a lead for the next hunt.
   - Campaign-fleet pattern (single fresh sighting) vs persistent-fleet pattern (banner frozen for months, still
     vuln-flagged).
   - Hosts ruled out by owned domains, SSH (web-persona hunts only), many ports, or the noise gate.
   - Signals still provisional, and hosts the audit marks fragile (one signal from weak).
   - If the user has reference sensors (`~/.honeypot-hunter/references.json`), how candidates compare with them.
   - Persona style: read the candidate titles and say whether they share a fake-persona style even where the exact
     titles differ (see "Reading personas" in [SKILL.md](../SKILL.md)). Supporting evidence only, not a score.
8. Say plainly what the evidence supports, using "likely sensor" wording.
9. Suggest verdicts but don't set them until the user agrees. Offer a report ([report.md](report.md)).

Never contact any candidate host directly.
