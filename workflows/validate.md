# Validate or red-team the scoring

Use when the user asks whether the scores can be trusted, how a fleet operator could evade them, or after a scoring
change.

## Offline (free)

1. `python3 -m unittest discover -s tests`: `tests/test_adversarial.py` holds evasion, lookalike and known-gap
   scenarios. A failing known-gap test means a gap was closed or moved; update README's red-team table.
2. `audit <hunt_id>` on a real hunt: load-bearing signals (how many hosts change band if one signal were defeated),
   evasion cost per host, hosts resting mostly on fleet evidence, and data gaps.
3. `rescore <hunt_id>` after a change: re-scores from stored records with no API calls; report band changes.

## With labelled data (costs credits; ask first)

Accuracy needs labels that don't come from the scoring itself:

- **Negatives:** hosts of an organisation that obviously runs ordinary production servers (a large public website
  operator, a bank). Expect all weak.
- **Positives:** open-source honeypots in their default configuration, found by a fingerprint hard-coded in the
  project's own public source (a default page string, plant name or node name). Shodan's `tag:honeypot` is another
  label, but plans below Corporate can't search with it.

Procedure:
1. Size each set with free `explore` counts; narrow to ≤100 if possible (≤300 hard limit).
2. Write a prediction first (expected detection rate and why), and freeze the scoring.
3. Ask the user before each search; run `hunt --query '<label query>' --name "Validation: ..." --inspect-top 100`
   with **no profile and no window**, so profile-tuned signals don't bias the result.
4. Score with the label signals removed (`honeypot_tag`, and `honeypot_software` when the label is a banner) and
   report: share of positives at possible+ and strong, share of negatives at possible+, which signals separate the
   sets, and what the missed positives look like. Make sure `pivot` has run on both sets.
5. If you change the scoring because of the result, the improvement is in-sample: confirm it on a fresh holdout set
   before quoting it, and keep the production control at 0 false alarms.
