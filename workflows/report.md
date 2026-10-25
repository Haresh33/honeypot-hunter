# Hunt report

Input: a hunt ID.

1. Run `python3 -m honeypot_hunter export <hunt_id> --format md -o ~/.honeypot-hunter/reports/honeypot-hunt-<hunt_id>.md`
   (create the folder if it doesn't exist). Reports contain real IPs from Shodan; keep them out of this skill's
   folder so they never end up in a shared repository.
2. Read the report and add a short executive summary at the top. Cover:
   - The profile and the count ladder.
   - How many candidates were found and how many were inspected.
   - The hosts marked likely sensor, and why.
   - The strongest candidates still unreviewed.
   - Fleet evidence and the pivot table: which shared fingerprints are rare on Shodan, and any lead outside the hunt.
   - Caveats: which signals are provisional, that a high score means a fingerprint match, not proof, and how this
     honeypot type did in the validation table in [README.md](../README.md).
3. Don't include the API key or anything from `.env`.
4. Before the user shares a report publicly, point out that it names third-party IPs and possibly someone's
   deception infrastructure.
