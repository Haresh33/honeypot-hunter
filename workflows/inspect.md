# Inspect one IP

Input: an IP address, and optionally a candidate ID from a saved hunt.

Run `python3 -m honeypot_hunter --json inspect <ip> [--candidate <id>]`. This is free and passive: never contact
the IP directly.

Explain the result:
- The score and band, plus each signal with its points. Without `--candidate`, the host is scored against an empty
  profile (no CVE, no campaign window, no fleet signals), so say that profile- and fleet-specific signals don't
  apply.
- What the port history shows: first and last sighting, number of observations, whether the banner stayed the same
  or changed. Many observations with a first sighting at the start of Shodan's history window usually means the
  history horizon, not a fresh deployment.
- The service shape: one web port (web-persona sensor) or many unrelated services (multi-honeypot host).
- The persona: does the page title read like a generated fake (bland corporate-intranet or hobby-blog name, CMS on
  a host with no owned domain)? Say so as a judgment, separate from the score.
- If the user has reference sensors in `~/.honeypot-hunter/references.json`, how the host compares with them.

End with a recommended verdict and the reason for it, in "likely sensor" / "unlikely" terms.
