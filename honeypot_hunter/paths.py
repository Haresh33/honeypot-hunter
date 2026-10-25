"""Where per-user data lives: outside the skill folder, so the skill stays clean to share.

Default ~/.honeypot-hunter (override with HONEYPOT_HUNTER_HOME). It holds the
SQLite database, an optional .env with the Shodan key, and references.json
with your own confirmed reference sensors.
"""

from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("HONEYPOT_HUNTER_HOME") or (Path.home() / ".honeypot-hunter"))
