"""SQLite persistence: saved hunts, scored candidates, verdicts, cached inspections."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

VERDICTS = ("unreviewed", "likely_sensor", "ruled_out")

MIGRATIONS = [
    # v1 — same shape as the original artifact's tables.
    """
    CREATE TABLE hunts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      query TEXT NOT NULL,
      profile_json TEXT NOT NULL,
      ladder_json TEXT,
      window_start TEXT,
      window_end TEXT,
      total INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE candidates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hunt_id INTEGER NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
      ip TEXT NOT NULL,
      score INTEGER NOT NULL,
      band TEXT NOT NULL,
      signals_json TEXT NOT NULL,
      data_json TEXT NOT NULL,
      detail_json TEXT,
      verdict TEXT NOT NULL DEFAULT 'unreviewed',
      created_at INTEGER NOT NULL
    );
    CREATE INDEX candidates_hunt_idx ON candidates (hunt_id, score);
    """,
    # v2 — analyst notes + inspection timestamp + search-phase score kept for comparison.
    """
    ALTER TABLE candidates ADD COLUMN notes TEXT NOT NULL DEFAULT '';
    ALTER TABLE candidates ADD COLUMN inspected_at INTEGER;
    ALTER TABLE candidates ADD COLUMN search_score INTEGER;
    """,
    # v3 — free fingerprint pivots (global Shodan counts per shared fingerprint).
    """
    CREATE TABLE pivots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hunt_id INTEGER NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      value TEXT NOT NULL,
      query TEXT NOT NULL,
      hunt_hosts INTEGER NOT NULL,
      total INTEGER,
      facets_json TEXT,
      error TEXT,
      created_at INTEGER NOT NULL,
      UNIQUE (hunt_id, kind, value)
    );
    """,
]


def _iso(ms: Optional[int]) -> Optional[str]:
    if ms is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000))


class Store:
    def __init__(self, path: "str | Path"):
        self.path = str(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            for i, sql in enumerate(MIGRATIONS[version:], start=version + 1):
                self._db.executescript(sql)
                self._db.execute(f"PRAGMA user_version = {i}")
            self._db.commit()

    # ---- hunts -------------------------------------------------------------

    def create_hunt(self, name: str, query: str, profile: dict, ladder: Optional[list], window_start: Optional[str], window_end: Optional[str], total: int, scored: list[dict]) -> int:
        now = int(time.time() * 1000)
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO hunts (name, query, profile_json, ladder_json, window_start, window_end, total, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (name, query, json.dumps(profile), json.dumps(ladder) if ladder else None, window_start, window_end, total, now),
            )
            hunt_id = int(cur.lastrowid)
            self._db.executemany(
                "INSERT INTO candidates (hunt_id, ip, score, band, signals_json, data_json, verdict, created_at, search_score) VALUES (?,?,?,?,?,?,'unreviewed',?,?)",
                [(hunt_id, s["data"]["ip"], s["score"], s["band"], json.dumps(s["signals"]), json.dumps(s["data"]), now, s["score"]) for s in scored],
            )
        return hunt_id

    def _hunt_row(self, row: sqlite3.Row, count: int) -> dict:
        return {
            "id": row["id"], "name": row["name"], "query": row["query"],
            "profile": json.loads(row["profile_json"] or "{}"),
            "ladder": json.loads(row["ladder_json"]) if row["ladder_json"] else None,
            "windowStart": row["window_start"], "windowEnd": row["window_end"],
            "total": row["total"], "created_at": _iso(row["created_at"]), "candidateCount": count,
        }

    def list_hunts(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT h.*, (SELECT COUNT(*) FROM candidates c WHERE c.hunt_id = h.id) AS n, "
                "(SELECT COUNT(*) FROM candidates c WHERE c.hunt_id = h.id AND c.verdict='likely_sensor') AS likely "
                "FROM hunts h ORDER BY h.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            h = self._hunt_row(r, r["n"])
            h["likelyCount"] = r["likely"]
            out.append(h)
        return out

    def get_hunt(self, hunt_id: int) -> Optional[dict]:
        with self._lock:
            row = self._db.execute("SELECT * FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
            if not row:
                return None
            cands = self._db.execute("SELECT * FROM candidates WHERE hunt_id = ? ORDER BY score DESC, ip ASC", (hunt_id,)).fetchall()
        return {"hunt": self._hunt_row(row, len(cands)), "candidates": [self._cand(c) for c in cands]}

    def delete_hunt(self, hunt_id: int) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM pivots WHERE hunt_id = ?", (hunt_id,))
            self._db.execute("DELETE FROM candidates WHERE hunt_id = ?", (hunt_id,))
            self._db.execute("DELETE FROM hunts WHERE id = ?", (hunt_id,))

    # ---- candidates ---------------------------------------------------------

    def _cand(self, r: sqlite3.Row) -> dict:
        return {
            "id": r["id"], "huntId": r["hunt_id"], "ip": r["ip"], "score": r["score"], "band": r["band"],
            "searchScore": r["search_score"],
            "signals": json.loads(r["signals_json"] or "[]"),
            "data": json.loads(r["data_json"] or "{}"),
            "detail": json.loads(r["detail_json"]) if r["detail_json"] else None,
            "verdict": r["verdict"], "notes": r["notes"], "inspected_at": _iso(r["inspected_at"]),
        }

    def get_candidate(self, cand_id: int) -> Optional[dict]:
        with self._lock:
            r = self._db.execute("SELECT * FROM candidates WHERE id = ?", (cand_id,)).fetchone()
        return self._cand(r) if r else None

    def update_inspection(self, cand_id: int, data: dict, detail: dict, score: int, band: str, signals: list[dict]) -> None:
        with self._lock, self._db:
            self._db.execute(
                "UPDATE candidates SET data_json=?, detail_json=?, score=?, band=?, signals_json=?, inspected_at=? WHERE id=?",
                (json.dumps(data), json.dumps(detail), score, band, json.dumps(signals), int(time.time() * 1000), cand_id),
            )

    def update_scores(self, rows: "list[tuple[int, int, str, list[dict], bool]]") -> None:
        """rows: (cand_id, score, band, signals, search_phase). Search-phase rows also refresh search_score."""
        with self._lock, self._db:
            for cid, score, band, signals, search_phase in rows:
                if search_phase:
                    self._db.execute("UPDATE candidates SET score=?, band=?, signals_json=?, search_score=? WHERE id=?", (score, band, json.dumps(signals), score, cid))
                else:
                    self._db.execute("UPDATE candidates SET score=?, band=?, signals_json=? WHERE id=?", (score, band, json.dumps(signals), cid))

    def set_window(self, hunt_id: int, window_start: Optional[str], window_end: Optional[str]) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE hunts SET window_start=?, window_end=? WHERE id=?", (window_start, window_end, hunt_id))

    def save_pivot(self, hunt_id: int, kind: str, value: str, query: str, hunt_hosts: int, total: Optional[int], facets: Optional[dict], error: Optional[str]) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO pivots (hunt_id, kind, value, query, hunt_hosts, total, facets_json, error, created_at) VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT (hunt_id, kind, value) DO UPDATE SET query=excluded.query, hunt_hosts=excluded.hunt_hosts, total=excluded.total, "
                "facets_json=excluded.facets_json, error=excluded.error, created_at=excluded.created_at",
                (hunt_id, kind, value, query, hunt_hosts, total, json.dumps(facets) if facets else None, error, int(time.time() * 1000)),
            )

    def get_pivots(self, hunt_id: int) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM pivots WHERE hunt_id = ? ORDER BY hunt_hosts DESC, kind", (hunt_id,)).fetchall()
        return [{"kind": r["kind"], "value": r["value"], "query": r["query"], "huntHosts": r["hunt_hosts"], "total": r["total"],
                 "facets": json.loads(r["facets_json"]) if r["facets_json"] else None, "error": r["error"], "created_at": _iso(r["created_at"])} for r in rows]

    def set_verdict(self, cand_id: int, verdict: str, notes: Optional[str] = None) -> bool:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        with self._lock, self._db:
            if notes is None:
                cur = self._db.execute("UPDATE candidates SET verdict=? WHERE id=?", (verdict, cand_id))
            else:
                cur = self._db.execute("UPDATE candidates SET verdict=?, notes=? WHERE id=?", (verdict, notes[:2000], cand_id))
        return cur.rowcount > 0

    def hunt_meta(self, hunt_id: int) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._db.execute("SELECT * FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
        return self._hunt_row(row, 0) if row else None
