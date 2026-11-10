"""SQLite storage: allowed and blocked domains, applied versions and the audit log."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entry       TEXT NOT NULL UNIQUE,
    list        TEXT NOT NULL CHECK (list IN ('allow', 'block')),
    note        TEXT NOT NULL DEFAULT '',
    expires_on  TEXT NOT NULL DEFAULT '',
    added_by    TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acl_versions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    user        TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    acl         TEXT NOT NULL,
    snapshot    TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    user        TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

DOMAIN_FIELDS = ("entry", "list", "note", "expires_on", "added_by", "created_at")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class Database:
    def __init__(self, path: str):
        self.path = path
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ----- domains ----------------------------------------------------------
    def list_domains(self, kind: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM domains WHERE list = ?", (kind,)).fetchall()
        return [dict(r) for r in rows]

    def get_domain(self, domain_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
        return dict(row) if row else None

    def find_domain(self, entry: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM domains WHERE entry = ?", (entry,)).fetchone()
        return dict(row) if row else None

    def put_domain(self, entry: str, kind: str, user: str, note: str = "", expires_on: str = "") -> bool:
        """Add an entry to a list, moving it if it is on the other one. Returns False if already there."""
        with self.connect() as conn:
            row = conn.execute("SELECT list FROM domains WHERE entry = ?", (entry,)).fetchone()
            if row and row["list"] == kind:
                return False
            conn.execute("DELETE FROM domains WHERE entry = ?", (entry,))
            conn.execute(
                "INSERT INTO domains (entry, list, note, expires_on, added_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (entry, kind, note, expires_on, user, now()),
            )
        return True

    def update_domain(self, domain_id: int, note: str, expires_on: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE domains SET note = ?, expires_on = ? WHERE id = ?", (note, expires_on, domain_id))

    def delete_domains(self, ids: list[int], kind: str) -> list[str]:
        """Delete entries by id from one list and return the entries removed."""
        removed = []
        with self.connect() as conn:
            for domain_id in ids:
                row = conn.execute("SELECT entry FROM domains WHERE id = ? AND list = ?", (domain_id, kind)).fetchone()
                if row:
                    conn.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
                    removed.append(row["entry"])
        return removed

    def expired(self) -> list[dict[str, Any]]:
        """Allowed entries whose last valid day has passed."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domains WHERE list = 'allow' AND expires_on != '' AND expires_on < ?", (today(),)
            ).fetchall()
        return [dict(r) for r in rows]

    def replace_allowed(self, rows: list[dict[str, Any]]) -> None:
        """Replace the whole allow list (used when restoring a version)."""
        with self.connect() as conn:
            conn.execute("DELETE FROM domains WHERE list = 'allow'")
            for r in rows:
                conn.execute("DELETE FROM domains WHERE entry = ?", (r["entry"],))
                conn.execute(
                    "INSERT INTO domains (entry, list, note, expires_on, added_by, created_at) "
                    "VALUES (?, 'allow', ?, ?, ?, ?)",
                    (r["entry"], r.get("note", ""), r.get("expires_on", ""), r.get("added_by", ""),
                     r.get("created_at") or now()),
                )

    # ----- applied versions -------------------------------------------------
    def add_version(self, acl: str, user: str, note: str, rows: list[dict[str, Any]]) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO acl_versions (created_at, user, note, acl, snapshot) VALUES (?, ?, ?, ?, ?)",
                (now(), user, note, acl, json.dumps([{f: r.get(f, "") for f in DOMAIN_FIELDS} for r in rows])),
            )
            return int(cur.lastrowid)

    def list_versions(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, user, note FROM acl_versions ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_version(self, version_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM acl_versions WHERE id = ?", (version_id,)).fetchone()
        return dict(row) if row else None

    # ----- audit ------------------------------------------------------------
    def audit(self, user: str, action: str, detail: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audit (created_at, user, action, detail) VALUES (?, ?, ?, ?)",
                (now(), user, action, detail[:2000]),
            )

    def list_audit(self, limit: int = 300) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ----- meta -------------------------------------------------------------
    def meta(self, key: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
