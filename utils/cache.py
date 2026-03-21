"""
SQLite-based cache with TTL for collector results.
Usage:
    cache = ReconCache()
    data = cache.get("github", "tesla.com")
    if data is None:
        data = collect()
        cache.set("github", "tesla.com", data, ttl=86400)
"""

import sqlite3
import json
import hashlib
import time
import os
from typing import Optional


DB_PATH = os.path.expanduser("~/.semantic_recon_cache.db")


class ReconCache:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )
            """)
            conn.commit()

    def _make_key(self, source: str, query: str) -> str:
        raw = f"{source}:{query}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, source: str, query: str) -> Optional[list]:
        key = self._make_key(source, query)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()

        if row is None:
            return None

        data, expires_at = row
        if time.time() > expires_at:
            self.delete(source, query)
            return None

        return json.loads(data)

    def set(self, source: str, query: str, data: list, ttl: int = 86400):
        key = self._make_key(source, query)
        expires_at = time.time() + ttl
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, data, expires_at) VALUES (?, ?, ?)",
                (key, json.dumps(data), expires_at)
            )
            conn.commit()

    def delete(self, source: str, query: str):
        key = self._make_key(source, query)
        with self._connect() as conn:
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            conn.commit()

    def clear_expired(self):
        with self._connect() as conn:
            conn.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
            conn.commit()

    def clear_all(self):
        with self._connect() as conn:
            conn.execute("DELETE FROM cache")
            conn.commit()

    def stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM cache WHERE expires_at < ?", (time.time(),)
            ).fetchone()[0]
        return {"total": total, "expired": expired, "valid": total - expired}
