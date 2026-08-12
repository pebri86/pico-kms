from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class Registry:
    def __init__(self, path: str = "data/kms.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS key_registry (
                    key_id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    object_id TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    key_parameters TEXT,
                    certificate_id TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """)

    def register_key(
        self,
        key_id: str,
        role: str,
        object_id: str,
        label: str,
        algorithm: str,
        key_parameters: str | None = None,
        certificate_id: str | None = None,
        status: str = "ACTIVE",
    ):
        if role not in ("CSCA", "DS", "CVCA"):
            raise ValueError("invalid role")

        if algorithm not in ("RSA", "EC"):
            raise ValueError("invalid algorithm")

        if status not in ("ACTIVE", "RETIRED"):
            raise ValueError("invalid status")

        if not key_id:
            raise ValueError("key_id is required")

        if not object_id:
            raise ValueError("object_id is required")

        if not label:
            raise ValueError("label is required")

        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            if conn.execute(
                "SELECT 1 FROM key_registry WHERE key_id = ?",
                (key_id,),
            ).fetchone():
                raise ValueError("key_id already registered")

            if conn.execute(
                "SELECT 1 FROM key_registry WHERE object_id = ?",
                (object_id,),
            ).fetchone():
                raise ValueError("object_id already registered")

            conn.execute(
                """
                INSERT INTO key_registry (
                    key_id,
                    role,
                    object_id,
                    label,
                    algorithm,
                    key_parameters,
                    certificate_id,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key_id,
                    role,
                    object_id,
                    label,
                    algorithm,
                    key_parameters,
                    certificate_id,
                    status,
                    now,
                    now,
                ),
            )

    def get_key_by_object_id(self, object_id: str):
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM key_registry
                WHERE object_id = ?
                """,
                (object_id,),
            ).fetchone()

        return dict(row) if row else None

    def get_key(self, key_id: str):
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM key_registry
                WHERE key_id = ?
                """,
                (key_id,),
            ).fetchone()

        return dict(row) if row else None

    def list_keys(self):
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT *
                FROM key_registry
                ORDER BY key_id
                """).fetchall()

        return [dict(row) for row in rows]

    def retire_key(self, key_id: str):
        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT status
                FROM key_registry
                WHERE key_id = ?
                """,
                (key_id,),
            ).fetchone()

            if row is None:
                raise KeyError(key_id)

            if row["status"] == "RETIRED":
                raise ValueError("key already retired")

            conn.execute(
                """
                UPDATE key_registry
                SET status = ?, updated_at = ?
                WHERE key_id = ?
                """,
                ("RETIRED", now, key_id),
            )

    def update_certificate(self, key_id: str, certificate_id: str):
        if not key_id:
            raise ValueError("key_id is required")

        if not certificate_id:
            raise ValueError("certificate_id is required")

        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT status
                FROM key_registry
                WHERE key_id = ?
                """,
                (key_id,),
            ).fetchone()

            if row is None:
                raise KeyError("key not registered")

            if row["status"] != "ACTIVE":
                raise ValueError(f"key is not active: {row['status']}")

            conn.execute(
                """
                UPDATE key_registry
                SET certificate_id = ?,
                    updated_at = ?
                WHERE key_id = ?
                """,
                (
                    certificate_id,
                    now,
                    key_id,
                ),
            )
