"""
FlowGuard database migration script.

Run once to add the users, audit_log, and workflow_transitions tables.
Idempotent: safe to run multiple times.
Never deletes existing data.

Usage:
    .venv/bin/python migrate.py
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "flowguard.db"


def migrate() -> None:
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")

    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT  NOT NULL,
            role        TEXT    NOT NULL,
            region      TEXT    DEFAULT NULL,
            institution TEXT    DEFAULT NULL,
            is_active   INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL,
            last_login  TEXT    DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id        INTEGER DEFAULT NULL,
            actor_username  TEXT    DEFAULT NULL,
            event_type      TEXT    NOT NULL,
            entity_type     TEXT    DEFAULT NULL,
            entity_id       TEXT    DEFAULT NULL,
            outcome         TEXT    NOT NULL DEFAULT 'success',
            timestamp       TEXT    NOT NULL,
            metadata        TEXT    DEFAULT NULL,
            reason          TEXT    DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS workflow_transitions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id  TEXT NOT NULL,
            actor_id        INTEGER DEFAULT NULL,
            actor_username  TEXT NOT NULL,
            action          TEXT NOT NULL,
            from_stage      TEXT NOT NULL,
            to_stage        TEXT NOT NULL,
            from_status     TEXT NOT NULL,
            to_status       TEXT NOT NULL,
            reason          TEXT DEFAULT NULL,
            created_at      TEXT NOT NULL
        );
    """)

    db.commit()
    db.close()
    print("Migration complete.")
    print("Run `.venv/bin/python manage.py create-admin` to create the first administrator.")


if __name__ == "__main__":
    migrate()
