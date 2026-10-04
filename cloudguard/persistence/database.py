"""
SQLite storage for CloudGuard scan snapshots.

One shared connection guarded by a lock keeps
usage safe with the scan worker thread while
supporting in-memory databases for tests.

Schema versioning uses PRAGMA user_version;
migrations are applied in order at startup.
The repository layer isolates SQL so another
database backend could replace it without
touching business logic.
"""

from __future__ import annotations

import sqlite3
import threading

SCHEMA_VERSION = 1

SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        environment TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        account_identifier TEXT,
        regions_json TEXT NOT NULL DEFAULT '[]',
        asset_count INTEGER NOT NULL DEFAULT 0,
        relationship_count INTEGER NOT NULL DEFAULT 0,
        finding_count INTEGER NOT NULL DEFAULT 0,
        attack_path_count INTEGER NOT NULL DEFAULT 0,
        highest_risk INTEGER NOT NULL DEFAULT 0,
        failed_collectors_json TEXT NOT NULL DEFAULT '[]',
        error_message TEXT,
        scanner_version TEXT NOT NULL DEFAULT '',
        duration_ms REAL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_scans_created_at
    ON scans(created_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_scans_status
    ON scans(status)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_scans_account
    ON scans(account_identifier)
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_assets (
        scan_id TEXT NOT NULL REFERENCES scans(scan_id),
        asset_id TEXT NOT NULL,
        asset_type TEXT NOT NULL,
        name TEXT NOT NULL,
        sensitive INTEGER NOT NULL,
        internet_exposed INTEGER NOT NULL,
        region TEXT,
        data_json TEXT NOT NULL,
        PRIMARY KEY (scan_id, asset_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_relationships (
        scan_id TEXT NOT NULL REFERENCES scans(scan_id),
        relationship_id TEXT NOT NULL,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        relationship_type TEXT NOT NULL,
        data_json TEXT NOT NULL,
        PRIMARY KEY (scan_id, relationship_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_findings (
        scan_id TEXT NOT NULL REFERENCES scans(scan_id),
        finding_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        data_json TEXT NOT NULL,
        PRIMARY KEY (scan_id, finding_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_findings_fingerprint
    ON scan_findings(fingerprint)
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_attack_paths (
        scan_id TEXT NOT NULL REFERENCES scans(scan_id),
        path_id TEXT NOT NULL,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        data_json TEXT NOT NULL,
        PRIMARY KEY (scan_id, path_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_paths_path_id
    ON scan_attack_paths(path_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_remediations (
        scan_id TEXT NOT NULL REFERENCES scans(scan_id),
        remediation_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        data_json TEXT NOT NULL,
        PRIMARY KEY (scan_id, remediation_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_environments (
        scan_id TEXT PRIMARY KEY
            REFERENCES scans(scan_id),
        data_json TEXT NOT NULL
    )
    """,
)


class Database:
    def __init__(self, path: str) -> None:
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(
            path,
            check_same_thread=False,
        )
        self._connection.row_factory = (
            sqlite3.Row
        )
        self._connection.execute(
            "PRAGMA foreign_keys = ON"
        )
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            version = self._connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]

            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    "CloudGuard database schema "
                    f"version {version} is newer "
                    "than this CloudGuard "
                    "version supports "
                    f"({SCHEMA_VERSION})."
                )

            if version < 1:
                for statement in (
                    SCHEMA_STATEMENTS
                ):
                    self._connection.execute(
                        statement
                    )

                self._connection.execute(
                    "PRAGMA user_version = 1"
                )

            self._connection.commit()

    def execute(
        self,
        sql: str,
        parameters: tuple = (),
    ) -> sqlite3.Cursor:
        with self._lock:
            cursor = self._connection.execute(
                sql,
                parameters,
            )
            self._connection.commit()
            return cursor

    def executemany(
        self,
        sql: str,
        rows: list[tuple],
    ) -> None:
        with self._lock:
            self._connection.executemany(
                sql,
                rows,
            )
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()
