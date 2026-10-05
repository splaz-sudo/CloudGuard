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

SCHEMA_VERSION = 2

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
    """
    CREATE TABLE IF NOT EXISTS scan_collector_results (
        scan_id TEXT NOT NULL REFERENCES scans(scan_id),
        collector TEXT NOT NULL,
        service TEXT NOT NULL,
        region TEXT,
        status TEXT NOT NULL,
        resources_discovered INTEGER NOT NULL DEFAULT 0,
        duration_ms REAL NOT NULL DEFAULT 0.0,
        error_category TEXT,
        error_message TEXT,
        coverage_limitation TEXT,
        PRIMARY KEY (scan_id, collector, service, region)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_collector_results_scan_id
    ON scan_collector_results(scan_id)
    """,
)


class QueryResult:
    """
    Cursor-compatible view of rows that were
    read while the connection lock was still
    held.

    Repository code uses this exactly like a
    sqlite3.Cursor: ``fetchone()``,
    ``fetchall()``, iteration and ``rowcount``.
    It holds plain Python values, so it stays
    valid no matter what other threads do to
    the shared connection afterwards.
    """

    __slots__ = ("_rows", "_rowcount", "_offset")

    def __init__(
        self,
        rows: list[sqlite3.Row],
        rowcount: int,
    ) -> None:
        self._rows = rows
        self._rowcount = rowcount
        self._offset = 0

    @property
    def rowcount(self) -> int:
        return self._rowcount

    def fetchone(self) -> sqlite3.Row | None:
        if self._offset >= len(self._rows):
            return None

        row = self._rows[self._offset]
        self._offset += 1
        return row

    def fetchall(self) -> list[sqlite3.Row]:
        rows = self._rows[self._offset:]
        self._offset = len(self._rows)
        return rows

    def __iter__(self):
        return iter(self.fetchall())


class Database:
    def __init__(
        self,
        path: str,
        *,
        wal_mode: bool = True,
        busy_timeout_ms: int = 5000,
        cache_size_kib: int = 8192,
    ) -> None:
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

        # Performance and reliability pragmas
        if wal_mode:
            self._connection.execute(
                "PRAGMA journal_mode = WAL"
            )
        if busy_timeout_ms:
            self._connection.execute(
                f"PRAGMA busy_timeout = {busy_timeout_ms}"
            )
        if cache_size_kib:
            self._connection.execute(
                f"PRAGMA cache_size = -{cache_size_kib}"
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

            if version < 2:
                for statement in (
                    SCHEMA_STATEMENTS[14:17]
                ):
                    self._connection.execute(
                        statement
                    )

                self._connection.execute(
                    "PRAGMA user_version = 2"
                )

            self._connection.commit()

    def execute(
        self,
        sql: str,
        parameters: tuple = (),
    ) -> QueryResult:
        """
        Run a statement and return its rows.

        The connection is shared by every worker
        thread, so the result set must be read
        *inside* the lock. A sqlite3.Cursor that
        is consumed after another thread has
        executed a statement on the same
        connection can report an empty row, a
        partially decoded row or raise an
        InterfaceError - which surfaced to the
        API as intermittent 404/500 responses
        for scans that demonstrably exist.

        Rows are therefore materialized here and
        handed back as a cursor-like object that
        no longer touches the connection.
        """
        with self._lock:
            cursor = self._connection.execute(
                sql,
                parameters,
            )

            rowcount = cursor.rowcount
            rows = (
                cursor.fetchall()
                if cursor.description is not None
                else []
            )

            self._connection.commit()

            return QueryResult(rows, rowcount)

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

    def integrity_check(self) -> bool:
        """
        Run SQLite integrity check.
        Returns True if database is consistent.
        """
        with self._lock:
            result = self._connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()
            return result[0] == "ok"

    def set_read_only(self, read_only: bool) -> None:
        """
        Set database to read-only mode.
        Useful for replicas or read-only access.
        """
        with self._lock:
            mode = "ON" if read_only else "OFF"
            self._connection.execute(
                f"PRAGMA read_only = {mode}"
            )

    def vacuum(self) -> None:
        """
        Rebuild database to reclaim space and defragment.
        """
        with self._lock:
            self._connection.execute("VACUUM")

    def backup_to(self, target_path: str) -> None:
        """
        Backup database to another file.
        Uses SQLite's online backup API.
        """
        import sqlite3
        target = sqlite3.connect(target_path)
        with self._lock:
            self._connection.backup(target)
        target.close()
