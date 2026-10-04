"""
Process-wide scan service access.

The service is created lazily so tests can
point CLOUDGUARD_DATABASE_PATH at a temporary
database before the app is imported.
"""

from __future__ import annotations

import threading

from cloudguard.config import (
    Settings,
    load_settings,
)
from cloudguard.persistence.database import (
    Database,
)
from cloudguard.persistence.repository import (
    ScanRepository,
)
from cloudguard.scans.service import ScanService

_lock = threading.Lock()
_service: ScanService | None = None


def get_scan_service() -> ScanService:
    global _service

    with _lock:
        if _service is None:
            settings = load_settings()

            database = Database(
                settings.database_path
            )

            _service = ScanService(
                ScanRepository(database),
                settings,
            )

        return _service


def get_settings() -> Settings:
    get_scan_service()

    return load_settings()


def reset_scan_service() -> None:
    """Test hook: drop the cached service."""

    global _service

    with _lock:
        _service = None
