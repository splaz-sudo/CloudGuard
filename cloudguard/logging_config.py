from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class CloudGuardJSONFormatter(
    logging.Formatter
):
    """
    Formats CloudGuard application logs as
    structured JSON.

    Structured logs are easier to search, parse,
    correlate, and later forward into a SIEM or
    observability platform.
    """

    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": (
                datetime.now(timezone.utc)
                .isoformat()
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if hasattr(record, "event"):
            log_entry["event"] = record.event

        if hasattr(record, "method"):
            log_entry["method"] = record.method

        if hasattr(record, "path"):
            log_entry["path"] = record.path

        if hasattr(record, "status_code"):
            log_entry["status_code"] = (
                record.status_code
            )

        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = (
                record.duration_ms
            )

        if hasattr(record, "request_id"):
            log_entry["request_id"] = (
                record.request_id
            )

        if record.exc_info:
            log_entry["exception"] = (
                self.formatException(
                    record.exc_info
                )
            )

        return json.dumps(
            log_entry,
            ensure_ascii=False,
            default=str,
        )


def configure_logging(
    level: int = logging.INFO,
) -> None:
    """
    Configure CloudGuard application logging.

    The function is safe to call multiple times
    without adding duplicate handlers.
    """

    logger = logging.getLogger(
        "cloudguard"
    )

    logger.setLevel(level)
    logger.propagate = False

    if any(
        getattr(
            handler,
            "_cloudguard_handler",
            False,
        )
        for handler in logger.handlers
    ):
        return

    handler = logging.StreamHandler(
        sys.stdout
    )

    handler.setLevel(level)

    handler.setFormatter(
        CloudGuardJSONFormatter()
    )

    handler._cloudguard_handler = True

    logger.addHandler(handler)