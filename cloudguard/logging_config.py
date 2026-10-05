from __future__ import annotations

import json
import logging
import sys
import threading
import time
import traceback
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Optional
from functools import wraps
from dataclasses import dataclass, field
from collections import defaultdict


# Context variables for request correlation
scan_id_var: ContextVar[Optional[str]] = ContextVar("scan_id", default=None)
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
account_id_var: ContextVar[Optional[str]] = ContextVar("account_id", default=None)
region_var: ContextVar[Optional[str]] = ContextVar("region", default=None)
collector_var: ContextVar[Optional[str]] = ContextVar("collector", default=None)


@dataclass
class MetricPoint:
    """A single metric data point."""
    name: str
    value: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    labels: dict[str, str] = field(default_factory=dict)
    metric_type: str = "gauge"  # gauge, counter, histogram


class MetricsCollector:
    """
    Lightweight in-memory metrics collector.

    Supports counters, gauges, and histograms.
    Not a replacement for Prometheus but useful for
    local observability without external dependencies.
    """

    def __init__(self):
        self._counters: dict[str, float] = defaultdict(float)
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def increment(self, name: str, value: float = 1.0, labels: dict[str, str] = None):
        """Increment a counter."""
        key = self._make_key(name, labels)
        with self._lock:
            self._counters[key] += value

    def set_gauge(self, name: str, value: float, labels: dict[str, str] = None):
        """Set a gauge value."""
        key = self._make_key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def observe(self, name: str, value: float, labels: dict[str, str] = None):
        """Record a histogram observation."""
        key = self._make_key(name, labels)
        with self._lock:
            self._histograms[key].append(value)

    def get_metrics(self) -> dict:
        """Get all current metrics."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {
                    k: {"count": len(v), "sum": sum(v), "avg": sum(v) / len(v) if v else 0}
                    for k, v in self._histograms.items()
                },
            }

    def _make_key(self, name: str, labels: dict[str, str] = None) -> str:
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"


# Global metrics collector instance
metrics = MetricsCollector()


def record_metric(
    name: str,
    value: float,
    metric_type: str = "gauge",
    labels: dict[str, str] = None,
):
    """Convenience function to record a metric."""
    if metric_type == "counter":
        metrics.increment(name, value, labels)
    elif metric_type == "gauge":
        metrics.set_gauge(name, value, labels)
    elif metric_type == "histogram":
        metrics.observe(name, value, labels)


def get_scan_context() -> dict[str, Optional[str]]:
    """Get current scan context for log correlation."""
    return {
        "scan_id": scan_id_var.get(),
        "request_id": request_id_var.get(),
        "account_id": account_id_var.get(),
        "region": region_var.get(),
        "collector": collector_var.get(),
    }


def set_scan_context(
    scan_id: str = None,
    request_id: str = None,
    account_id: str = None,
    region: str = None,
    collector: str = None,
):
    """Set scan context variables."""
    if scan_id:
        scan_id_var.set(scan_id)
    if request_id:
        request_id_var.set(request_id)
    if account_id:
        account_id_var.set(account_id)
    if region:
        region_var.set(region)
    if collector:
        collector_var.set(collector)


def clear_scan_context():
    """Clear all scan context variables."""
    scan_id_var.set(None)
    request_id_var.set(None)
    account_id_var.set(None)
    region_var.set(None)
    collector_var.set(None)


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
        # Get scan context for correlation
        context = get_scan_context()

        log_entry: dict[str, Any] = {
            "timestamp": (
                datetime.now(timezone.utc)
                .isoformat()
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add context fields if present
        if context["scan_id"]:
            log_entry["scan_id"] = context["scan_id"]
        if context["request_id"]:
            log_entry["request_id"] = context["request_id"]
        if context["account_id"]:
            log_entry["account_id"] = context["account_id"]
        if context["region"]:
            log_entry["region"] = context["region"]
        if context["collector"]:
            log_entry["collector"] = context["collector"]

        # Add standard request fields
        if hasattr(record, "event"):
            log_entry["event"] = record.event

        if hasattr(record, "method"):
            log_entry["method"] = record.method

        if hasattr(record, "path"):
            log_entry["path"] = record.path

        if hasattr(record, "status_code"):
            log_entry["status_code"] = record.status_code

        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = record.duration_ms

        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id

        # Add performance metrics
        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = record.duration_ms

        # Add resource info
        if hasattr(record, "asset_count"):
            log_entry["asset_count"] = record.asset_count
        if hasattr(record, "finding_count"):
            log_entry["finding_count"] = record.finding_count
        if hasattr(record, "attack_path_count"):
            log_entry["attack_path_count"] = record.attack_path_count
        if hasattr(record, "highest_risk"):
            log_entry["highest_risk"] = record.highest_risk

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

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


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with CloudGuard configuration."""
    logger = logging.getLogger(f"cloudguard.{name}")
    return logger


# Decorator for automatic metric recording
def record_duration(metric_name: str, labels: dict[str, str] = None):
    """Decorator to record function execution duration."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start
                record_metric(
                    f"{metric_name}.duration",
                    duration,
                    "histogram",
                    labels,
                )
                return result
            except Exception as e:
                duration = time.time() - start
                record_metric(
                    f"{metric_name}.duration",
                    duration,
                    "histogram",
                    {**(labels or {}), "error": "true"},
                )
                raise
        return wrapper
    return decorator


# Context manager for scan operations
class ScanContext:
    """Context manager for scan operations with automatic metrics."""

    def __init__(self, scan_id: str, account_id: str = None, region: str = None):
        self.scan_id = scan_id
        self.account_id = account_id
        self.region = region
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        set_scan_context(
            scan_id=self.scan_id,
            account_id=self.account_id,
            region=self.region,
        )
        record_metric("scan.started", 1, "counter", {"scan_id": self.scan_id})
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        record_metric(
            "scan.duration",
            duration,
            "histogram",
            {"scan_id": self.scan_id},
        )
        if exc_type:
            record_metric(
                "scan.failed", 1, "counter", {"scan_id": self.scan_id}
            )
        else:
            record_metric(
                "scan.completed", 1, "counter", {"scan_id": self.scan_id}
            )
        clear_scan_context()
        return False