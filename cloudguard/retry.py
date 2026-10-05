"""
Retry utilities with bounded exponential backoff and jitter.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

from cloudguard.aws_errors import is_retryable_error

T = TypeVar("T")


@dataclass(frozen=True)
class RetryConfig:
    max_attempts: int = 3
    base_delay_ms: float = 250.0
    max_delay_ms: float = 5000.0
    exponential_base: float = 2.0
    jitter_factor: float = 0.25

    @classmethod
    def fast(cls) -> "RetryConfig":
        return cls(
            max_attempts=2,
            base_delay_ms=100.0,
            max_delay_ms=1000.0,
        )

    @classmethod
    def standard(cls) -> "RetryConfig":
        return cls()

    @classmethod
    def aggressive(cls) -> "RetryConfig":
        return cls(
            max_attempts=5,
            base_delay_ms=500.0,
            max_delay_ms=15000.0,
        )


def calculate_delay(
    attempt: int,
    config: RetryConfig,
) -> float:
    """
    Calculate delay with exponential backoff and jitter.

    Formula: min(base * exponential_base^attempt, max_delay) * (1 +- jitter)
    """
    delay = min(
        config.base_delay_ms
        * (config.exponential_base ** attempt),
        config.max_delay_ms,
    )

    jitter = delay * config.jitter_factor * (
        2 * random.random() - 1
    )

    return max(0, delay + jitter)


def retry_with_backoff(
    func: Callable[[], T],
    config: RetryConfig | None = None,
    should_retry: Callable[[Exception], bool] | None = None,
) -> T:
    """
    Execute a function with retry logic.

    Retries on retryable errors using bounded exponential backoff
    with jitter. Does not retry on authentication/authorization
    failures or validation errors.
    """
    if config is None:
        config = RetryConfig.standard()

    if should_retry is None:
        should_retry = is_retryable_error

    last_exception: Exception | None = None

    for attempt in range(config.max_attempts):
        try:
            return func()
        except Exception as error:
            last_exception = error

            if not should_retry(error):
                raise

            if attempt < config.max_attempts - 1:
                delay_ms = calculate_delay(attempt, config)
                time.sleep(delay_ms / 1000.0)
                continue

            raise

    assert last_exception is not None
    raise last_exception


def retry_with_backoff_async(
    func: Callable[[], T],
    config: RetryConfig | None = None,
    should_retry: Callable[[Exception], bool] | None = None,
) -> T:
    """
    Synchronous version for compatibility.
    """
    return retry_with_backoff(func, config, should_retry)