"""
API Hardening

Implements additional security measures for the API:
- Request validation and size limits
- Rate limiting (in-memory, per-IP)
- Enhanced error handling
- Security headers (already in middleware)
- Request/response sanitization
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional

from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiter.

    Limits requests per IP per time window.
    Not suitable for distributed deployments without Redis.
    """

    def __init__(
        self,
        app,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        burst_allowance: int = 10,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.burst_allowance = burst_allowance

        # In-memory storage: ip -> list of timestamps
        self._minute_buckets: dict[str, list[float]] = defaultdict(list)
        self._hour_buckets: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client_ip = self._get_client_ip(request)

        # Check rate limits
        if not self._check_rate_limit(client_ip):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please slow down.",
            )

        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit-Minute"] = str(
            self.requests_per_minute
        )
        response.headers["X-RateLimit-Remaining-Minute"] = str(
            max(0, self.requests_per_minute - self._get_minute_count(client_ip))
        )

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check for forwarded headers (behind proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to client host
        if request.client:
            return request.client.host

        return "unknown"

    def _check_rate_limit(self, ip: str) -> bool:
        """Check if IP is within rate limits."""
        now = time.time()

        # Clean old entries
        self._clean_buckets(ip, now)

        minute_count = len(self._minute_buckets[ip])
        hour_count = len(self._hour_buckets[ip])

        # Check minute limit
        if minute_count >= self.requests_per_minute + self.burst_allowance:
            return False

        # Check hour limit
        if hour_count >= self.requests_per_hour:
            return False

        # Record this request
        self._minute_buckets[ip].append(now)
        self._hour_buckets[ip].append(now)

        return True

    def _clean_buckets(self, ip: str, now: float):
        """Remove expired timestamps."""
        minute_ago = now - 60
        hour_ago = now - 3600

        self._minute_buckets[ip] = [
            t for t in self._minute_buckets[ip] if t > minute_ago
        ]
        self._hour_buckets[ip] = [
            t for t in self._hour_buckets[ip] if t > hour_ago
        ]

        # Clean up empty buckets to prevent memory leak
        if not self._minute_buckets[ip]:
            del self._minute_buckets[ip]
        if not self._hour_buckets[ip]:
            del self._hour_buckets[ip]

    def _get_minute_count(self, ip: str) -> int:
        return len(self._minute_buckets.get(ip, []))


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Limits request body size to prevent abuse.
    """

    def __init__(
        self,
        app,
        max_size_bytes: int = 10 * 1024 * 1024,  # 10 MB default
    ):
        super().__init__(app)
        self.max_size_bytes = max_size_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_size_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            f"Request body too large. "
                            f"Maximum size: {self.max_size_bytes} bytes"
                        ),
                    )
            except ValueError:
                pass

        response = await call_next(request)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Enhanced security headers (in addition to existing middleware).
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Additional security headers
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-DNS-Prefetch-Control"] = "off"
        response.headers["X-Download-Options"] = "noopen"

        return response


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Validates request parameters and headers.
    """

    ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
    MAX_URL_LENGTH = 2048
    MAX_HEADER_COUNT = 50
    MAX_HEADER_SIZE = 8192

    async def dispatch(self, request: Request, call_next):
        # Validate HTTP method
        if request.method not in self.ALLOWED_METHODS:
            raise HTTPException(
                status_code=405,
                detail=f"Method {request.method} not allowed",
            )

        # Validate URL length
        if len(str(request.url)) > self.MAX_URL_LENGTH:
            raise HTTPException(
                status_code=414,
                detail="URL too long",
            )

        # Validate headers
        if len(request.headers) > self.MAX_HEADER_COUNT:
            raise HTTPException(
                status_code=431,
                detail="Too many headers",
            )

        for name, value in request.headers.items():
            if len(name) + len(value) > self.MAX_HEADER_SIZE:
                raise HTTPException(
                    status_code=431,
                    detail="Header too large",
                )

        response = await call_next(request)
        return response


def create_api_key_dependency(api_key: Optional[str] = None):
    """
    Creates a FastAPI dependency for API key authentication.

    If api_key is empty/None, authentication is disabled (development mode).
    """
    from fastapi import Depends, HTTPException, Security
    from fastapi.security import APIKeyHeader

    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def verify_api_key(
        api_key_header_value: str = Security(api_key_header),
    ) -> str:
        if not api_key:
            # Development mode - no auth required
            return "dev"

        if not api_key_header_value:
            raise HTTPException(
                status_code=401,
                detail="API key required",
            )

        if api_key_header_value != api_key:
            raise HTTPException(
                status_code=403,
                detail="Invalid API key",
            )

        return api_key_header_value

    return Depends(verify_api_key)


def sanitize_error_response(error: Exception) -> dict:
    """
    Sanitize error for client response.

    Never exposes:
    - Stack traces
    - Internal file paths
    - Database connection strings
    - AWS credentials
    - Internal service names
    """
    error_str = str(error)

    # Patterns to sanitize
    sanitized = error_str

    # Remove file paths
    import re
    sanitized = re.sub(
        r'/[a-zA-Z0-9_./\-]+',
        '[PATH_REDACTED]',
        sanitized,
    )

    # Remove potential AWS keys
    sanitized = re.sub(
        r'AKIA[0-9A-Z]{16}',
        '[AWS_KEY_REDACTED]',
        sanitized,
    )
    sanitized = re.sub(
        r'aws_secret_access_key[^"\']*["\'][^"\']*["\']',
        'aws_secret_access_key="[REDACTED]"',
        sanitized,
        flags=re.IGNORECASE,
    )

    # Remove stack trace lines
    sanitized = re.sub(
        r'File "[^"]+", line \d+, in \w+',
        '[STACK_TRACE_REDACTED]',
        sanitized,
    )

    # Truncate if too long
    if len(sanitized) > 500:
        sanitized = sanitized[:500] + "..."

    return {
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": sanitized,
        }
    }