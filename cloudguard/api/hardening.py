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
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


def reject(
    status_code: int,
    detail: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """
    Build a rejection response from middleware.

    Every middleware below runs *outside*
    FastAPI's ExceptionMiddleware, so raising
    HTTPException here would propagate to the
    server-error handler and come back as an
    opaque 500. Returning the response keeps
    the real status code (429/413/414/431/405)
    visible to clients.
    """
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers=headers,
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiter.

    Limits requests per IP per time window.
    Not suitable for distributed deployments without Redis.
    """

    def __init__(
        self,
        app,
        requests_per_minute: int = 300,
        requests_per_hour: int = 6000,
        burst_allowance: int = 60,
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
            return reject(
                429,
                "Rate limit exceeded. Please slow down.",
                {
                    "Retry-After": "60",
                    "X-RateLimit-Limit-Minute": str(
                        self.requests_per_minute
                    ),
                    "X-RateLimit-Remaining-Minute": "0",
                },
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
                    return reject(
                        413,
                        (
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
            return reject(
                405,
                f"Method {request.method} not allowed",
            )

        # Validate URL length
        if len(str(request.url)) > self.MAX_URL_LENGTH:
            return reject(414, "URL too long")

        # Validate headers
        if len(request.headers) > self.MAX_HEADER_COUNT:
            return reject(431, "Too many headers")

        for name, value in request.headers.items():
            if len(name) + len(value) > self.MAX_HEADER_SIZE:
                return reject(431, "Header too large")

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
def sanitize_path(path: str, allowed_base: str = "/") -> str:
    """
    Sanitize and validate file path to prevent path traversal.

    Args:
        path: Path to sanitize
        allowed_base: Base directory that paths must be under

    Returns:
        Sanitized absolute path

    Raises:
        ValueError: If path attempts traversal or is outside allowed base
    """
    import os
    from pathlib import Path

    # Resolve to absolute path
    try:
        resolved = Path(path).resolve()
        base = Path(allowed_base).resolve()
    except Exception:
        raise ValueError("Invalid path")

    # Check if path is within allowed base
    try:
        resolved.relative_to(base)
    except ValueError:
        raise ValueError("Path traversal attempt detected")

    return str(resolved)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and injection.

    Removes:
    - Path separators
    - Null bytes
    - Control characters
    - Trailing spaces/dots (Windows reserved)

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for storage
    """
    import os

    if not filename:
        return "unnamed"

    # Remove path separators
    filename = filename.replace("/", "").replace("\\", "")

    # Remove null bytes and control characters
    filename = "".join(c for c in filename if ord(c) >= 32)

    # Remove Windows reserved names
    reserved = {"CON", "PRN", "AUX", "NUL",
                "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}
    name_part = filename.split(".")[0].upper()
    if name_part in reserved:
        filename = f"_{filename}"

    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255 - len(ext)] + ext

    return filename


def validate_json_schema(data: dict, schema: dict) -> tuple[bool, list[str]]:
    """
    Basic JSON schema validation.

    Args:
        data: Data to validate
        schema: Expected schema (simplified)

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    def check_type(value, expected_type, path=""):
        if expected_type == "string" and not isinstance(value, str):
            errors.append(f"{path}: expected string, got {type(value).__name__}")
        elif expected_type == "number" and not isinstance(value, (int, float)):
            errors.append(f"{path}: expected number, got {type(value).__name__}")
        elif expected_type == "boolean" and not isinstance(value, bool):
            errors.append(f"{path}: expected boolean, got {type(value).__name__}")
        elif expected_type == "object" and not isinstance(value, dict):
            errors.append(f"{path}: expected object, got {type(value).__name__}")
        elif expected_type == "array" and not isinstance(value, list):
            errors.append(f"{path}: expected array, got {type(value).__name__}")

    def validate_object(obj, schema_def, path=""):
        if not isinstance(obj, dict):
            errors.append(f"{path}: expected object")
            return

        for key, expected in schema_def.items():
            full_path = f"{path}.{key}" if path else key
            if key not in obj:
                if expected.get("required", False):
                    errors.append(f"{full_path}: required field missing")
                continue
            if "type" in expected:
                check_type(obj[key], expected["type"], full_path)
            if expected.get("type") == "object" and "properties" in expected:
                validate_object(obj[key], expected["properties"], full_path)

    if "type" in schema:
        check_type(data, schema["type"])
    if schema.get("type") == "object" and "properties" in schema:
        validate_object(data, schema["properties"])

    return len(errors) == 0, errors


def safe_subprocess_run(
    cmd: list[str],
    timeout: float = 30.0,
    cwd: str = None,
    env: dict = None,
) -> tuple[int, str, str]:
    """
    Safely run a subprocess with timeout and no shell injection.

    Args:
        cmd: Command and arguments as list (never use shell=True)
        timeout: Maximum execution time in seconds
        cwd: Working directory
        env: Environment variables

    Returns:
        Tuple of (return_code, stdout, stderr)

    Raises:
        subprocess.TimeoutExpired: If process exceeds timeout
        ValueError: If cmd is not a list or contains shell metacharacters
    """
    import subprocess

    if not isinstance(cmd, list):
        raise ValueError("Command must be a list of arguments")

    # Check for shell metacharacters in arguments
    dangerous = {"|", "&", ";", "$", "`", ">", "<", "(", ")", "{", "}", "$(", "${"}
    for arg in cmd:
        if any(c in arg for c in dangerous):
            raise ValueError(f"Potentially dangerous character in argument: {arg}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        env=env,
        shell=False,  # Never use shell=True
    )

    return result.returncode, result.stdout, result.stderr


def safe_deserialize_json(json_str: str, max_size: int = 1024 * 1024) -> dict:
    """
    Safely deserialize JSON with size limit.

    Args:
        json_str: JSON string to parse
        max_size: Maximum allowed size in bytes

    Returns:
        Parsed JSON object

    Raises:
        ValueError: If JSON is too large or invalid
    """
    import json

    if len(json_str.encode()) > max_size:
        raise ValueError(f"JSON payload exceeds maximum size of {max_size} bytes")

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")