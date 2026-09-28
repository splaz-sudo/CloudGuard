from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import (
    BaseHTTPMiddleware,
)
from starlette.requests import Request
from starlette.responses import Response


logger = logging.getLogger(
    "cloudguard.api.requests"
)


class RequestLoggingMiddleware(
    BaseHTTPMiddleware
):
    """
    Adds a request identifier and records
    structured metadata for each HTTP request.

    Sensitive request bodies, authorization
    headers, cookies, and query values are not
    written to application logs.
    """

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:
        request_id = str(uuid.uuid4())

        request.state.request_id = (
            request_id
        )

        start_time = (
            time.perf_counter()
        )

        try:
            response = await call_next(
                request
            )
        except Exception:
            duration_ms = round(
                (
                    time.perf_counter()
                    - start_time
                )
                * 1000,
                2,
            )

            logger.exception(
                "Request failed",
                extra={
                    "event": (
                        "http_request_failed"
                    ),
                    "method": (
                        request.method
                    ),
                    "path": (
                        request.url.path
                    ),
                    "status_code": 500,
                    "duration_ms": (
                        duration_ms
                    ),
                    "request_id": (
                        request_id
                    ),
                },
            )

            raise

        duration_ms = round(
            (
                time.perf_counter()
                - start_time
            )
            * 1000,
            2,
        )

        response.headers[
            "X-Request-ID"
        ] = request_id

        logger.info(
            "Request completed",
            extra={
                "event": (
                    "http_request_completed"
                ),
                "method": request.method,
                "path": request.url.path,
                "status_code": (
                    response.status_code
                ),
                "duration_ms": duration_ms,
                "request_id": request_id,
            },
        )

        return response


class SecurityHeadersMiddleware(
    BaseHTTPMiddleware
):
    """
    Adds defensive HTTP security headers to
    CloudGuard API responses.
    """

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:
        response = await call_next(
            request
        )

        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"

        response.headers[
            "X-Frame-Options"
        ] = "DENY"

        response.headers[
            "Referrer-Policy"
        ] = "no-referrer"

        response.headers[
            "Permissions-Policy"
        ] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=()"
        )

        response.headers[
            "Content-Security-Policy"
        ] = (
            "default-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        return response