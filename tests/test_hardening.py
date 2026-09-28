from __future__ import annotations

import json
import uuid

from fastapi.testclient import TestClient

from cloudguard.main import app


client = TestClient(
    app,
    raise_server_exceptions=False,
)


def test_health_endpoint_has_security_headers():
    response = client.get("/api/health")

    assert response.status_code == 200

    assert (
        response.headers["x-content-type-options"]
        == "nosniff"
    )

    assert (
        response.headers["x-frame-options"]
        == "DENY"
    )

    assert (
        response.headers["referrer-policy"]
        == "no-referrer"
    )

    assert (
        response.headers["permissions-policy"]
        == (
            "camera=(), microphone=(), "
            "geolocation=()"
        )
    )

    assert (
        "frame-ancestors 'none'"
        in response.headers[
            "content-security-policy"
        ]
    )


def test_request_id_is_valid_uuid():
    response = client.get("/api/health")

    assert response.status_code == 200

    request_id = response.headers.get(
        "x-request-id"
    )

    assert request_id is not None

    parsed = uuid.UUID(request_id)

    assert str(parsed) == request_id


def test_request_id_changes_per_request():
    first = client.get("/api/health")
    second = client.get("/api/health")

    assert (
        first.headers["x-request-id"]
        != second.headers["x-request-id"]
    )


def test_unknown_api_route_returns_404():
    response = client.get(
        "/api/route-that-does-not-exist"
    )

    assert response.status_code == 404

    assert (
        response.headers.get(
            "x-request-id"
        )
        is not None
    )

    assert (
        response.headers[
            "x-content-type-options"
        ]
        == "nosniff"
    )


def test_api_does_not_expose_server_exception_details():
    from fastapi import FastAPI

    from cloudguard.api.errors import (
        unhandled_exception_handler,
    )
    from cloudguard.api.middleware import (
        RequestLoggingMiddleware,
        SecurityHeadersMiddleware,
    )

    test_app = FastAPI()

    test_app.add_exception_handler(
        Exception,
        unhandled_exception_handler,
    )

    test_app.add_middleware(
        SecurityHeadersMiddleware
    )

    test_app.add_middleware(
        RequestLoggingMiddleware
    )

    @test_app.get("/failure")
    async def failure():
        raise RuntimeError(
            "TOP_SECRET_INTERNAL_VALUE"
        )

    failure_client = TestClient(
        test_app,
        raise_server_exceptions=False,
    )

    response = failure_client.get(
        "/failure"
    )

    assert response.status_code == 500

    body = response.text

    assert (
        "TOP_SECRET_INTERNAL_VALUE"
        not in body
    )

    assert "RuntimeError" not in body
    assert "Traceback" not in body

    payload = response.json()

    assert payload == {
        "error": {
            "code": (
                "INTERNAL_SERVER_ERROR"
            ),
            "message": (
                "CloudGuard encountered an "
                "unexpected internal error."
            ),
        }
    }


def test_error_response_is_valid_json():
    from fastapi import FastAPI

    from cloudguard.api.errors import (
        unhandled_exception_handler,
    )

    test_app = FastAPI()

    test_app.add_exception_handler(
        Exception,
        unhandled_exception_handler,
    )

    @test_app.get("/failure")
    async def failure():
        raise ValueError(
            "internal implementation detail"
        )

    failure_client = TestClient(
        test_app,
        raise_server_exceptions=False,
    )

    response = failure_client.get(
        "/failure"
    )

    payload = json.loads(
        response.text
    )

    assert (
        payload["error"]["code"]
        == "INTERNAL_SERVER_ERROR"
    )


def test_pdf_endpoint_keeps_security_headers():
    response = client.get(
        "/api/report/pdf"
    )

    assert response.status_code == 200

    assert (
        response.headers["content-type"]
        == "application/pdf"
    )

    assert (
        response.headers[
            "x-content-type-options"
        ]
        == "nosniff"
    )

    assert (
        response.headers[
            "x-frame-options"
        ]
        == "DENY"
    )

    assert (
        response.headers.get(
            "x-request-id"
        )
        is not None
    )


def test_sensitive_headers_are_not_reflected():
    secret = (
        "Bearer CLOUDGUARD_TEST_SECRET"
    )

    response = client.get(
        "/api/health",
        headers={
            "Authorization": secret,
        },
    )

    assert response.status_code == 200

    assert secret not in response.text

    for value in response.headers.values():
        assert secret not in value