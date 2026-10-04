from __future__ import annotations

import json
import logging
import uuid

from fastapi.testclient import TestClient

from cloudguard.logging_config import (
    CloudGuardJSONFormatter,
)
from cloudguard.main import app


client = TestClient(app)


def test_response_contains_request_id():
    response = client.get("/api/health")

    assert response.status_code == 200

    request_id = response.headers.get(
        "x-request-id"
    )

    assert request_id is not None

    parsed_id = uuid.UUID(request_id)

    assert str(parsed_id) == request_id


def test_request_ids_are_unique():
    first_response = client.get(
        "/api/health"
    )

    second_response = client.get(
        "/api/health"
    )

    first_id = first_response.headers[
        "x-request-id"
    ]

    second_id = second_response.headers[
        "x-request-id"
    ]

    assert first_id != second_id


def test_json_formatter_produces_structured_log():
    formatter = CloudGuardJSONFormatter()

    record = logging.LogRecord(
        name="cloudguard.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Request completed",
        args=(),
        exc_info=None,
    )

    record.event = (
        "http_request_completed"
    )
    record.method = "GET"
    record.path = "/api/health"
    record.status_code = 200
    record.duration_ms = 12.5
    record.request_id = (
        "test-request-id"
    )

    formatted = formatter.format(
        record
    )

    payload = json.loads(formatted)

    assert payload["level"] == "INFO"

    assert (
        payload["logger"]
        == "cloudguard.test"
    )

    assert (
        payload["message"]
        == "Request completed"
    )

    assert (
        payload["event"]
        == "http_request_completed"
    )

    assert payload["method"] == "GET"
    assert payload["path"] == "/api/health"
    assert payload["status_code"] == 200
    assert payload["duration_ms"] == 12.5

    assert (
        payload["request_id"]
        == "test-request-id"
    )

    assert "timestamp" in payload


def test_security_headers_and_request_id_coexist():
    response = client.get("/api/health")

    assert response.status_code == 200

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