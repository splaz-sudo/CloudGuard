from fastapi import FastAPI
from fastapi.testclient import TestClient

from cloudguard.api.errors import (
    unhandled_exception_handler,
)


def create_test_app() -> FastAPI:
    app = FastAPI()

    app.add_exception_handler(
        Exception,
        unhandled_exception_handler,
    )

    @app.get("/explode")
    async def explode():
        raise RuntimeError(
            "SECRET_INTERNAL_EXCEPTION"
        )

    return app


def test_unhandled_exception_returns_safe_response():
    app = create_test_app()

    client = TestClient(
        app,
        raise_server_exceptions=False,
    )

    response = client.get("/explode")

    assert response.status_code == 500

    assert response.json() == {
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": (
                "CloudGuard encountered an "
                "unexpected internal error."
            ),
        }
    }


def test_unhandled_exception_does_not_leak_details():
    app = create_test_app()

    client = TestClient(
        app,
        raise_server_exceptions=False,
    )

    response = client.get("/explode")

    body = response.text

    assert "SECRET_INTERNAL_EXCEPTION" not in body
    assert "RuntimeError" not in body
    assert "Traceback" not in body