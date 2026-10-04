from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from cloudguard.api.errors import (
    unhandled_exception_handler,
)
from cloudguard.api.middleware import (
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)
from cloudguard.api.routes.health import (
    router as health_router,
)
from cloudguard.api.routes.remediation import (
    router as remediation_router,
)
from cloudguard.api.routes.scans import (
    router as scans_router,
)
from cloudguard.api.routes.security import (
    router as security_router,
)
from cloudguard.logging_config import (
    configure_logging,
)


configure_logging()


app = FastAPI(
    title="CloudGuard",
    description=(
        "Cloud security intelligence platform for "
        "asset discovery, security analysis, "
        "attack-path detection, and risk correlation."
    ),
    version="0.1.0",
)


app.add_exception_handler(
    Exception,
    unhandled_exception_handler,
)


app.add_middleware(
    SecurityHeadersMiddleware
)

app.add_middleware(
    RequestLoggingMiddleware
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    health_router
)

app.include_router(
    security_router
)

app.include_router(
    remediation_router
)

app.include_router(
    scans_router
)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "CloudGuard",
        "status": "running",
        "docs": "/docs",
    }