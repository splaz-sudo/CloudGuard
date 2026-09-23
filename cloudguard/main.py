from fastapi import FastAPI

from cloudguard.api.routes.health import (
    router as health_router,
)
from cloudguard.api.routes.security import (
    router as security_router,
)


app = FastAPI(
    title="CloudGuard",
    description=(
        "Cloud security intelligence platform for "
        "asset discovery, security analysis, "
        "attack-path detection, and risk correlation."
    ),
    version="0.1.0",
)


app.include_router(
    health_router
)

app.include_router(
    security_router
)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "CloudGuard",
        "status": "running",
        "docs": "/docs",
    }