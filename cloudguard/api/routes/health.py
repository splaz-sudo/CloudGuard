from fastapi import APIRouter


router = APIRouter(
    prefix="/api",
    tags=["System"],
)


@router.get("/health")
def health_check() -> dict[str, str]:
    """
    Basic health endpoint used to verify that the
    CloudGuard API is running.
    """

    return {
        "status": "healthy",
        "service": "CloudGuard API",
        "version": "0.1.0",
    }
