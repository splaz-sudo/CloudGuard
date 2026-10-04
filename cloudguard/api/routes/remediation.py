from fastapi import APIRouter, HTTPException

from cloudguard.remediation.models import (
    Remediation,
    SimulationResult,
)
from cloudguard.remediation.service import (
    RemediationNotFoundError,
    RemediationService,
)
from cloudguard.services.analysis import (
    AnalysisService,
)


router = APIRouter(
    prefix="/api/remediations",
    tags=["Remediation"],
)

analysis_service = AnalysisService()

remediation_service = RemediationService()


@router.get("")
def get_remediations() -> list[Remediation]:
    """
    Returns structured remediation candidates
    generated from the current analysis.

    Recommendations are advisory only.
    CloudGuard does not modify cloud resources.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    return (
        remediation_service
        .get_remediations(result)
    )


@router.get("/prioritized")
def get_prioritized_remediations() -> (
    list[Remediation]
):
    """
    Returns remediations ranked by simulated
    impact: attack paths eliminated, then
    risk-score reduction.

    Each candidate is evaluated against an
    isolated simulation of the current
    environment. No cloud resources are
    modified.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    return (
        remediation_service
        .get_prioritized(result)
    )


@router.post("/{remediation_id}/simulate")
def simulate_remediation(
    remediation_id: str,
) -> SimulationResult:
    """
    Simulates a remediation against an isolated
    copy of the current security state and
    returns before/after risk analysis.

    This endpoint never modifies cloud
    resources.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    try:
        return remediation_service.simulate(
            result,
            remediation_id,
        )
    except RemediationNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=(
                "Unknown remediation: "
                f"{remediation_id}"
            ),
        ) from None
