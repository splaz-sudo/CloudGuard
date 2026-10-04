from fastapi import APIRouter, HTTPException

from cloudguard.api.presenters import (
    scan_http_error,
)
from cloudguard.remediation.models import (
    Remediation,
    SimulationResult,
)
from cloudguard.remediation.service import (
    RemediationNotFoundError,
    RemediationService,
)
from cloudguard.scans.runtime import (
    get_scan_service,
)


router = APIRouter(
    prefix="/api/remediations",
    tags=["Remediation"],
)

remediation_service = RemediationService()


def _latest_analysis():
    """
    Backwards-compatible source: the newest
    completed local-lab scan.
    """

    service = get_scan_service()

    snapshot = (
        service
        .get_or_create_latest_local_lab()
    )

    return (
        snapshot,
        service.analysis_result_for(
            snapshot
        ),
    )


@router.get("")
def get_remediations() -> list[Remediation]:
    """
    Returns structured remediation candidates
    from the latest completed scan.

    Recommendations are advisory only.
    CloudGuard does not modify cloud resources.
    """

    try:
        snapshot, _ = _latest_analysis()

        return snapshot.remediations
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/prioritized")
def get_prioritized_remediations() -> (
    list[Remediation]
):
    """
    Returns remediations ranked by simulated
    impact: attack paths eliminated, then
    risk-score reduction.
    """

    try:
        _, result = _latest_analysis()

        return (
            remediation_service
            .get_prioritized(result)
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.post("/{remediation_id}/simulate")
def simulate_remediation(
    remediation_id: str,
) -> SimulationResult:
    """
    Simulates a remediation against an
    isolated copy of the latest scan's
    security state. Never modifies cloud
    resources or stored scans.
    """

    try:
        _, result = _latest_analysis()

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
    except Exception as error:
        raise scan_http_error(
            error
        ) from error
