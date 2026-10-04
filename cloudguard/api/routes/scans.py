from fastapi import APIRouter

from cloudguard.api.presenters import (
    overview_payload,
    scan_http_error,
)
from cloudguard.findings.models import Finding
from cloudguard.graph.attack_paths import (
    AttackPath,
)
from cloudguard.models.assets import CloudAsset
from cloudguard.models.relationships import (
    Relationship,
)
from cloudguard.remediation.models import (
    Remediation,
    SimulationResult,
)
from cloudguard.remediation.service import (
    RemediationService,
)
from cloudguard.scans.models import (
    ScanCreateRequest,
    ScanRecord,
)
from cloudguard.scans.runtime import (
    get_scan_service,
)
from cloudguard.scans.service import (
    ScanNotFoundError,
)
from cloudguard.services.compliance_analysis import (  # noqa: E501
    ComplianceAnalysisService,
)
from cloudguard.services.identity_analysis import (  # noqa: E501
    IdentityAnalysisService,
)
from cloudguard.services.network_analysis import (  # noqa: E501
    NetworkAnalysisService,
)


router = APIRouter(
    prefix="/api/scans",
    tags=["Scans"],
)

remediation_service = RemediationService()

identity_analysis_service = (
    IdentityAnalysisService()
)

network_analysis_service = (
    NetworkAnalysisService()
)

compliance_analysis_service = (
    ComplianceAnalysisService()
)


@router.post("")
def create_scan(
    request: ScanCreateRequest,
) -> ScanRecord:
    """
    Starts a new scan. By default the request
    waits for completion; pass wait=false for
    asynchronous execution and poll
    GET /api/scans/{scan_id}.
    """

    try:
        return get_scan_service().create_scan(
            source=request.source,
            environment=request.environment,
            regions=request.regions,
            wait=request.wait,
        )
    except Exception as error:
        raise scan_http_error(error) from error


@router.get("")
def list_scans(
    limit: int = 50,
) -> list[ScanRecord]:
    return get_scan_service().list_scans(
        limit
    )


@router.get("/{scan_id}")
def get_scan(scan_id: str) -> ScanRecord:
    try:
        return get_scan_service().get_scan(
            scan_id
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.post("/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
) -> ScanRecord:
    try:
        return (
            get_scan_service().cancel_scan(
                scan_id
            )
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/{scan_id}/overview")
def get_scan_overview(
    scan_id: str,
) -> dict:
    try:
        snapshot = (
            get_scan_service().get_snapshot(
                scan_id
            )
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    return overview_payload(snapshot)


@router.get("/{scan_id}/assets")
def get_scan_assets(
    scan_id: str,
) -> list[CloudAsset]:
    try:
        return (
            get_scan_service()
            .get_snapshot(scan_id)
            .assets
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/{scan_id}/relationships")
def get_scan_relationships(
    scan_id: str,
) -> list[Relationship]:
    try:
        return (
            get_scan_service()
            .get_snapshot(scan_id)
            .relationships
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/{scan_id}/findings")
def get_scan_findings(
    scan_id: str,
) -> list[Finding]:
    try:
        return (
            get_scan_service()
            .get_snapshot(scan_id)
            .findings
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/{scan_id}/attack-paths")
def get_scan_attack_paths(
    scan_id: str,
) -> list[AttackPath]:
    try:
        return (
            get_scan_service()
            .get_snapshot(scan_id)
            .attack_paths
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/{scan_id}/remediations")
def get_scan_remediations(
    scan_id: str,
) -> list[Remediation]:
    try:
        return (
            get_scan_service()
            .get_snapshot(scan_id)
            .remediations
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get(
    "/{scan_id}/remediations/prioritized"
)
def get_scan_prioritized_remediations(
    scan_id: str,
) -> list[Remediation]:
    """
    Ranks the scan's remediations by simulated
    impact against the stored scan graph. The
    stored scan is never modified.
    """

    try:
        service = get_scan_service()

        snapshot = service.get_snapshot(
            scan_id
        )

        result = service.analysis_result_for(
            snapshot
        )

        return (
            remediation_service
            .get_prioritized(result)
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.post(
    "/{scan_id}/remediations/"
    "{remediation_id}/simulate"
)
def simulate_scan_remediation(
    scan_id: str,
    remediation_id: str,
) -> SimulationResult:
    """
    Simulates a remediation against an
    isolated copy of this scan's graph. The
    persisted scan is never modified.
    """

    try:
        service = get_scan_service()

        snapshot = service.get_snapshot(
            scan_id
        )

        for remediation in (
            snapshot.remediations
        ):
            if (
                remediation.remediation_id
                == remediation_id
            ):
                return (
                    remediation_service
                    .simulator.simulate(
                        service
                        .analysis_result_for(
                            snapshot
                        ),
                        remediation,
                    )
                )

        raise ScanNotFoundError(
            "Unknown remediation for scan "
            f"{scan_id}: {remediation_id}"
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/{scan_id}/identity-risks")
def get_scan_identity_risks(
    scan_id: str,
) -> list[dict]:
    try:
        service = get_scan_service()

        snapshot = service.get_snapshot(
            scan_id
        )

        identities = (
            identity_analysis_service
            .analyze(
                service.analysis_result_for(
                    snapshot
                )
            )
        )

        return [
            identity.to_dict()
            for identity in identities
        ]
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/{scan_id}/network-risks")
def get_scan_network_risks(
    scan_id: str,
) -> list[dict]:
    try:
        service = get_scan_service()

        snapshot = service.get_snapshot(
            scan_id
        )

        environment = snapshot.environment

        if environment is None:
            raise ScanNotFoundError(
                "Scan environment data is "
                f"missing for {scan_id}."
            )

        risks = (
            network_analysis_service.analyze(
                analysis_result=(
                    service
                    .analysis_result_for(
                        snapshot
                    )
                ),
                instances=(
                    environment.instances
                ),
                security_groups=(
                    environment
                    .security_groups
                ),
            )
        )

        return [
            risk.to_dict()
            for risk in risks
        ]
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/{scan_id}/compliance")
def get_scan_compliance(
    scan_id: str,
) -> dict:
    try:
        service = get_scan_service()

        snapshot = service.get_snapshot(
            scan_id
        )

        report = (
            compliance_analysis_service
            .analyze(
                service.analysis_result_for(
                    snapshot
                )
            )
        )

        return report.model_dump(
            mode="json"
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error
