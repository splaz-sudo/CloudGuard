"""
Shared response builders and error mapping
for scan-backed API endpoints.
"""

from fastapi import HTTPException

from cloudguard.lab_scenarios import (
    UnknownScenarioError,
)
from cloudguard.remediation.service import (
    RemediationNotFoundError,
)
from cloudguard.scans.models import (
    ScanSnapshot,
    ScanSource,
)
from cloudguard.scans.service import (
    ScanFailedError,
    ScanNotFoundError,
    ScanNotReadyError,
)


def overview_payload(
    snapshot: ScanSnapshot,
) -> dict:
    record = snapshot.record

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in snapshot.findings:
        severity = (
            finding.severity.value.lower()
        )

        if severity in severity_counts:
            severity_counts[severity] += 1

    highest_risk_score = max(
        (
            finding.risk_score
            for finding in snapshot.findings
        ),
        default=0,
    )

    sensitive_assets = sum(
        asset.sensitive
        for asset in snapshot.assets
    )

    internet_exposed_assets = sum(
        asset.internet_exposed
        for asset in snapshot.assets
    )

    graph = snapshot.build_graph()

    return {
        "mode": (
            "local"
            if record.source
            == ScanSource.LOCAL_LAB
            else "aws"
        ),
        "scan_id": record.scan_id,
        "source": record.source.value,
        "environment": record.environment,
        "status": record.status.value,
        "created_at": record.created_at,
        "account_identifier": (
            record.account_identifier
        ),
        "regions": record.regions,
        "assets": graph.asset_count,
        "relationships": (
            graph.relationship_count
        ),
        "sensitive_assets": sensitive_assets,
        "internet_exposed_assets": (
            internet_exposed_assets
        ),
        "attack_paths": len(
            snapshot.attack_paths
        ),
        "findings": len(snapshot.findings),
        "severity": severity_counts,
        "highest_risk_score": (
            highest_risk_score
        ),
    }


def scan_http_error(
    error: Exception,
) -> HTTPException:
    if isinstance(
        error,
        ScanNotFoundError,
    ):
        return HTTPException(
            status_code=404,
            detail=str(error),
        )

    if isinstance(
        error,
        RemediationNotFoundError,
    ):
        return HTTPException(
            status_code=404,
            detail=str(error),
        )

    if isinstance(
        error,
        UnknownScenarioError,
    ):
        return HTTPException(
            status_code=400,
            detail=str(error),
        )

    if isinstance(
        error,
        (ScanNotReadyError, ScanFailedError),
    ):
        return HTTPException(
            status_code=409,
            detail=str(error),
        )

    return HTTPException(
        status_code=500,
        detail="CloudGuard scan error.",
    )
