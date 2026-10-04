from io import BytesIO

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from cloudguard.api.presenters import (
    overview_payload,
    scan_http_error,
)
from cloudguard.reporting.engine import (
    SecurityReportEngine,
)
from cloudguard.reporting.pdf import (
    SecurityReportPDF,
)
from cloudguard.scans.runtime import (
    get_scan_service,
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
    prefix="/api",
    tags=["Security"],
)


report_engine = SecurityReportEngine()

pdf_renderer = SecurityReportPDF()

identity_analysis_service = (
    IdentityAnalysisService()
)

network_analysis_service = (
    NetworkAnalysisService()
)

compliance_analysis_service = (
    ComplianceAnalysisService()
)


def _latest_snapshot():
    """
    Backwards-compatible data source: the
    newest completed local-lab scan. One scan
    fans out to every endpoint instead of
    re-analyzing per request.
    """

    return (
        get_scan_service()
        .get_or_create_latest_local_lab()
    )


def _analysis_result(snapshot):
    return (
        get_scan_service()
        .analysis_result_for(snapshot)
    )


def build_security_report():
    """
    Build the complete CloudGuard security
    report from the latest completed scan.

    The same report model powers both the
    JSON endpoint and the PDF export.
    """

    snapshot = _latest_snapshot()

    result = _analysis_result(snapshot)

    identities = (
        identity_analysis_service
        .analyze(result)
    )

    environment = snapshot.environment

    network_risks = (
        network_analysis_service.analyze(
            analysis_result=result,
            instances=(
                environment.instances
                if environment
                else []
            ),
            security_groups=(
                environment.security_groups
                if environment
                else []
            ),
        )
    )

    compliance_report = (
        compliance_analysis_service
        .analyze(result)
    )

    return report_engine.build(
        analysis_result=result,
        identity_risks=identities,
        network_risks=network_risks,
        compliance_report=(
            compliance_report
        ),
    )


@router.get("/overview")
def get_overview() -> dict:
    """
    Returns high-level CloudGuard security
    metrics for the latest completed scan.
    """

    try:
        return overview_payload(
            _latest_snapshot()
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error


@router.get("/assets")
def get_assets() -> list[dict]:
    """
    Returns normalized cloud assets from the
    latest completed scan.
    """

    try:
        snapshot = _latest_snapshot()
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    return [
        asset.model_dump(mode="json")
        for asset in snapshot.assets
    ]


@router.get("/relationships")
def get_relationships() -> list[dict]:
    """
    Returns security relationships from the
    latest completed scan.
    """

    try:
        snapshot = _latest_snapshot()
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    return [
        relationship.model_dump(mode="json")
        for relationship in (
            snapshot.relationships
        )
    ]


@router.get("/findings")
def get_findings() -> list[dict]:
    """
    Returns security findings from the latest
    completed scan.
    """

    try:
        snapshot = _latest_snapshot()
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    return [
        finding.model_dump(mode="json")
        for finding in snapshot.findings
    ]


@router.get("/attack-paths")
def get_attack_paths() -> list[dict]:
    """
    Returns discovered attack paths from the
    latest completed scan.
    """

    try:
        snapshot = _latest_snapshot()
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    return [
        path.model_dump(mode="json")
        for path in snapshot.attack_paths
    ]


@router.get("/identity-risks")
def get_identity_risks() -> list[dict]:
    """
    Returns contextual IAM identity risk
    analysis for the latest completed scan.
    """

    try:
        snapshot = _latest_snapshot()

        identities = (
            identity_analysis_service
            .analyze(
                _analysis_result(snapshot)
            )
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    return [
        identity.to_dict()
        for identity in identities
    ]


@router.get("/network-risks")
def get_network_risks() -> list[dict]:
    """
    Returns contextual network exposure risk
    for the latest completed scan.
    """

    try:
        snapshot = _latest_snapshot()

        environment = snapshot.environment

        network_risks = (
            network_analysis_service.analyze(
                analysis_result=(
                    _analysis_result(snapshot)
                ),
                instances=(
                    environment.instances
                    if environment
                    else []
                ),
                security_groups=(
                    environment
                    .security_groups
                    if environment
                    else []
                ),
            )
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    return [
        risk.to_dict()
        for risk in network_risks
    ]


@router.get("/compliance")
def get_compliance() -> dict:
    """
    Returns evidence-based compliance mappings
    for the latest completed scan.
    """

    try:
        snapshot = _latest_snapshot()

        report = (
            compliance_analysis_service
            .analyze(
                _analysis_result(snapshot)
            )
        )
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    return report.model_dump(mode="json")


@router.get("/report")
def get_security_report() -> dict:
    """
    Returns CloudGuard's consolidated security
    assessment as structured JSON.
    """

    try:
        report = build_security_report()
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    return report.model_dump(mode="json")


@router.get("/report/pdf")
def get_security_report_pdf():
    """
    Generates the CloudGuard security
    assessment as a downloadable PDF.
    """

    try:
        report = build_security_report()
    except Exception as error:
        raise scan_http_error(
            error
        ) from error

    pdf_bytes = pdf_renderer.build(report)

    pdf_stream = BytesIO(pdf_bytes)

    return StreamingResponse(
        pdf_stream,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                "attachment; "
                "filename="
                "\"CloudGuard-Security-Assessment.pdf\""
            ),
            "Content-Length": str(
                len(pdf_bytes)
            ),
        },
    )
