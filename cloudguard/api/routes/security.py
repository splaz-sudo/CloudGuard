from io import BytesIO

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from cloudguard.local_lab import LocalAWSLab
from cloudguard.reporting.engine import (
    SecurityReportEngine,
)
from cloudguard.reporting.pdf import (
    SecurityReportPDF,
)
from cloudguard.services.analysis import (
    AnalysisService,
)
from cloudguard.services.compliance_analysis import (
    ComplianceAnalysisService,
)
from cloudguard.services.identity_analysis import (
    IdentityAnalysisService,
)
from cloudguard.services.network_analysis import (
    NetworkAnalysisService,
)


router = APIRouter(
    prefix="/api",
    tags=["Security"],
)

analysis_service = AnalysisService()

identity_analysis_service = (
    IdentityAnalysisService()
)

network_analysis_service = (
    NetworkAnalysisService()
)

compliance_analysis_service = (
    ComplianceAnalysisService()
)

report_engine = SecurityReportEngine()

pdf_renderer = SecurityReportPDF()


def build_security_report():
    """
    Build the complete CloudGuard security report
    from the current local assessment.

    The same report model powers both the JSON
    endpoint and the PDF export.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    identities = (
        identity_analysis_service
        .analyze(result)
    )

    lab = LocalAWSLab()

    (
        instances,
        security_groups,
        _,
        _,
        _,
    ) = lab.create_environment()

    network_risks = (
        network_analysis_service.analyze(
            analysis_result=result,
            instances=instances,
            security_groups=(
                security_groups
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
    Returns high-level CloudGuard security metrics.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    findings = result.findings

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = (
            finding.severity.value.lower()
        )

        if severity in severity_counts:
            severity_counts[severity] += 1

    highest_risk_score = max(
        (
            finding.risk_score
            for finding in findings
        ),
        default=0,
    )

    sensitive_assets = sum(
        asset.sensitive
        for asset in result.assets
    )

    internet_exposed_assets = sum(
        asset.internet_exposed
        for asset in result.assets
    )

    return {
        "mode": "local",
        "assets": (
            result.security_graph.asset_count
        ),
        "relationships": (
            result.security_graph
            .relationship_count
        ),
        "sensitive_assets": (
            sensitive_assets
        ),
        "internet_exposed_assets": (
            internet_exposed_assets
        ),
        "attack_paths": len(
            result.attack_paths
        ),
        "findings": len(findings),
        "severity": severity_counts,
        "highest_risk_score": (
            highest_risk_score
        ),
    }


@router.get("/assets")
def get_assets() -> list[dict]:
    """
    Returns normalized cloud assets.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    assets = []

    for node_id in (
        result.security_graph.graph.nodes
    ):
        asset = (
            result.security_graph
            .get_asset(node_id)
        )

        if asset is None:
            continue

        assets.append(
            asset.model_dump(
                mode="json"
            )
        )

    return assets


@router.get("/relationships")
def get_relationships() -> list[dict]:
    """
    Returns relationships between cloud assets.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    relationships = []

    for source, target in (
        result.security_graph.graph.edges
    ):
        relationship = (
            result.security_graph
            .get_relationship(
                source,
                target,
            )
        )

        if relationship is None:
            continue

        relationships.append(
            relationship.model_dump(
                mode="json"
            )
        )

    return relationships


@router.get("/findings")
def get_findings() -> list[dict]:
    """
    Returns CloudGuard security findings.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    return [
        finding.model_dump(
            mode="json"
        )
        for finding in result.findings
    ]


@router.get("/attack-paths")
def get_attack_paths() -> list[dict]:
    """
    Returns discovered attack paths.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    return [
        path.model_dump(
            mode="json"
        )
        for path in result.attack_paths
    ]


@router.get("/identity-risks")
def get_identity_risks() -> list[dict]:
    """
    Returns contextual IAM identity risk analysis.

    Results are based on CloudGuard's observed
    assets, relationships, permissions, and
    attack paths.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    identities = (
        identity_analysis_service
        .analyze(result)
    )

    return [
        identity.to_dict()
        for identity in identities
    ]


@router.get("/network-risks")
def get_network_risks() -> list[dict]:
    """
    Returns contextual network exposure risk.

    The local endpoint analyzes CloudGuard's
    simulated AWS environment and performs no
    AWS API calls.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    lab = LocalAWSLab()

    (
        instances,
        security_groups,
        _,
        _,
        _,
    ) = lab.create_environment()

    network_risks = (
        network_analysis_service.analyze(
            analysis_result=result,
            instances=instances,
            security_groups=(
                security_groups
            ),
        )
    )

    return [
        risk.to_dict()
        for risk in network_risks
    ]


@router.get("/compliance")
def get_compliance() -> dict:
    """
    Returns evidence-based compliance mappings.

    This endpoint does not represent a complete
    certification or full framework audit.
    """

    result = (
        analysis_service
        .analyze_local_lab()
    )

    report = (
        compliance_analysis_service
        .analyze(result)
    )

    return report.model_dump(
        mode="json"
    )


@router.get("/report")
def get_security_report() -> dict:
    """
    Returns CloudGuard's consolidated security
    assessment as structured JSON.
    """

    report = build_security_report()

    return report.model_dump(
        mode="json"
    )


@router.get("/report/pdf")
def get_security_report_pdf():
    """
    Generates the CloudGuard security assessment
    as a downloadable PDF.

    The PDF is rendered from the same structured
    report used by the JSON report endpoint.
    """

    report = build_security_report()

    pdf_bytes = pdf_renderer.build(
        report
    )

    pdf_stream = BytesIO(
        pdf_bytes
    )

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