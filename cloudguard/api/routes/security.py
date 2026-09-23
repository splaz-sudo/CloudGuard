from fastapi import APIRouter

from cloudguard.services.analysis import AnalysisService


router = APIRouter(
    prefix="/api",
    tags=["Security"],
)

analysis_service = AnalysisService()


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
        result.security_graph
        .graph.edges
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
