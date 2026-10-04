from cloudguard.local_lab import LocalAWSLab
from cloudguard.reporting.engine import (
    SecurityReportEngine,
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


def build_report():
    analysis = (
        AnalysisService()
        .analyze_local_lab()
    )

    identity_risks = (
        IdentityAnalysisService()
        .analyze(analysis)
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
        NetworkAnalysisService()
        .analyze(
            analysis_result=analysis,
            instances=instances,
            security_groups=security_groups,
        )
    )

    compliance_report = (
        ComplianceAnalysisService()
        .analyze(analysis)
    )

    return (
        SecurityReportEngine()
        .build(
            analysis_result=analysis,
            identity_risks=identity_risks,
            network_risks=network_risks,
            compliance_report=compliance_report,
        )
    )


def test_report_metadata():
    report = build_report()

    assert (
        report.report_name
        == "CloudGuard Security Assessment"
    )

    assert report.report_version == "1.0"
    assert report.assessment_mode == "local"


def test_report_summary():
    report = build_report()

    summary = report.summary

    assert summary.total_assets == 4
    assert summary.total_relationships == 3
    assert summary.sensitive_assets == 1
    assert summary.internet_exposed_assets == 1
    assert summary.attack_paths == 1
    assert summary.findings == 2

    assert summary.critical_findings == 1
    assert summary.high_findings == 1

    assert summary.highest_risk_score == 95


def test_report_contains_attack_path():
    report = build_report()

    assert len(report.attack_paths) == 1

    path = report.attack_paths[0]

    assert path.nodes == [
        "internet",
        "i-cloudguard-web-01",
        "iam-role:cloudguard-web-role",
        "s3:customer-backups",
    ]

    assert path.hop_count == 3
    assert path.sensitive_target is True


def test_report_prioritizes_findings():
    report = build_report()

    assert len(report.findings) == 2

    assert (
        report.findings[0].risk_score
        >= report.findings[1].risk_score
    )

    assert (
        report.findings[0].severity
        == "CRITICAL"
    )

    assert (
        report.findings[0].risk_score
        == 95
    )


def test_report_contains_identity_risk():
    report = build_report()

    assert len(report.identity_risks) == 1

    risk = report.identity_risks[0]

    assert (
        risk.identity_id
        == "iam-role:cloudguard-web-role"
    )

    assert risk.risk_score == 95
    assert risk.severity == "critical"

    assert (
        "s3:customer-backups"
        in risk.sensitive_resources
    )


def test_report_contains_network_risk():
    report = build_report()

    assert len(report.network_risks) == 1

    risk = report.network_risks[0]

    assert (
        risk.asset_id
        == "i-cloudguard-web-01"
    )

    assert risk.risk_score == 80
    assert risk.severity == "high"

    assert risk.public_ip == "203.0.113.10"


def test_report_contains_compliance_summary():
    report = build_report()

    compliance = report.compliance

    assert compliance.frameworks == 2
    assert compliance.mapped_controls == 4

    assert (
        compliance.non_compliant_controls
        == 4
    )

    assert (
        compliance.not_assessed_controls
        == 0
    )

    assert compliance.mapped_findings == 2


def test_report_contains_limitations():
    report = build_report()

    assert len(report.limitations) >= 3

    limitations = " ".join(
        report.limitations
    ).lower()

    assert "simulated aws" in limitations
    assert "effective-permission" in limitations
    assert "certification" in limitations