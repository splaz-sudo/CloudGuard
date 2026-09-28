from cloudguard.compliance.models import (
    ComplianceStatus,
)
from cloudguard.services.analysis import (
    AnalysisService,
)
from cloudguard.services.compliance_analysis import (
    ComplianceAnalysisService,
)


def get_compliance_report():
    analysis = (
        AnalysisService()
        .analyze_local_lab()
    )

    return (
        ComplianceAnalysisService()
        .analyze(analysis)
    )


def test_compliance_report_contains_frameworks():
    report = get_compliance_report()

    assert len(report.frameworks) == 2

    framework_names = {
        framework.framework.value
        for framework in report.frameworks
    }

    assert (
        "CIS AWS Foundations"
        in framework_names
    )

    assert "NIST CSF" in framework_names


def test_compliance_report_contains_four_controls():
    report = get_compliance_report()

    assert len(report.controls) == 4


def test_compliance_maps_unique_findings():
    report = get_compliance_report()

    assert report.mapped_findings == 2


def test_network_control_is_non_compliant():
    report = get_compliance_report()

    control = next(
        item
        for item in report.controls
        if item.control_id
        == "CG-CIS-NET-01"
    )

    assert (
        control.status
        == ComplianceStatus.NON_COMPLIANT
    )

    assert (
        "CG-NET-i-cloudguard-web-01"
        in control.related_findings
    )

    assert (
        "i-cloudguard-web-01"
        in control.affected_assets
    )


def test_iam_control_maps_attack_path():
    report = get_compliance_report()

    control = next(
        item
        for item in report.controls
        if item.control_id
        == "CG-CIS-IAM-01"
    )

    assert (
        control.status
        == ComplianceStatus.NON_COMPLIANT
    )

    assert (
        "CG-PATH-s3:customer-backups-1"
        in control.related_findings
    )

    assert (
        "s3:customer-backups"
        in control.affected_assets
    )


def test_nist_access_control_mapping_exists():
    report = get_compliance_report()

    control = next(
        item
        for item in report.controls
        if item.control_id == "PR.AA"
    )

    assert (
        control.status
        == ComplianceStatus.NON_COMPLIANT
    )


def test_compliance_control_contains_remediation():
    report = get_compliance_report()

    control = next(
        item
        for item in report.controls
        if item.control_id
        == "CG-CIS-NET-01"
    )

    assert len(control.remediation) > 0