from cloudguard.services.analysis import (
    AnalysisService,
)
from cloudguard.services.identity_analysis import (
    IdentityAnalysisService,
)


def get_identity_risks():
    analysis = (
        AnalysisService()
        .analyze_local_lab()
    )

    return (
        IdentityAnalysisService()
        .analyze(analysis)
    )


def test_local_lab_contains_identity_risk():
    risks = get_identity_risks()

    assert len(risks) == 1


def test_cloudguard_role_is_detected():
    risks = get_identity_risks()

    risk = risks[0]

    assert (
        risk.identity_id
        == "iam-role:cloudguard-web-role"
    )

    assert (
        risk.identity_name
        == "cloudguard-web-role"
    )

    assert risk.identity_type == "iam_role"


def test_identity_has_expected_permission():
    risks = get_identity_risks()

    risk = risks[0]

    assert "s3:ListBucket" in risk.permissions


def test_identity_is_connected_to_exposed_workload():
    risks = get_identity_risks()

    risk = risks[0]

    assert (
        "i-cloudguard-web-01"
        in risk.exposed_workloads
    )


def test_identity_can_reach_sensitive_bucket():
    risks = get_identity_risks()

    risk = risks[0]

    assert (
        "s3:customer-backups"
        in risk.sensitive_resources
    )


def test_identity_participates_in_attack_path():
    risks = get_identity_risks()

    risk = risks[0]

    expected_path = [
        "internet",
        "i-cloudguard-web-01",
        "iam-role:cloudguard-web-role",
        "s3:customer-backups",
    ]

    assert expected_path in risk.attack_paths


def test_identity_risk_is_critical():
    risks = get_identity_risks()

    risk = risks[0]

    assert risk.risk_score == 95
    assert risk.severity == "critical"