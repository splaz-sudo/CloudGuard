from cloudguard.local_lab import (
    LocalAWSLab,
)
from cloudguard.services.analysis import (
    AnalysisService,
)
from cloudguard.services.network_analysis import (
    NetworkAnalysisService,
)


def get_network_risks():
    lab = LocalAWSLab()

    (
        instances,
        security_groups,
        _,
        _,
        _,
    ) = lab.create_environment()

    analysis = (
        AnalysisService()
        .analyze_local_lab()
    )

    return (
        NetworkAnalysisService()
        .analyze(
            analysis_result=analysis,
            instances=instances,
            security_groups=security_groups,
        )
    )


def test_local_lab_contains_network_risk():
    risks = get_network_risks()

    assert len(risks) == 1


def test_public_ec2_is_analyzed():
    risks = get_network_risks()

    risk = risks[0]

    assert (
        risk.asset_id
        == "i-cloudguard-web-01"
    )

    assert risk.public_ip == "203.0.113.10"


def test_internet_exposed_service_is_detected():
    risks = get_network_risks()

    risk = risks[0]

    assert len(risk.exposed_services) == 1

    service = risk.exposed_services[0]

    assert service.protocol == "tcp"
    assert service.from_port == 80
    assert service.to_port == 80

    assert (
        "0.0.0.0/0"
        in service.sources
    )


def test_network_risk_detects_attached_identity():
    risks = get_network_risks()

    risk = risks[0]

    assert (
        "iam-role:cloudguard-web-role"
        in risk.attached_identities
    )


def test_network_risk_detects_sensitive_resource():
    risks = get_network_risks()

    risk = risks[0]

    assert (
        "s3:customer-backups"
        in risk.sensitive_resources
    )


def test_network_risk_contains_attack_path():
    risks = get_network_risks()

    risk = risks[0]

    expected_path = [
        "internet",
        "i-cloudguard-web-01",
        "iam-role:cloudguard-web-role",
        "s3:customer-backups",
    ]

    assert expected_path in risk.attack_paths


def test_network_risk_is_high():
    risks = get_network_risks()

    risk = risks[0]

    assert risk.risk_score == 80
    assert risk.severity == "high"