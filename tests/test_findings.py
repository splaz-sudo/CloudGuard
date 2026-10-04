import pytest
from pydantic import ValidationError

from cloudguard.findings.models import (
    Finding,
    FindingCategory,
    Severity,
)


def test_finding_model():
    finding = Finding(
        id="CG-NET-001",
        title="Internet exposed workload",
        description=(
            "An EC2 workload is reachable from the internet."
        ),
        severity=Severity.HIGH,
        category=FindingCategory.NETWORK,
        affected_assets=["i-test123"],
        evidence=[
            "Public IP detected",
            "Security group permits 0.0.0.0/0",
        ],
        remediation=(
            "Restrict inbound access to trusted networks."
        ),
        risk_score=80,
    )

    assert finding.id == "CG-NET-001"
    assert finding.severity == Severity.HIGH
    assert finding.risk_score == 80

    assert "i-test123" in finding.affected_assets


def test_finding_risk_score_cannot_exceed_100():
    with pytest.raises(ValidationError):
        Finding(
            id="CG-TEST-001",
            title="Invalid risk",
            description="Test finding.",
            severity=Severity.HIGH,
            category=FindingCategory.CONFIGURATION,
            risk_score=101,
        )


def test_finding_risk_score_cannot_be_negative():
    with pytest.raises(ValidationError):
        Finding(
            id="CG-TEST-002",
            title="Invalid risk",
            description="Test finding.",
            severity=Severity.LOW,
            category=FindingCategory.CONFIGURATION,
            risk_score=-1,
        )
