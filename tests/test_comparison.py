import pytest
from fastapi.testclient import TestClient

from cloudguard.comparison.engine import (
    ComparisonEngine,
)
from cloudguard.config import Settings
from cloudguard.main import app
from cloudguard.persistence.database import (
    Database,
)
from cloudguard.persistence.repository import (
    ScanRepository,
)
from cloudguard.scans.models import ScanSource
from cloudguard.scans.service import (
    ScanService,
)


client = TestClient(app)


@pytest.fixture()
def service():
    return ScanService(
        ScanRepository(
            Database(":memory:")
        ),
        Settings(
            environment="test",
            database_path=":memory:",
        ),
    )


def scan(service, scenario):
    return service.create_scan(
        ScanSource.LOCAL_LAB,
        environment=scenario,
        wait=True,
    )


def test_compare_identical_scans_all_unchanged(
    service,
):
    first = scan(service, "public-ec2")
    second = scan(service, "public-ec2")

    result = ComparisonEngine().compare(
        service.get_snapshot(first.scan_id),
        service.get_snapshot(second.scan_id),
    )

    assert result.risk_before == 95
    assert result.risk_after == 95
    assert result.risk_delta == 0

    assert len(result.new_findings) == 0
    assert len(result.resolved_findings) == 0
    assert (
        len(result.unchanged_findings) == 2
    )

    assert len(result.new_paths) == 0
    assert len(result.resolved_paths) == 0
    assert (
        len(result.unchanged_paths) == 1
    )


def test_compare_remediated_scan_all_resolved(
    service,
):
    before = scan(service, "public-ec2")
    after = scan(
        service,
        "remediated-lab",
    )

    result = ComparisonEngine().compare(
        service.get_snapshot(before.scan_id),
        service.get_snapshot(after.scan_id),
    )

    assert result.risk_before == 95
    assert result.risk_after == 0
    assert result.risk_delta == -95

    assert (
        len(result.resolved_findings) == 2
    )
    assert len(result.new_findings) == 0
    assert (
        len(result.unchanged_findings) == 0
    )

    assert len(result.resolved_paths) == 1
    assert len(result.new_paths) == 0
    assert len(result.unchanged_paths) == 0

    resolved_ids = {
        change.finding_id
        for change in (
            result.resolved_findings
        )
    }

    assert (
        "CG-NET-i-cloudguard-web-01"
        in resolved_ids
    )


def test_compare_reverse_shows_new(service):
    fixed = scan(service, "remediated-lab")
    broken = scan(service, "public-ec2")

    result = ComparisonEngine().compare(
        service.get_snapshot(fixed.scan_id),
        service.get_snapshot(broken.scan_id),
    )

    assert result.risk_delta == 95

    assert len(result.new_findings) == 2
    assert len(result.resolved_findings) == 0
    assert len(result.new_paths) == 1

    new_titles = {
        change.title
        for change in result.new_findings
    }

    assert any(
        "attack path" in title.lower()
        for title in new_titles
    )


def test_compare_partial_change(service):
    exposed = scan(
        service,
        "two-exposed-workloads",
    )
    baseline = scan(service, "public-ec2")

    result = ComparisonEngine().compare(
        service.get_snapshot(
            exposed.scan_id
        ),
        service.get_snapshot(baseline.scan_id),
    )

    # i-cloudguard-web-02's exposure is
    # resolved; the path finding and the
    # web-01 exposure are unchanged.
    assert len(result.resolved_findings) == 1
    assert (
        result.resolved_findings[
            0
        ].finding_id
        == "CG-NET-i-cloudguard-web-02"
    )

    assert (
        len(result.unchanged_findings) == 2
    )
    assert len(result.new_findings) == 0

    assert (
        len(result.unchanged_paths) == 1
    )
    assert len(result.resolved_paths) == 0


def test_comparison_is_deterministic(service):
    first = scan(service, "public-ec2")
    second = scan(service, "public-ec2")

    engine = ComparisonEngine()

    one = engine.compare(
        service.get_snapshot(first.scan_id),
        service.get_snapshot(second.scan_id),
    )
    two = engine.compare(
        service.get_snapshot(first.scan_id),
        service.get_snapshot(second.scan_id),
    )

    assert one.model_dump() == (
        two.model_dump()
    )


def test_verify_remediation_resolved(service):
    before = scan(service, "public-ec2")
    after = scan(
        service,
        "remediated-lab",
    )

    snapshot_a = service.get_snapshot(
        before.scan_id
    )
    snapshot_b = service.get_snapshot(
        after.scan_id
    )

    remediation = snapshot_a.remediations[0]

    verification = (
        ComparisonEngine()
        .verify_remediation(
            snapshot_a,
            snapshot_b,
            remediation,
        )
    )

    assert verification.status.value == (
        "resolved"
    )

    assert (
        "CG-NET-i-cloudguard-web-01"
        in verification.resolved_finding_ids
    )

    assert (
        verification.remaining_finding_ids
        == []
    )
    assert (
        verification.remaining_path_ids
        == []
    )

    assert "does not claim" in (
        verification.note
    )


def test_verify_remediation_unchanged(service):
    before = scan(service, "public-ec2")
    after = scan(service, "public-ec2")

    snapshot_a = service.get_snapshot(
        before.scan_id
    )
    snapshot_b = service.get_snapshot(
        after.scan_id
    )

    remediation = snapshot_a.remediations[0]

    verification = (
        ComparisonEngine()
        .verify_remediation(
            snapshot_a,
            snapshot_b,
            remediation,
        )
    )

    assert verification.status.value == (
        "unchanged"
    )

    assert verification.remaining_finding_ids


def test_compare_api_endpoint():
    first = client.post(
        "/api/scans",
        json={
            "source": "local_lab",
            "environment": "public-ec2",
        },
    ).json()

    second = client.post(
        "/api/scans",
        json={
            "source": "local_lab",
            "environment": "remediated-lab",
        },
    ).json()

    response = client.get(
        "/api/scans/compare/"
        f"{first['scan_id']}/{second['scan_id']}"
    )

    assert response.status_code == 200

    result = response.json()

    assert result["risk_before"] == 95
    assert result["risk_after"] == 0
    assert result["risk_delta"] == -95

    assert (
        len(result["resolved_findings"]) == 2
    )
    assert len(result["new_findings"]) == 0

    assert (
        len(result["resolved_paths"]) == 1
    )


def test_compare_api_unknown_scan():
    response = client.get(
        "/api/scans/compare/"
        "scan-nope/scan-alsonope"
    )

    assert response.status_code == 404


def test_verify_api_endpoint():
    first = client.post(
        "/api/scans",
        json={
            "source": "local_lab",
            "environment": "public-ec2",
        },
    ).json()

    second = client.post(
        "/api/scans",
        json={
            "source": "local_lab",
            "environment": "remediated-lab",
        },
    ).json()

    remediation_id = (
        "REM-RESTRICT-NETWORK-EXPOSURE-"
        "i-cloudguard-web-01"
    )

    response = client.get(
        f"/api/scans/{first['scan_id']}"
        f"/remediations/{remediation_id}"
        f"/verify/{second['scan_id']}"
    )

    assert response.status_code == 200

    verification = response.json()

    assert verification["status"] == (
        "resolved"
    )

    assert (
        remediation_id
        == verification["remediation_id"]
    )
