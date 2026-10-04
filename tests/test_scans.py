import pytest

from cloudguard.config import Settings
from cloudguard.persistence.database import (
    Database,
)
from cloudguard.persistence.repository import (
    ScanRepository,
)
from cloudguard.scans.models import (
    ScanSource,
    ScanStatus,
)
from cloudguard.scans.service import (
    ScanNotFoundError,
    ScanService,
)


@pytest.fixture()
def make_service():
    def _make():
        database = Database(":memory:")

        return ScanService(
            ScanRepository(database),
            Settings(
                environment="test",
                database_path=":memory:",
            ),
        )

    return _make


@pytest.fixture()
def service(make_service):
    return make_service()


def test_local_lab_scan_completes(service):
    record = service.create_scan(
        ScanSource.LOCAL_LAB,
        wait=True,
    )

    assert record.status == (
        ScanStatus.COMPLETED
    )

    assert record.scan_id.startswith("scan-")
    assert record.source == ScanSource.LOCAL_LAB
    assert record.environment == "public-ec2"

    assert record.asset_count == 4
    assert record.relationship_count == 3
    assert record.finding_count == 2
    assert record.attack_path_count == 1
    assert record.highest_risk == 95

    assert record.started_at is not None
    assert record.completed_at is not None
    assert record.duration_ms is not None
    assert record.scanner_version


def test_snapshot_is_persisted(service):
    record = service.create_scan(
        ScanSource.LOCAL_LAB,
        wait=True,
    )

    snapshot = service.get_snapshot(
        record.scan_id
    )

    assert len(snapshot.assets) == 4
    assert len(snapshot.relationships) == 3
    assert len(snapshot.findings) == 2
    assert len(snapshot.attack_paths) == 1
    assert len(snapshot.remediations) == 1

    assert snapshot.environment is not None
    assert (
        snapshot.environment.instances[
            0
        ].instance_id
        == "i-cloudguard-web-01"
    )

    graph = snapshot.build_graph()

    assert graph.asset_count == 4
    assert graph.relationship_count == 3


def test_fingerprints_are_stored(service):
    record = service.create_scan(
        ScanSource.LOCAL_LAB,
        wait=True,
    )

    snapshot = service.get_snapshot(
        record.scan_id
    )

    for finding in snapshot.findings:
        assert finding.fingerprint

    fingerprints = {
        finding.fingerprint
        for finding in snapshot.findings
    }

    assert len(fingerprints) == 2


def test_scans_are_immutable_snapshots(service):
    first = service.create_scan(
        ScanSource.LOCAL_LAB,
        wait=True,
    )

    second = service.create_scan(
        ScanSource.LOCAL_LAB,
        wait=True,
    )

    assert first.scan_id != second.scan_id

    first_snapshot = service.get_snapshot(
        first.scan_id
    )
    second_snapshot = service.get_snapshot(
        second.scan_id
    )

    # Both snapshots exist independently;
    # rescanning never overwrites history.
    assert (
        first_snapshot.record.created_at
        != second_snapshot.record.created_at
        or first_snapshot.record.scan_id
        != second_snapshot.record.scan_id
    )

    assert (
        first_snapshot.record.highest_risk
        == 95
    )


def test_scan_history_is_listed(service):
    service.create_scan(
        ScanSource.LOCAL_LAB,
        wait=True,
    )
    service.create_scan(
        ScanSource.LOCAL_LAB,
        wait=True,
    )

    records = service.list_scans()

    assert len(records) == 2

    assert (
        records[0].created_at
        >= records[1].created_at
    )


def test_unknown_scenario_fails_scan(service):
    record = service.create_scan(
        ScanSource.LOCAL_LAB,
        environment="does-not-exist",
        wait=True,
    )

    assert record.status == ScanStatus.FAILED
    assert record.error_message


def test_unknown_scan_raises(service):
    with pytest.raises(ScanNotFoundError):
        service.get_snapshot("scan-nope")


def test_interrupted_scans_recovered(
    make_service,
):
    first_service = make_service()

    running = first_service.create_scan(
        ScanSource.LOCAL_LAB,
        wait=False,
    )

    # Simulate an interrupted process by
    # forcing the record back to RUNNING.
    running.status = ScanStatus.RUNNING
    first_service.repository.update_scan(
        running
    )

    # A new service instance over the same
    # repository must recover it.
    recovered = ScanService(
        first_service.repository,
        first_service.settings,
    )

    record = recovered.get_scan(
        running.scan_id
    )

    assert record.status == ScanStatus.FAILED
    assert "interrupted" in (
        record.error_message or ""
    )


def test_persistence_survives_reopen(
    tmp_path,
):
    db_path = str(
        tmp_path / "scans.db"
    )

    service_one = ScanService(
        ScanRepository(
            Database(db_path)
        ),
        Settings(
            environment="test",
            database_path=db_path,
        ),
    )

    record = service_one.create_scan(
        ScanSource.LOCAL_LAB,
        wait=True,
    )

    # Simulate a restart: brand-new service
    # and database connection, same file.
    service_two = ScanService(
        ScanRepository(
            Database(db_path)
        ),
        Settings(
            environment="test",
            database_path=db_path,
        ),
    )

    snapshot = service_two.get_snapshot(
        record.scan_id
    )

    assert (
        snapshot.record.scan_id
        == record.scan_id
    )

    assert len(snapshot.assets) == 4
    assert len(snapshot.attack_paths) == 1
    assert (
        snapshot.record.highest_risk == 95
    )


def test_simulation_does_not_mutate_scan(
    service,
):
    record = service.create_scan(
        ScanSource.LOCAL_LAB,
        wait=True,
    )

    before = service.get_snapshot(
        record.scan_id
    )

    remediation = before.remediations[0]

    result = service.analysis_result_for(
        before
    )

    simulation = (
        service.remediation_service
        .simulator.simulate(
            result,
            remediation,
        )
    )

    assert simulation.after.attack_paths == 0

    after = service.get_snapshot(
        record.scan_id
    )

    assert (
        after.record.attack_path_count == 1
    )
    assert after.record.highest_risk == 95
    assert len(after.findings) == 2
    assert (
        after.relationships
        and before.relationships
    )

    assert [
        item.relationship_id
        for item in after.relationships
    ] == [
        item.relationship_id
        for item in before.relationships
    ]


@pytest.mark.parametrize(
    (
        "scenario",
        "expected_paths",
        "expected_findings",
        "expected_risk",
    ),
    [
        ("public-ec2", 1, 2, 95),
        ("remediated-lab", 0, 0, 0),
        ("two-exposed-workloads", 1, 3, 95),
        ("broad-iam-role", 1, 2, 95),
        ("private-lab", 0, 0, 0),
    ],
)
def test_scenario_outcomes(
    service,
    scenario,
    expected_paths,
    expected_findings,
    expected_risk,
):
    record = service.create_scan(
        ScanSource.LOCAL_LAB,
        environment=scenario,
        wait=True,
    )

    assert record.status == (
        ScanStatus.COMPLETED
    )
    assert (
        record.attack_path_count
        == expected_paths
    )
    assert (
        record.finding_count
        == expected_findings
    )
    assert (
        record.highest_risk
        == expected_risk
    )
