from fastapi.testclient import TestClient

from cloudguard.main import app


client = TestClient(app)


def create_scan(
    environment="public-ec2",
    source="local_lab",
):
    response = client.post(
        "/api/scans",
        json={
            "source": source,
            "environment": environment,
        },
    )

    assert response.status_code == 200

    return response.json()


def test_create_and_get_scan():
    created = create_scan()

    assert created["status"] == "completed"
    assert created["highest_risk"] == 95
    assert created["asset_count"] == 4

    response = client.get(
        f"/api/scans/{created['scan_id']}"
    )

    assert response.status_code == 200

    fetched = response.json()

    assert (
        fetched["scan_id"]
        == created["scan_id"]
    )


def test_list_scans():
    created = create_scan()

    response = client.get("/api/scans")

    assert response.status_code == 200

    scan_ids = {
        item["scan_id"]
        for item in response.json()
    }

    assert created["scan_id"] in scan_ids


def test_unknown_scan_returns_404():
    response = client.get(
        "/api/scans/scan-does-not-exist"
    )

    assert response.status_code == 404


def test_invalid_scenario_returns_failed_scan():
    created = create_scan(
        environment="not-a-scenario"
    )

    assert created["status"] == "failed"

    response = client.get(
        "/api/scans/"
        f"{created['scan_id']}/findings"
    )

    assert response.status_code == 409


def test_scan_endpoints_share_one_snapshot():
    created = create_scan()

    scan_id = created["scan_id"]

    overview = client.get(
        f"/api/scans/{scan_id}/overview"
    ).json()

    assets = client.get(
        f"/api/scans/{scan_id}/assets"
    ).json()

    relationships = client.get(
        f"/api/scans/{scan_id}/relationships"
    ).json()

    findings = client.get(
        f"/api/scans/{scan_id}/findings"
    ).json()

    paths = client.get(
        f"/api/scans/{scan_id}/attack-paths"
    ).json()

    remediations = client.get(
        f"/api/scans/{scan_id}/remediations"
    ).json()

    # Every endpoint reflects the SAME scan.
    assert overview["scan_id"] == scan_id
    assert overview["assets"] == len(assets)
    assert overview["relationships"] == len(
        relationships
    )
    assert overview["findings"] == len(
        findings
    )
    assert overview["attack_paths"] == len(
        paths
    )
    assert overview["mode"] == "local"
    assert overview["environment"] == (
        "public-ec2"
    )

    assert len(remediations) == 1


def test_scan_simulation_and_immutability():
    created = create_scan()

    scan_id = created["scan_id"]

    remediations = client.get(
        f"/api/scans/{scan_id}/remediations"
    ).json()

    remediation_id = remediations[0][
        "remediation_id"
    ]

    response = client.post(
        f"/api/scans/{scan_id}/remediations/"
        f"{remediation_id}/simulate"
    )

    assert response.status_code == 200

    simulation = response.json()

    assert simulation["before"][
        "highest_risk"
    ] == 95

    assert simulation["before"][
        "attack_paths"
    ] == 1

    assert simulation["after"][
        "attack_paths"
    ] == 0

    # The stored scan must be untouched.
    record = client.get(
        f"/api/scans/{scan_id}"
    ).json()

    assert record["attack_path_count"] == 1
    assert record["highest_risk"] == 95

    paths = client.get(
        f"/api/scans/{scan_id}/attack-paths"
    ).json()

    assert len(paths) == 1


def test_scan_unknown_remediation_404():
    created = create_scan()

    response = client.post(
        f"/api/scans/{created['scan_id']}"
        "/remediations/REM-NOPE/simulate"
    )

    assert response.status_code == 404


def test_scan_prioritized_remediations():
    created = create_scan()

    response = client.get(
        f"/api/scans/{created['scan_id']}"
        "/remediations/prioritized"
    )

    assert response.status_code == 200

    prioritized = response.json()

    assert prioritized[0]["priority"] == 1
    assert prioritized[0][
        "risk_reduction"
    ] == 95


def test_scan_identity_and_network_views():
    created = create_scan()

    scan_id = created["scan_id"]

    identity = client.get(
        f"/api/scans/{scan_id}/identity-risks"
    )

    assert identity.status_code == 200
    assert len(identity.json()) == 1

    network = client.get(
        f"/api/scans/{scan_id}/network-risks"
    )

    assert network.status_code == 200

    risks = network.json()

    assert risks[0]["risk_score"] == 80


def test_scan_compliance_view():
    created = create_scan()

    response = client.get(
        f"/api/scans/{created['scan_id']}"
        "/compliance"
    )

    assert response.status_code == 200

    report = response.json()

    assert report["mapped_findings"] >= 1


def test_legacy_endpoints_use_latest_scan():
    overview = client.get(
        "/api/overview"
    ).json()

    assert overview["mode"] == "local"
    assert overview["highest_risk_score"] == 95
    assert "scan_id" in overview

    findings = client.get(
        "/api/findings"
    ).json()

    assert len(findings) == overview[
        "findings"
    ]


def test_collector_results_endpoint():
    created = create_scan()

    scan_id = created["scan_id"]

    response = client.get(
        f"/api/scans/{scan_id}/collector-results"
    )

    assert response.status_code == 200

    results = response.json()

    assert len(results) == 5

    collector_names = {
        result["collector"]
        for result in results
    }

    expected_collectors = {
        "local_lab_ec2_instances",
        "local_lab_ec2_security_groups",
        "local_lab_s3_buckets",
        "local_lab_iam_roles",
        "local_lab_iam_instance_profiles",
    }

    assert collector_names == expected_collectors

    for result in results:
        assert result["status"] == "success"
        assert result["resources_discovered"] >= 1
        assert result["error_category"] is None
        assert result["error_message"] is None
