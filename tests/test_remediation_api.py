from fastapi.testclient import TestClient

from cloudguard.main import app


client = TestClient(app)

LOCAL_LAB_REMEDIATION_ID = (
    "REM-RESTRICT-NETWORK-EXPOSURE-"
    "i-cloudguard-web-01"
)


def test_remediations_endpoint():
    response = client.get(
        "/api/remediations"
    )

    assert response.status_code == 200

    remediations = response.json()

    assert len(remediations) == 1

    remediation = remediations[0]

    assert (
        remediation["remediation_id"]
        == LOCAL_LAB_REMEDIATION_ID
    )

    assert (
        remediation["action_type"]
        == "restrict_network_exposure"
    )

    assert remediation[
        "affected_resources"
    ] == ["i-cloudguard-web-01"]

    assert remediation["evidence"]
    assert remediation["manual_steps"]
    assert remediation[
        "paths_affected"
    ] == 1
    assert remediation[
        "risk_before"
    ] == 95


def test_prioritized_endpoint():
    response = client.get(
        "/api/remediations/prioritized"
    )

    assert response.status_code == 200

    remediations = response.json()

    assert len(remediations) == 1

    remediation = remediations[0]

    assert remediation["priority"] == 1
    assert remediation[
        "paths_removed"
    ] == 1
    assert remediation[
        "risk_before"
    ] == 95
    assert remediation[
        "risk_after"
    ] == 0
    assert remediation[
        "risk_reduction"
    ] == 95
    assert remediation[
        "risk_reduction_percent"
    ] == 100.0


def test_simulate_endpoint():
    response = client.post(
        "/api/remediations/"
        f"{LOCAL_LAB_REMEDIATION_ID}"
        "/simulate"
    )

    assert response.status_code == 200

    result = response.json()

    assert (
        result["remediation_id"]
        == LOCAL_LAB_REMEDIATION_ID
    )

    assert result[
        "simulation_only"
    ] is True

    assert result["note"]

    assert result["before"][
        "highest_risk"
    ] == 95

    assert result["before"][
        "attack_paths"
    ] == 1

    assert result["after"][
        "attack_paths"
    ] == 0

    assert result["impact"][
        "paths_removed"
    ] == 1

    assert result["impact"][
        "risk_reduction"
    ] == (
        result["before"]["highest_risk"]
        - result["after"]["highest_risk"]
    )


def test_simulate_unknown_remediation():
    response = client.post(
        "/api/remediations/"
        "REM-DOES-NOT-EXIST/simulate"
    )

    assert response.status_code == 404

    body = response.json()

    assert "detail" in body
    assert (
        "REM-DOES-NOT-EXIST"
        in body["detail"]
    )


def test_original_state_intact_after_simulation():
    simulate_response = client.post(
        "/api/remediations/"
        f"{LOCAL_LAB_REMEDIATION_ID}"
        "/simulate"
    )

    assert (
        simulate_response.status_code
        == 200
    )

    paths_response = client.get(
        "/api/attack-paths"
    )

    paths = paths_response.json()

    assert len(paths) == 1

    assert paths[0]["nodes"] == [
        "internet",
        "i-cloudguard-web-01",
        "iam-role:cloudguard-web-role",
        "s3:customer-backups",
    ]

    overview_response = client.get(
        "/api/overview"
    )

    assert overview_response.json()[
        "highest_risk_score"
    ] == 95


def test_attack_paths_expose_explanations():
    response = client.get(
        "/api/attack-paths"
    )

    assert response.status_code == 200

    path = response.json()[0]

    assert path["path_id"]
    assert path["severity"] == "CRITICAL"
    assert path["risk_score"] == 95
    assert path["explanation"]

    assert len(path["hops"]) == 3

    for hop in path["hops"]:
        assert hop["reason"]
        assert hop["impact"]
        assert hop[
            "relationship_type"
        ] in {
            "exposed_to",
            "assumes",
            "can_read",
        }
