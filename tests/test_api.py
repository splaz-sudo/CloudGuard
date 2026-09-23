from fastapi.testclient import TestClient

from cloudguard.main import app


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "CloudGuard"
    assert data["status"] == "running"


def test_health_endpoint():
    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "CloudGuard API"


def test_overview_endpoint():
    response = client.get("/api/overview")

    assert response.status_code == 200

    data = response.json()

    assert data["mode"] == "local"
    assert data["assets"] == 4
    assert data["relationships"] == 3
    assert data["sensitive_assets"] == 1
    assert data["internet_exposed_assets"] == 1
    assert data["attack_paths"] == 1
    assert data["findings"] == 2
    assert data["severity"]["critical"] == 1
    assert data["severity"]["high"] == 1
    assert data["highest_risk_score"] == 95


def test_assets_endpoint():
    response = client.get("/api/assets")

    assert response.status_code == 200

    assets = response.json()

    assert len(assets) == 4

    asset_ids = {
        asset["id"]
        for asset in assets
    }

    assert "internet" in asset_ids
    assert "i-cloudguard-web-01" in asset_ids
    assert (
        "iam-role:cloudguard-web-role"
        in asset_ids
    )
    assert "s3:customer-backups" in asset_ids


def test_relationships_endpoint():
    response = client.get(
        "/api/relationships"
    )

    assert response.status_code == 200

    relationships = response.json()

    assert len(relationships) == 3

    relationship_types = {
        relationship[
            "relationship_type"
        ]
        for relationship in relationships
    }

    assert "exposed_to" in relationship_types
    assert "assumes" in relationship_types
    assert "can_read" in relationship_types


def test_findings_endpoint():
    response = client.get("/api/findings")

    assert response.status_code == 200

    findings = response.json()

    assert len(findings) == 2

    severities = {
        finding["severity"]
        for finding in findings
    }

    assert "HIGH" in severities
    assert "CRITICAL" in severities


def test_attack_paths_endpoint():
    response = client.get(
        "/api/attack-paths"
    )

    assert response.status_code == 200

    paths = response.json()

    assert len(paths) == 1

    path = paths[0]

    assert path["nodes"] == [
        "internet",
        "i-cloudguard-web-01",
        "iam-role:cloudguard-web-role",
        "s3:customer-backups",
    ]

    assert path["hop_count"] == 3
    assert path["sensitive_target"] is True
