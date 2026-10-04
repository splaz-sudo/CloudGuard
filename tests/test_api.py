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


def test_identity_risks_endpoint():
    response = client.get(
        "/api/identity-risks"
    )

    assert response.status_code == 200

    risks = response.json()

    assert len(risks) == 1

    risk = risks[0]

    assert (
        risk["identity_id"]
        == "iam-role:cloudguard-web-role"
    )

    assert (
        risk["identity_name"]
        == "cloudguard-web-role"
    )

    assert risk["identity_type"] == "iam_role"
    assert risk["risk_score"] == 95
    assert risk["severity"] == "critical"

    assert (
        "s3:ListBucket"
        in risk["permissions"]
    )

    assert (
        "i-cloudguard-web-01"
        in risk["exposed_workloads"]
    )

    assert (
        "s3:customer-backups"
        in risk["sensitive_resources"]
    )


def test_network_risks_endpoint():
    response = client.get(
        "/api/network-risks"
    )

    assert response.status_code == 200

    risks = response.json()

    assert len(risks) == 1

    risk = risks[0]

    assert (
        risk["asset_id"]
        == "i-cloudguard-web-01"
    )

    assert (
        risk["public_ip"]
        == "203.0.113.10"
    )

    assert risk["risk_score"] == 80
    assert risk["severity"] == "high"

    assert len(
        risk["exposed_services"]
    ) == 1

    service = risk[
        "exposed_services"
    ][0]

    assert service["protocol"] == "tcp"
    assert service["from_port"] == 80
    assert service["to_port"] == 80

    assert (
        "0.0.0.0/0"
        in service["sources"]
    )

    assert (
        "iam-role:cloudguard-web-role"
        in risk["attached_identities"]
    )

    assert (
        "s3:customer-backups"
        in risk["sensitive_resources"]
    )


def test_compliance_endpoint():
    response = client.get(
        "/api/compliance"
    )

    assert response.status_code == 200

    report = response.json()

    assert len(report["frameworks"]) == 2
    assert len(report["controls"]) == 4
    assert report["mapped_findings"] == 2

    framework_names = {
        framework["framework"]
        for framework
        in report["frameworks"]
    }

    assert (
        "CIS AWS Foundations"
        in framework_names
    )

    assert "NIST CSF" in framework_names

    controls = {
        control["control_id"]:
        control
        for control in report["controls"]
    }

    assert "CG-CIS-NET-01" in controls
    assert "CG-CIS-IAM-01" in controls
    assert "PR.AA" in controls
    assert "PR.PS" in controls

    assert (
        controls[
            "CG-CIS-NET-01"
        ]["status"]
        == "NON_COMPLIANT"
    )

    assert (
        "CG-NET-i-cloudguard-web-01"
        in controls[
            "CG-CIS-NET-01"
        ]["related_findings"]
    )

    assert (
        controls[
            "CG-CIS-IAM-01"
        ]["status"]
        == "NON_COMPLIANT"
    )

    assert (
        "CG-PATH-s3:customer-backups-1"
        in controls[
            "CG-CIS-IAM-01"
        ]["related_findings"]
    )


def test_security_report_endpoint():
    response = client.get(
        "/api/report"
    )

    assert response.status_code == 200

    report = response.json()

    assert (
        report["report_name"]
        == "CloudGuard Security Assessment"
    )

    assert report["report_version"] == "1.0"
    assert report["assessment_mode"] == "local"

    summary = report["summary"]

    assert summary["total_assets"] == 4
    assert summary["total_relationships"] == 3
    assert summary["sensitive_assets"] == 1

    assert (
        summary["internet_exposed_assets"]
        == 1
    )

    assert summary["attack_paths"] == 1
    assert summary["findings"] == 2
    assert summary["critical_findings"] == 1
    assert summary["high_findings"] == 1

    assert (
        summary["highest_risk_score"]
        == 95
    )

    assert len(report["attack_paths"]) == 1
    assert len(report["findings"]) == 2
    assert len(report["identity_risks"]) == 1
    assert len(report["network_risks"]) == 1

    attack_path = report[
        "attack_paths"
    ][0]

    assert attack_path["nodes"] == [
        "internet",
        "i-cloudguard-web-01",
        "iam-role:cloudguard-web-role",
        "s3:customer-backups",
    ]

    critical_finding = report[
        "findings"
    ][0]

    assert (
        critical_finding["severity"]
        == "CRITICAL"
    )

    assert (
        critical_finding["risk_score"]
        == 95
    )

    identity_risk = report[
        "identity_risks"
    ][0]

    assert (
        identity_risk["risk_score"]
        == 95
    )

    network_risk = report[
        "network_risks"
    ][0]

    assert (
        network_risk["risk_score"]
        == 80
    )

    compliance = report["compliance"]

    assert compliance["frameworks"] == 2
    assert compliance["mapped_controls"] == 4

    assert (
        compliance[
            "non_compliant_controls"
        ]
        == 4
    )

    assert (
        compliance["mapped_findings"]
        == 2
    )

    assert len(
        report["compliance_controls"]
    ) == 4

    assert len(report["limitations"]) >= 3


def test_security_report_pdf_endpoint():
    response = client.get(
        "/api/report/pdf"
    )

    assert response.status_code == 200

    assert (
        response.headers["content-type"]
        == "application/pdf"
    )

    content_disposition = (
        response.headers.get(
            "content-disposition",
            "",
        )
    )

    assert (
        "CloudGuard-Security-Assessment.pdf"
        in content_disposition
    )

    assert response.content.startswith(
        b"%PDF"
    )

    assert len(response.content) > 1000