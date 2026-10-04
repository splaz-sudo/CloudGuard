from cloudguard.findings.classifier import ResourceClassifier
from cloudguard.findings.engine import FindingEngine
from cloudguard.graph.attack_paths import AttackPathEngine
from cloudguard.graph.aws_graph import AWSGraphBuilder
from cloudguard.local_lab import LocalAWSLab
from cloudguard.normalizers.aws import AWSNormalizer


def build_local_lab_graph():
    lab = LocalAWSLab()

    (
        instances,
        security_groups,
        buckets,
        roles,
        instance_profiles,
    ) = lab.create_environment()

    normalizer = AWSNormalizer()

    assets = []

    assets.extend(
        normalizer.normalize_ec2(
            instances,
            lab.ACCOUNT_ID,
        )
    )

    assets.extend(
        normalizer.normalize_s3(
            buckets,
            lab.ACCOUNT_ID,
        )
    )

    assets.extend(
        normalizer.normalize_roles(
            roles,
            lab.ACCOUNT_ID,
        )
    )

    classifier = ResourceClassifier()

    assets = classifier.classify(
        assets
    )

    graph = AWSGraphBuilder().build(
        assets=assets,
        instances=instances,
        security_groups=security_groups,
        roles=roles,
        instance_profiles=instance_profiles,
    )

    return graph


def test_local_lab_builds_expected_graph():
    graph = build_local_lab_graph()

    assert graph.asset_count == 4
    assert graph.relationship_count == 3


def test_local_lab_discovers_attack_path():
    graph = build_local_lab_graph()

    paths = AttackPathEngine(
        graph
    ).find_paths_to_sensitive_assets()

    assert len(paths) == 1

    assert paths[0].nodes == [
        "internet",
        "i-cloudguard-web-01",
        "iam-role:cloudguard-web-role",
        "s3:customer-backups",
    ]

    assert paths[0].hop_count == 3
    assert paths[0].sensitive_target is True


def test_local_lab_generates_security_findings():
    graph = build_local_lab_graph()

    findings = FindingEngine().analyze(
        graph
    )

    assert len(findings) == 2

    severities = {
        finding.severity.value
        for finding in findings
    }

    assert "HIGH" in severities
    assert "CRITICAL" in severities

    critical_findings = [
        finding
        for finding in findings
        if finding.severity.value
        == "CRITICAL"
    ]

    assert len(critical_findings) == 1

    assert (
        critical_findings[0].risk_score
        == 95
    )
