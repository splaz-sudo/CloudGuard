from cloudguard.demo import create_demo_environment
from cloudguard.graph.attack_paths import AttackPathEngine
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.inference.engine import SecurityInferenceEngine


def build_demo_graph():
    (
        assets,
        network_configurations,
        role_attachments,
        permission_grants,
    ) = create_demo_environment()

    inference = SecurityInferenceEngine()

    relationships = inference.infer(
        network_configurations,
        role_attachments,
        permission_grants,
    )

    graph = SecurityGraph()
    graph.build(assets, relationships)

    return graph


def test_graph_contains_expected_assets():
    graph = build_demo_graph()

    assert graph.asset_count == 4
    assert graph.relationship_count == 3


def test_internet_can_reach_web_server():
    graph = build_demo_graph()

    reachable = graph.successors("internet")

    assert len(reachable) == 1
    assert reachable[0].id == "ec2-web-01"


def test_attack_path_to_sensitive_bucket():
    graph = build_demo_graph()

    engine = AttackPathEngine(graph)

    paths = engine.find_paths_to_sensitive_assets()

    assert len(paths) == 1

    assert paths[0].nodes == [
        "internet",
        "ec2-web-01",
        "web-app-role",
        "customer-backups",
    ]

    assert paths[0].sensitive_target is True
    assert paths[0].hop_count == 3
