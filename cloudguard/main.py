from cloudguard.demo import create_demo_environment
from cloudguard.graph.attack_paths import AttackPathEngine
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.inference.engine import SecurityInferenceEngine


def main() -> None:
    (
        assets,
        network_configurations,
        role_attachments,
        permission_grants,
    ) = create_demo_environment()

    inference_engine = SecurityInferenceEngine()

    relationships = inference_engine.infer(
        network_configurations=network_configurations,
        role_attachments=role_attachments,
        permission_grants=permission_grants,
    )

    security_graph = SecurityGraph()
    security_graph.build(
        assets=assets,
        relationships=relationships,
    )

    attack_engine = AttackPathEngine(security_graph)

    paths = attack_engine.find_paths_to_sensitive_assets()

    print("\nCloudGuard")
    print("Cloud Security Intelligence Platform")
    print("=" * 55)

    print(f"\nAssets discovered:       {security_graph.asset_count}")
    print(f"Relationships inferred: {security_graph.relationship_count}")
    print(f"Attack paths discovered: {len(paths)}")

    for number, path in enumerate(paths, start=1):
        print(f"\nATTACK PATH {number}")
        print("-" * 55)

        for index, node_id in enumerate(path.nodes):
            asset = security_graph.get_asset(node_id)

            if asset is None:
                continue

            suffix = " [SENSITIVE]" if asset.sensitive else ""

            print(
                f"{asset.name} "
                f"[{asset.asset_type.value}]"
                f"{suffix}"
            )

            if index < len(path.relationships):
                relationship = path.relationships[index]

                print(
                    f"   | {relationship.relationship_type.value}"
                )

                if relationship.permissions:
                    print(
                        "   | "
                        + ", ".join(relationship.permissions)
                    )

                if relationship.evidence:
                    print(
                        f"   | evidence: {relationship.evidence}"
                    )

                print("   v")

        print(f"\nPath length: {path.hop_count} hops")


if __name__ == "__main__":
    main()