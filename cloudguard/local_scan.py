from cloudguard.findings.classifier import ResourceClassifier
from cloudguard.findings.engine import FindingEngine
from cloudguard.graph.attack_paths import AttackPathEngine
from cloudguard.graph.aws_graph import AWSGraphBuilder
from cloudguard.local_lab import LocalAWSLab
from cloudguard.normalizers.aws import AWSNormalizer


def main() -> None:
    print("\nCloudGuard Local Security Lab")
    print("=" * 60)
    print("Mode: LOCAL SIMULATION")
    print("No AWS resources or API calls are used.")

    # --------------------------------------------------
    # 1. Create simulated AWS environment
    # --------------------------------------------------

    lab = LocalAWSLab()

    (
        instances,
        security_groups,
        buckets,
        roles,
        instance_profiles,
    ) = lab.create_environment()

    # --------------------------------------------------
    # 2. Normalize simulated AWS resources
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 3. Classify sensitive resources
    # --------------------------------------------------

    classifier = ResourceClassifier()

    assets = classifier.classify(
        assets
    )

    # --------------------------------------------------
    # 4. Build security graph
    # --------------------------------------------------

    graph_builder = AWSGraphBuilder()

    security_graph = graph_builder.build(
        assets=assets,
        instances=instances,
        security_groups=security_groups,
        roles=roles,
        instance_profiles=instance_profiles,
    )

    # --------------------------------------------------
    # 5. Discover attack paths
    # --------------------------------------------------

    attack_engine = AttackPathEngine(
        security_graph
    )

    attack_paths = (
        attack_engine
        .find_paths_to_sensitive_assets()
    )

    # --------------------------------------------------
    # 6. Generate security findings
    # --------------------------------------------------

    finding_engine = FindingEngine()

    findings = finding_engine.analyze(
        security_graph
    )

    # --------------------------------------------------
    # 7. Print inventory
    # --------------------------------------------------

    print("\nInventory")
    print("-" * 60)

    print(
        f"EC2 instances:       "
        f"{len(instances)}"
    )

    print(
        f"Security groups:     "
        f"{len(security_groups)}"
    )

    print(
        f"S3 buckets:          "
        f"{len(buckets)}"
    )

    print(
        f"IAM roles:           "
        f"{len(roles)}"
    )

    print(
        f"Instance profiles:   "
        f"{len(instance_profiles)}"
    )

    # --------------------------------------------------
    # 8. Print graph statistics
    # --------------------------------------------------

    print("\nSecurity Graph")
    print("-" * 60)

    print(
        f"Assets:              "
        f"{security_graph.asset_count}"
    )

    print(
        f"Relationships:       "
        f"{security_graph.relationship_count}"
    )

    print(
        f"Attack paths:        "
        f"{len(attack_paths)}"
    )

    # --------------------------------------------------
    # 9. Print findings summary
    # --------------------------------------------------

    critical_count = sum(
        finding.severity.value == "CRITICAL"
        for finding in findings
    )

    high_count = sum(
        finding.severity.value == "HIGH"
        for finding in findings
    )

    medium_count = sum(
        finding.severity.value == "MEDIUM"
        for finding in findings
    )

    low_count = sum(
        finding.severity.value == "LOW"
        for finding in findings
    )

    highest_risk_score = max(
        (
            finding.risk_score
            for finding in findings
        ),
        default=0,
    )

    print("\nSecurity Summary")
    print("-" * 60)

    print(
        f"Findings:            "
        f"{len(findings)}"
    )

    print(
        f"Critical:            "
        f"{critical_count}"
    )

    print(
        f"High:                "
        f"{high_count}"
    )

    print(
        f"Medium:              "
        f"{medium_count}"
    )

    print(
        f"Low:                 "
        f"{low_count}"
    )

    print(
        f"Highest risk score:  "
        f"{highest_risk_score}/100"
    )

    # --------------------------------------------------
    # 10. Print findings
    # --------------------------------------------------

    for number, finding in enumerate(
        findings,
        start=1,
    ):
        print(
            f"\nFINDING {number}"
        )

        print("-" * 60)

        print(
            f"ID:       "
            f"{finding.id}"
        )

        print(
            f"Severity: "
            f"{finding.severity.value}"
        )

        print(
            f"Category: "
            f"{finding.category.value}"
        )

        print(
            f"Risk:     "
            f"{finding.risk_score}/100"
        )

        print(
            f"Title:    "
            f"{finding.title}"
        )

        print(
            f"\n{finding.description}"
        )

        if finding.affected_assets:
            print(
                "\nAffected assets:"
            )

            for asset_id in (
                finding.affected_assets
            ):
                print(
                    f"  - {asset_id}"
                )

        if finding.evidence:
            print("\nEvidence:")

            for evidence in (
                finding.evidence
            ):
                print(
                    f"  - {evidence}"
                )

        if finding.remediation:
            print("\nRemediation:")

            print(
                f"  "
                f"{finding.remediation}"
            )

    # --------------------------------------------------
    # 11. Print attack paths
    # --------------------------------------------------

    if attack_paths:
        print("\nAttack Paths")
        print("=" * 60)

    for number, path in enumerate(
        attack_paths,
        start=1,
    ):
        print(
            f"\nATTACK PATH {number}"
        )

        print("-" * 60)

        for index, node_id in enumerate(
            path.nodes
        ):
            asset = (
                security_graph.get_asset(
                    node_id
                )
            )

            if asset is None:
                continue

            sensitive = (
                " [SENSITIVE]"
                if asset.sensitive
                else ""
            )

            print(
                f"{asset.name} "
                f"[{asset.asset_type.value}]"
                f"{sensitive}"
            )

            if index < len(
                path.relationships
            ):
                relationship = (
                    path.relationships[
                        index
                    ]
                )

                print("   |")

                print(
                    "   | "
                    f"{relationship.relationship_type.value}"
                )

                if relationship.permissions:
                    print(
                        "   | permissions: "
                        + ", ".join(
                            relationship.permissions
                        )
                    )

                if relationship.evidence:
                    print(
                        "   | evidence: "
                        f"{relationship.evidence}"
                    )

                print("   v")

        print(
            f"\nPath length: "
            f"{path.hop_count} hops"
        )


if __name__ == "__main__":
    main()
