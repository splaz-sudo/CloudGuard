from botocore.exceptions import BotoCoreError, ClientError

from cloudguard.collectors.aws_session import AWSSession
from cloudguard.collectors.ec2 import EC2Collector
from cloudguard.collectors.iam import IAMCollector
from cloudguard.collectors.s3 import S3Collector
from cloudguard.collectors.sts import STSCollector
from cloudguard.findings.classifier import ResourceClassifier
from cloudguard.findings.engine import FindingEngine
from cloudguard.graph.attack_paths import AttackPathEngine
from cloudguard.graph.aws_graph import AWSGraphBuilder
from cloudguard.normalizers.aws import AWSNormalizer


def main() -> None:
    print("\nCloudGuard AWS Security Scan")
    print("=" * 60)

    try:
        # --------------------------------------------------
        # AWS SESSION
        # --------------------------------------------------

        session = AWSSession(
            profile_name="cloudguard",
            region_name="us-east-1",
        )

        identity = STSCollector(
            session
        ).get_identity()

        # --------------------------------------------------
        # COLLECTION
        # --------------------------------------------------

        ec2_collector = EC2Collector(session)
        s3_collector = S3Collector(session)
        iam_collector = IAMCollector(session)

        instances = (
            ec2_collector.collect_instances()
        )

        security_groups = (
            ec2_collector.collect_security_groups()
        )

        buckets = (
            s3_collector.collect_buckets()
        )

        users = (
            iam_collector.collect_users()
        )

        roles = (
            iam_collector.collect_roles()
        )

        instance_profiles = (
            iam_collector.collect_instance_profiles()
        )

        # --------------------------------------------------
        # NORMALIZATION
        # --------------------------------------------------

        normalizer = AWSNormalizer()

        assets = []

        assets.extend(
            normalizer.normalize_ec2(
                instances,
                identity.account_id,
            )
        )

        assets.extend(
            normalizer.normalize_s3(
                buckets,
                identity.account_id,
            )
        )

        assets.extend(
            normalizer.normalize_users(
                users,
                identity.account_id,
            )
        )

        assets.extend(
            normalizer.normalize_roles(
                roles,
                identity.account_id,
            )
        )

        # --------------------------------------------------
        # RESOURCE CLASSIFICATION
        # --------------------------------------------------

        classifier = ResourceClassifier()

        assets = classifier.classify(
            assets
        )

        # --------------------------------------------------
        # SECURITY GRAPH
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
        # ATTACK PATH ANALYSIS
        # --------------------------------------------------

        attack_engine = AttackPathEngine(
            security_graph
        )

        attack_paths = (
            attack_engine.find_paths_to_sensitive_assets()
        )

        # --------------------------------------------------
        # FINDING ANALYSIS
        # --------------------------------------------------

        finding_engine = FindingEngine()

        findings = finding_engine.analyze(
            security_graph
        )

        # --------------------------------------------------
        # RISK SUMMARY
        # --------------------------------------------------

        highest_risk_score = max(
            (
                finding.risk_score
                for finding in findings
            ),
            default=0,
        )

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

        # --------------------------------------------------
        # INVENTORY OUTPUT
        # --------------------------------------------------

        print("\nInventory")
        print("-" * 60)

        print(
            f"EC2 instances:       {len(instances)}"
        )

        print(
            f"Security groups:     {len(security_groups)}"
        )

        print(
            f"S3 buckets:          {len(buckets)}"
        )

        print(
            f"IAM users:           {len(users)}"
        )

        print(
            f"IAM roles:           {len(roles)}"
        )

        print(
            f"Instance profiles:   "
            f"{len(instance_profiles)}"
        )

        # --------------------------------------------------
        # GRAPH OUTPUT
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
        # SECURITY SUMMARY
        # --------------------------------------------------

        print("\nSecurity Summary")
        print("-" * 60)

        print(
            f"Findings:            {len(findings)}"
        )

        print(
            f"Critical:            {critical_count}"
        )

        print(
            f"High:                {high_count}"
        )

        print(
            f"Medium:              {medium_count}"
        )

        print(
            f"Low:                 {low_count}"
        )

        print(
            f"Highest risk score:  "
            f"{highest_risk_score}/100"
        )

        # --------------------------------------------------
        # FINDINGS OUTPUT
        # --------------------------------------------------

        if not findings:
            print(
                "\nNo security findings were discovered."
            )

        for number, finding in enumerate(
            findings,
            start=1,
        ):
            print(
                f"\nFINDING {number}"
            )

            print("-" * 60)

            print(
                f"ID:       {finding.id}"
            )

            print(
                f"Severity: {finding.severity.value}"
            )

            print(
                f"Category: {finding.category.value}"
            )

            print(
                f"Risk:     {finding.risk_score}/100"
            )

            print(
                f"Title:    {finding.title}"
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
                print(
                    "\nEvidence:"
                )

                for evidence in (
                    finding.evidence
                ):
                    print(
                        f"  - {evidence}"
                    )

            if finding.remediation:
                print(
                    "\nRemediation:"
                )

                print(
                    f"  {finding.remediation}"
                )

        # --------------------------------------------------
        # ATTACK PATH DETAILS
        # --------------------------------------------------

        if attack_paths:
            print(
                "\nAttack Paths"
            )

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
                        path.relationships[index]
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

    except ClientError as error:
        print("\nAWS ERROR")

        print(
            error.response["Error"]["Code"],
            "-",
            error.response["Error"]["Message"],
        )

    except BotoCoreError as error:
        print(
            f"\nAWS SDK ERROR: {error}"
        )


if __name__ == "__main__":
    main()
