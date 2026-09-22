from botocore.exceptions import BotoCoreError, ClientError

from cloudguard.collectors.aws_session import AWSSession
from cloudguard.collectors.ec2 import EC2Collector
from cloudguard.collectors.iam import IAMCollector
from cloudguard.collectors.s3 import S3Collector
from cloudguard.collectors.sts import STSCollector
from cloudguard.graph.attack_paths import AttackPathEngine
from cloudguard.graph.aws_graph import AWSGraphBuilder
from cloudguard.normalizers.aws import AWSNormalizer


def main() -> None:
    print("\nCloudGuard AWS Security Scan")
    print("=" * 60)

    try:
        session = AWSSession(
            profile_name="cloudguard",
            region_name="us-east-1",
        )

        # --------------------------------------------------
        # Identity
        # --------------------------------------------------

        identity = STSCollector(
            session
        ).get_identity()

        # --------------------------------------------------
        # Collection
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
        # Normalization
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
        # Security Graph
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
        # Attack Path Analysis
        # --------------------------------------------------

        attack_engine = AttackPathEngine(
            security_graph
        )

        paths = (
            attack_engine.find_paths_to_sensitive_assets()
        )

        # --------------------------------------------------
        # Results
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
            f"Instance profiles:   {len(instance_profiles)}"
        )

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
            f"Attack paths:        {len(paths)}"
        )

        # --------------------------------------------------
        # Attack Paths
        # --------------------------------------------------

        if not paths:
            print(
                "\nNo attack paths to sensitive "
                "assets were discovered."
            )

        for number, path in enumerate(
            paths,
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

                    print(
                        "   |"
                    )

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

                    print(
                        "   v"
                    )

            print(
                f"\nPath length: "
                f"{path.hop_count} hops"
            )

    except ClientError as error:
        print(
            "\nAWS ERROR"
        )

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
