from cloudguard.collectors.aws_session import AWSSession
from cloudguard.collectors.ec2 import EC2Collector
from cloudguard.collectors.iam import IAMCollector
from cloudguard.collectors.s3 import S3Collector
from cloudguard.collectors.sts import STSCollector, require_identity
from cloudguard.normalizers.aws import AWSNormalizer


def main() -> None:
    print("\nCloudGuard AWS Inventory")
    print("=" * 50)

    session = AWSSession(
        profile_name="cloudguard",
        region_name="us-east-1",
    )

    identity = require_identity(
        STSCollector(session).get_identity()
    )

    ec2 = EC2Collector(session)
    s3 = S3Collector(session)
    iam = IAMCollector(session)

    instances = ec2.collect_instances()
    buckets = s3.collect_buckets()
    users = iam.collect_users()
    roles = iam.collect_roles()

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

    print(f"EC2 instances: {len(instances)}")
    print(f"S3 buckets:    {len(buckets)}")
    print(f"IAM users:     {len(users)}")
    print(f"IAM roles:     {len(roles)}")

    print(f"\nNormalized assets: {len(assets)}")

    print("\nAssets")
    print("-" * 50)

    for asset in assets:
        print(
            f"{asset.asset_type.value:<12}"
            f" {asset.name}"
        )


if __name__ == "__main__":
    main()
