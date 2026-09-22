from botocore.exceptions import ClientError

from cloudguard.collectors.aws_session import AWSSession
from cloudguard.collectors.s3 import S3Collector


def main() -> None:
    print("\nCloudGuard S3 Collector")
    print("=" * 45)

    try:
        session = AWSSession(
            profile_name="cloudguard",
            region_name="us-east-1",
        )

        collector = S3Collector(session)

        buckets = collector.collect_buckets()

        print(f"S3 buckets discovered: {len(buckets)}")

        for bucket in buckets:
            print(f"\nBucket: {bucket.name}")
            print(f"Region: {bucket.region}")
            print(
                "Public access block: "
                f"{bucket.public_access_block_enabled}"
            )
            print(
                f"Public policy: {bucket.policy_public}"
            )

    except ClientError as error:
        print(
            "AWS error:",
            error.response["Error"]["Code"],
            "-",
            error.response["Error"]["Message"],
        )


if __name__ == "__main__":
    main()
