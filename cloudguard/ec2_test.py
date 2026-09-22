from botocore.exceptions import ClientError

from cloudguard.collectors.aws_session import AWSSession
from cloudguard.collectors.ec2 import EC2Collector


def main() -> None:
    print("\nCloudGuard EC2 Collector")
    print("=" * 45)

    try:
        session = AWSSession(
            profile_name="cloudguard",
            region_name="us-east-1",
        )

        collector = EC2Collector(session)

        instances = collector.collect_instances()
        security_groups = collector.collect_security_groups()

        print(f"EC2 instances discovered: {len(instances)}")
        print(f"Security groups discovered: {len(security_groups)}")

        for instance in instances:
            print(
                f"\n{instance.instance_id}"
                f" | {instance.state}"
                f" | {instance.instance_type}"
            )

            print(f"Public IP: {instance.public_ip}")
            print(
                "Security groups: "
                + ", ".join(instance.security_group_ids)
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
