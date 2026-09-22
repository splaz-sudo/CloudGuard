from botocore.exceptions import ClientError

from cloudguard.collectors.aws_session import AWSSession
from cloudguard.collectors.iam import IAMCollector


def main() -> None:
    print("\nCloudGuard IAM Collector")
    print("=" * 45)

    try:
        session = AWSSession(
            profile_name="cloudguard",
            region_name="us-east-1",
        )

        collector = IAMCollector(session)

        users = collector.collect_users()
        roles = collector.collect_roles()

        print(f"IAM users discovered: {len(users)}")
        print(f"IAM roles discovered: {len(roles)}")

        for user in users:
            print(f"\nUSER: {user.name}")

            for policy in user.attached_policies:
                print(f"  Policy: {policy}")

        for role in roles:
            print(f"\nROLE: {role.name}")

            for policy in role.attached_policies:
                print(f"  Policy: {policy}")

    except ClientError as error:
        print(
            "AWS error:",
            error.response["Error"]["Code"],
            "-",
            error.response["Error"]["Message"],
        )


if __name__ == "__main__":
    main()
