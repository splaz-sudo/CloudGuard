from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from cloudguard.collectors.aws_session import AWSSession
from cloudguard.collectors.sts import STSCollector, require_identity


def main() -> None:
    print("\nCloudGuard AWS Connection Test")
    print("=" * 45)

    try:
        aws_session = AWSSession()
        collector = STSCollector(aws_session)

        identity = require_identity(collector.get_identity())

        print("AWS connection successful.")
        print(f"Account: {identity.account_id}")
        print(f"Identity ARN: {identity.arn}")

    except RuntimeError as error:
        print(f"ERROR: {error}")

    except NoCredentialsError:
        print("ERROR: AWS credentials were not found.")

    except ClientError as error:
        print(
            "AWS rejected the request:",
            error.response["Error"]["Code"],
        )

    except BotoCoreError as error:
        print(f"AWS SDK error: {error}")


if __name__ == "__main__":
    main()
