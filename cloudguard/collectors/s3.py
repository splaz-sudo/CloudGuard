import time

from pydantic import BaseModel, Field
from botocore.exceptions import ClientError

from cloudguard.aws_errors import CollectorResult
from cloudguard.collectors.aws_session import AWSSession
from cloudguard.retry import RetryConfig, retry_with_backoff


class S3Bucket(BaseModel):
    name: str
    region: str | None = None
    public_access_block_enabled: bool = False
    policy_public: bool = False
    tags: dict[str, str] = Field(
        default_factory=dict
    )


class S3Collector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.client = aws_session.client("s3")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_buckets(
        self,
    ) -> CollectorResult:

        def _collect() -> list[S3Bucket]:
            buckets: list[S3Bucket] = []

            response = self.client.list_buckets()

            for item in response.get(
                "Buckets",
                [],
            ):
                bucket_name = item["Name"]

                region = self._get_bucket_region(
                    bucket_name
                )

                public_access_block = (
                    self._has_public_access_block(
                        bucket_name
                    )
                )

                policy_public = (
                    self._is_policy_public(
                        bucket_name
                    )
                )

                tags = self._get_bucket_tags(
                    bucket_name
                )

                buckets.append(
                    S3Bucket(
                        name=bucket_name,
                        region=region,
                        public_access_block_enabled=(
                            public_access_block
                        ),
                        policy_public=policy_public,
                        tags=tags,
                    )
                )

            return buckets

        started = time.perf_counter()

        try:
            buckets = retry_with_backoff(_collect, self.retry_config)
            return CollectorResult(
                collector="s3",
                service="s3",
                region=None,
                status="success",
                resources_discovered=len(buckets),
                duration_ms=round(
                    (time.perf_counter() - started)
                    * 1000,
                    2,
                ),
                data=buckets,
            )
        except Exception as error:
            from cloudguard.aws_errors import (
                classify_collector_error,
                safe_error_message,
            )
            return CollectorResult(
                collector="s3",
                service="s3",
                region=None,
                status="failed",
                error_category=classify_collector_error(
                    error
                ),
                error_message=safe_error_message(error),
                duration_ms=round(
                    (time.perf_counter() - started)
                    * 1000,
                    2,
                ),
            )

    def _get_bucket_region(
        self,
        bucket_name: str,
    ) -> str:
        response = (
            self.client.get_bucket_location(
                Bucket=bucket_name
            )
        )

        location = response.get(
            "LocationConstraint"
        )

        if location is None:
            return "us-east-1"

        if location == "EU":
            return "eu-west-1"

        return location

    def _has_public_access_block(
        self,
        bucket_name: str,
    ) -> bool:
        try:
            response = (
                self.client.get_public_access_block(
                    Bucket=bucket_name
                )
            )

            config = response[
                "PublicAccessBlockConfiguration"
            ]

            return all(
                [
                    config.get(
                        "BlockPublicAcls",
                        False,
                    ),
                    config.get(
                        "IgnorePublicAcls",
                        False,
                    ),
                    config.get(
                        "BlockPublicPolicy",
                        False,
                    ),
                    config.get(
                        "RestrictPublicBuckets",
                        False,
                    ),
                ]
            )

        except ClientError as error:
            error_code = error.response[
                "Error"
            ].get(
                "Code",
                "",
            )

            if error_code in {
                "NoSuchPublicAccessBlockConfiguration",
                "NoSuchPublicAccessBlock",
            }:
                return False

            raise

    def _is_policy_public(
        self,
        bucket_name: str,
    ) -> bool:
        try:
            response = (
                self.client.get_bucket_policy_status(
                    Bucket=bucket_name
                )
            )

            return response.get(
                "PolicyStatus",
                {},
            ).get(
                "IsPublic",
                False,
            )

        except ClientError as error:
            error_code = error.response[
                "Error"
            ].get(
                "Code",
                "",
            )

            if error_code in {
                "NoSuchBucketPolicy",
                "NoSuchPolicy",
            }:
                return False

            raise

    def _get_bucket_tags(
        self,
        bucket_name: str,
    ) -> dict[str, str]:
        try:
            response = (
                self.client.get_bucket_tagging(
                    Bucket=bucket_name
                )
            )

            return {
                tag["Key"]: tag["Value"]
                for tag in response.get(
                    "TagSet",
                    [],
                )
            }

        except ClientError as error:
            error_code = error.response[
                "Error"
            ].get(
                "Code",
                "",
            )

            if error_code in {
                "NoSuchTagSet",
                "NoSuchTagSetError",
            }:
                return {}

            raise
