from pydantic import BaseModel

from cloudguard.collectors.aws_session import AWSSession


class S3Bucket(BaseModel):
    name: str
    region: str | None = None
    public_access_block_enabled: bool = False
    policy_public: bool = False


class S3Collector:
    def __init__(self, aws_session: AWSSession) -> None:
        self.client = aws_session.client("s3")

    def collect_buckets(self) -> list[S3Bucket]:
        buckets: list[S3Bucket] = []

        response = self.client.list_buckets()

        for item in response.get("Buckets", []):
            bucket_name = item["Name"]

            region = self._get_bucket_region(bucket_name)

            public_access_block = (
                self._has_public_access_block(bucket_name)
            )

            policy_public = self._is_policy_public(bucket_name)

            buckets.append(
                S3Bucket(
                    name=bucket_name,
                    region=region,
                    public_access_block_enabled=public_access_block,
                    policy_public=policy_public,
                )
            )

        return buckets

    def _get_bucket_region(self, bucket_name: str) -> str:
        response = self.client.get_bucket_location(
            Bucket=bucket_name
        )

        location = response.get("LocationConstraint")

        # AWS represents us-east-1 as None here.
        return location or "us-east-1"

    def _has_public_access_block(
        self,
        bucket_name: str,
    ) -> bool:
        try:
            response = self.client.get_public_access_block(
                Bucket=bucket_name
            )

            config = response["PublicAccessBlockConfiguration"]

            return all(
                [
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]
            )

        except self.client.exceptions.NoSuchPublicAccessBlockConfiguration:
            return False

    def _is_policy_public(
        self,
        bucket_name: str,
    ) -> bool:
        try:
            response = self.client.get_bucket_policy_status(
                Bucket=bucket_name
            )

            return response.get(
                "PolicyStatus", {}
            ).get("IsPublic", False)

        except self.client.exceptions.NoSuchBucketPolicy:
            return False
