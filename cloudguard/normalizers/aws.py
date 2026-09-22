from cloudguard.collectors.ec2 import EC2Instance
from cloudguard.collectors.iam import IAMRole, IAMUser
from cloudguard.collectors.s3 import S3Bucket
from cloudguard.models.assets import AssetType, CloudAsset


class AWSNormalizer:
    def normalize_ec2(
        self,
        instances: list[EC2Instance],
        account_id: str,
    ) -> list[CloudAsset]:

        return [
            CloudAsset(
                id=instance.instance_id,
                name=instance.instance_id,
                asset_type=AssetType.EC2,
                account_id=account_id,
                region=instance.region,
                internet_exposed=bool(instance.public_ip),
                metadata={
                    "instance_type": instance.instance_type,
                    "state": instance.state,
                    "public_ip": instance.public_ip or "",
                    "private_ip": instance.private_ip or "",
                },
            )
            for instance in instances
        ]

    def normalize_s3(
        self,
        buckets: list[S3Bucket],
        account_id: str,
    ) -> list[CloudAsset]:

        return [
            CloudAsset(
                id=f"s3:{bucket.name}",
                name=bucket.name,
                asset_type=AssetType.S3_BUCKET,
                account_id=account_id,
                region=bucket.region,
                sensitive=False,
                internet_exposed=bucket.policy_public,
                metadata={
                    "public_access_block": str(
                        bucket.public_access_block_enabled
                    ),
                    "policy_public": str(bucket.policy_public),
                },
            )
            for bucket in buckets
        ]

    def normalize_roles(
        self,
        roles: list[IAMRole],
        account_id: str,
    ) -> list[CloudAsset]:

        return [
            CloudAsset(
                id=f"iam-role:{role.name}",
                name=role.name,
                asset_type=AssetType.IAM_ROLE,
                account_id=account_id,
                metadata={
                    "arn": role.arn,
                    "attached_policy_count": str(
                        len(role.attached_policies)
                    ),
                },
            )
            for role in roles
        ]

    def normalize_users(
        self,
        users: list[IAMUser],
        account_id: str,
    ) -> list[CloudAsset]:

        return [
            CloudAsset(
                id=f"iam-user:{user.name}",
                name=user.name,
                asset_type=AssetType.IAM_USER,
                account_id=account_id,
                metadata={
                    "arn": user.arn,
                    "attached_policy_count": str(
                        len(user.attached_policies)
                    ),
                },
            )
            for user in users
        ]
