from cloudguard.inference.iam import PermissionGrant, RoleAttachment
from cloudguard.inference.network import InboundRule, NetworkConfiguration
from cloudguard.models.assets import AssetType, CloudAsset


def create_demo_environment():
    assets = [
        CloudAsset(
            id="internet",
            name="Internet",
            asset_type=AssetType.INTERNET,
        ),
        CloudAsset(
            id="ec2-web-01",
            name="EC2-WEB-01",
            asset_type=AssetType.EC2,
            account_id="123456789012",
            region="us-east-1",
        ),
        CloudAsset(
            id="web-app-role",
            name="WebAppRole",
            asset_type=AssetType.IAM_ROLE,
            account_id="123456789012",
        ),
        CloudAsset(
            id="customer-backups",
            name="customer-backups",
            asset_type=AssetType.S3_BUCKET,
            account_id="123456789012",
            region="us-east-1",
            sensitive=True,
        ),
    ]

    network_configurations = [
        NetworkConfiguration(
            asset_id="ec2-web-01",
            public_ip="54.10.20.30",
            inbound_rules=[
                InboundRule(
                    protocol="tcp",
                    from_port=443,
                    to_port=443,
                    sources=["0.0.0.0/0"],
                )
            ],
        )
    ]

    role_attachments = [
        RoleAttachment(
            workload_id="ec2-web-01",
            role_id="web-app-role",
        )
    ]

    permission_grants = [
        PermissionGrant(
            principal_id="web-app-role",
            target_asset_id="customer-backups",
            actions=[
                "s3:GetObject",
                "s3:ListBucket",
            ],
        )
    ]

    return (
        assets,
        network_configurations,
        role_attachments,
        permission_grants,
    )
