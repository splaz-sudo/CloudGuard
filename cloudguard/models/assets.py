from enum import Enum

from pydantic import BaseModel, Field, computed_field


class AssetType(str, Enum):
    INTERNET = "internet"
    EC2 = "ec2"
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    S3_BUCKET = "s3_bucket"
    RDS = "rds"
    LAMBDA = "lambda"
    SECRET = "secret"
    SECURITY_GROUP = "security_group"
    VPC = "vpc"


class CloudAsset(BaseModel):
    id: str
    name: str
    asset_type: AssetType

    account_id: str | None = None
    region: str | None = None
    partition: str | None = None

    sensitive: bool = False
    internet_exposed: bool = False

    metadata: dict[str, str] = Field(default_factory=dict)

    @computed_field
    @property
    def canonical_id(self) -> str:
        """
        Canonical resource identity for cross-scan
        correlation and deduplication.

        Format: provider/account/region/service/resource-id

        For CloudGuard AWS resources, provider is always 'aws'.
        """
        parts = ["aws"]

        if self.account_id:
            parts.append(self.account_id)
        else:
            parts.append("unknown-account")

        if self.region:
            parts.append(self.region)
        else:
            parts.append("global")

        parts.append(self.asset_type.value)
        parts.append(self.id)

        return "/".join(parts)

    def cross_account_id(self) -> str:
        """
        Identity that includes partition for
        cross-account scenarios.
        """
        parts = ["aws"]

        if self.partition:
            parts.append(self.partition)
        else:
            parts.append("aws")

        if self.account_id:
            parts.append(self.account_id)
        else:
            parts.append("unknown-account")

        if self.region:
            parts.append(self.region)
        else:
            parts.append("global")

        parts.append(self.asset_type.value)
        parts.append(self.id)

        return "/".join(parts)
