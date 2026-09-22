from enum import Enum

from pydantic import BaseModel, Field


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

    sensitive: bool = False
    internet_exposed: bool = False

    metadata: dict[str, str] = Field(default_factory=dict)
