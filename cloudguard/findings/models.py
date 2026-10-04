from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(str, Enum):
    NETWORK = "network"
    IAM = "iam"
    STORAGE = "storage"
    ATTACK_PATH = "attack_path"
    CONFIGURATION = "configuration"


class Finding(BaseModel):
    id: str

    title: str
    description: str

    severity: Severity
    category: FindingCategory

    affected_assets: list[str] = Field(
        default_factory=list
    )

    evidence: list[str] = Field(
        default_factory=list
    )

    remediation: str | None = None

    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
    )
