from enum import Enum

from pydantic import BaseModel, Field


class ComplianceStatus(str, Enum):
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"


class ComplianceFramework(str, Enum):
    CIS_AWS = "CIS AWS Foundations"
    NIST_CSF = "NIST CSF"


class ComplianceControl(BaseModel):
    framework: ComplianceFramework

    control_id: str
    title: str
    description: str

    status: ComplianceStatus

    related_findings: list[str] = Field(
        default_factory=list
    )

    affected_assets: list[str] = Field(
        default_factory=list
    )

    evidence: list[str] = Field(
        default_factory=list
    )

    remediation: list[str] = Field(
        default_factory=list
    )


class FrameworkSummary(BaseModel):
    framework: ComplianceFramework

    total_controls: int = 0
    non_compliant: int = 0
    not_assessed: int = 0


class ComplianceReport(BaseModel):
    frameworks: list[FrameworkSummary] = Field(
        default_factory=list
    )

    controls: list[ComplianceControl] = Field(
        default_factory=list
    )

    mapped_findings: int = 0