from __future__ import annotations

from pydantic import BaseModel, Field


class ReportSummary(BaseModel):
    mode: str = "local"

    total_assets: int = 0
    total_relationships: int = 0

    sensitive_assets: int = 0
    internet_exposed_assets: int = 0

    attack_paths: int = 0
    findings: int = 0

    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0

    highest_risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
    )


class ReportAttackPath(BaseModel):
    nodes: list[str] = Field(
        default_factory=list
    )

    hop_count: int = 0
    sensitive_target: bool = False


class ReportFinding(BaseModel):
    id: str
    title: str
    description: str

    severity: str
    category: str

    risk_score: int = Field(
        ge=0,
        le=100,
    )

    affected_assets: list[str] = Field(
        default_factory=list
    )

    evidence: list[str] = Field(
        default_factory=list
    )

    remediation: str | None = None


class ReportIdentityRisk(BaseModel):
    identity_id: str
    identity_name: str
    identity_type: str

    risk_score: int = Field(
        ge=0,
        le=100,
    )

    severity: str

    permissions: list[str] = Field(
        default_factory=list
    )

    exposed_workloads: list[str] = Field(
        default_factory=list
    )

    sensitive_resources: list[str] = Field(
        default_factory=list
    )

    attack_paths: list[list[str]] = Field(
        default_factory=list
    )

    risk_factors: list[str] = Field(
        default_factory=list
    )


class ReportNetworkRisk(BaseModel):
    asset_id: str
    asset_name: str

    risk_score: int = Field(
        ge=0,
        le=100,
    )

    severity: str
    public_ip: str | None = None

    security_groups: list[str] = Field(
        default_factory=list
    )

    exposed_services: list[dict] = Field(
        default_factory=list
    )

    attached_identities: list[str] = Field(
        default_factory=list
    )

    sensitive_resources: list[str] = Field(
        default_factory=list
    )

    attack_paths: list[list[str]] = Field(
        default_factory=list
    )

    risk_factors: list[str] = Field(
        default_factory=list
    )


class ReportComplianceSummary(BaseModel):
    frameworks: int = 0
    mapped_controls: int = 0
    non_compliant_controls: int = 0
    not_assessed_controls: int = 0
    mapped_findings: int = 0


class SecurityReport(BaseModel):
    report_name: str = (
        "CloudGuard Security Assessment"
    )

    report_version: str = "1.0"

    assessment_mode: str = "local"

    scope_note: str = (
        "This report is generated from CloudGuard's "
        "analyzed evidence. Local mode uses a "
        "simulated AWS environment and performs no "
        "AWS API calls."
    )

    limitations: list[str] = Field(
        default_factory=list
    )

    summary: ReportSummary

    assets: list[dict] = Field(
        default_factory=list
    )

    attack_paths: list[
        ReportAttackPath
    ] = Field(
        default_factory=list
    )

    findings: list[
        ReportFinding
    ] = Field(
        default_factory=list
    )

    identity_risks: list[
        ReportIdentityRisk
    ] = Field(
        default_factory=list
    )

    network_risks: list[
        ReportNetworkRisk
    ] = Field(
        default_factory=list
    )

    compliance: ReportComplianceSummary

    compliance_controls: list[dict] = Field(
        default_factory=list
    )