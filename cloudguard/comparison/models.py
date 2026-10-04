from enum import Enum

from pydantic import BaseModel, Field


class ChangeStatus(str, Enum):
    NEW = "new"
    UNCHANGED = "unchanged"
    RESOLVED = "resolved"


class FindingChange(BaseModel):
    fingerprint: str
    status: ChangeStatus
    finding_id: str
    title: str
    severity: str
    risk_score: int


class AttackPathChange(BaseModel):
    path_id: str
    status: ChangeStatus
    source: str
    target: str
    nodes: list[str] = Field(
        default_factory=list
    )
    risk_score: int


class ComparisonResult(BaseModel):
    """
    Deterministic comparison of two immutable
    scans. Observation-based: CloudGuard
    reports what changed between snapshots;
    it does not claim it caused the change.
    """

    scan_a: str
    scan_b: str

    risk_before: int
    risk_after: int

    # after - before (negative = improvement)
    risk_delta: int

    findings_before: int
    findings_after: int

    new_findings: list[FindingChange] = Field(
        default_factory=list
    )
    unchanged_findings: list[
        FindingChange
    ] = Field(default_factory=list)
    resolved_findings: list[
        FindingChange
    ] = Field(default_factory=list)

    paths_before: int
    paths_after: int

    new_paths: list[AttackPathChange] = Field(
        default_factory=list
    )
    unchanged_paths: list[
        AttackPathChange
    ] = Field(default_factory=list)
    resolved_paths: list[
        AttackPathChange
    ] = Field(default_factory=list)

    note: str = (
        "Observation-based comparison. "
        "CloudGuard compares scan snapshots; "
        "it does not claim it caused any "
        "observed change."
    )


class RemediationVerification(BaseModel):
    """
    Whether the condition a remediation
    targeted is still observed in a newer
    scan.
    """

    remediation_id: str
    scan_a: str
    scan_b: str

    status: ChangeStatus

    resolved_finding_ids: list[str] = Field(
        default_factory=list
    )
    remaining_finding_ids: list[str] = Field(
        default_factory=list
    )

    resolved_path_ids: list[str] = Field(
        default_factory=list
    )
    remaining_path_ids: list[str] = Field(
        default_factory=list
    )

    note: str = (
        "Observation-based verification. "
        "CloudGuard observes the new "
        "configuration and compares it with "
        "the previous scan; it does not claim "
        "it performed or caused the change."
    )
