from enum import Enum

from pydantic import BaseModel, Field


class RemediationActionType(str, Enum):
    RESTRICT_NETWORK_EXPOSURE = (
        "restrict_network_exposure"
    )
    REDUCE_IAM_PERMISSION = (
        "reduce_iam_permission"
    )
    REMOVE_ROLE_ATTACHMENT = (
        "remove_role_attachment"
    )
    RESTRICT_RESOURCE_ACCESS = (
        "restrict_resource_access"
    )


class Remediation(BaseModel):
    """
    A structured, evidence-backed remediation
    recommendation.

    Impact fields (paths_removed, risk_after,
    risk_reduction, ...) are populated only
    after the remediation has been evaluated
    against an isolated simulation of the
    current environment. They are never
    hard-coded.
    """

    remediation_id: str
    title: str
    description: str

    action_type: RemediationActionType

    affected_resources: list[str] = Field(
        default_factory=list
    )

    finding_ids: list[str] = Field(
        default_factory=list
    )

    attack_path_ids: list[str] = Field(
        default_factory=list
    )

    relationship_ids: list[str] = Field(
        default_factory=list
    )

    evidence: list[str] = Field(
        default_factory=list
    )

    manual_steps: list[str] = Field(
        default_factory=list
    )

    expected_effect: str = ""

    priority: int | None = None

    paths_affected: int = 0

    paths_removed: int | None = None
    risk_before: int | None = None
    risk_after: int | None = None
    risk_reduction: int | None = None
    risk_reduction_percent: float | None = None


class SimulationStateSummary(BaseModel):
    highest_risk: int
    attack_paths: int
    findings: int


class SimulationImpact(BaseModel):
    paths_removed: int
    removed_path_ids: list[str] = Field(
        default_factory=list
    )
    risk_reduction: int
    risk_reduction_percent: float


SIMULATION_NOTE = (
    "Simulation only. No cloud resources were "
    "modified. CloudGuard simulation is "
    "predictive analysis based on CloudGuard's "
    "security model; it does not guarantee "
    "that a remediation eliminates every "
    "real-world attack vector."
)


class SimulationResult(BaseModel):
    remediation_id: str
    action_type: RemediationActionType

    simulation_only: bool = True
    note: str = SIMULATION_NOTE

    before: SimulationStateSummary
    after: SimulationStateSummary
    impact: SimulationImpact
