"""
Explainable attack-path hops.

Every hop explanation is derived only from
information CloudGuard actually detected:

- the relationship type inferred from
  configuration,
- the relationship evidence recorded when the
  edge was created,
- the permissions observed on the edge,
- the asset types involved.

No exploit claims are made. A hop explains why a
security-relevant relationship exists, which
configuration is responsible for it, and what
that relationship enables.
"""

from pydantic import BaseModel

from cloudguard.models.assets import CloudAsset
from cloudguard.models.relationships import (
    Relationship,
    RelationshipType,
)


class AttackPathHop(BaseModel):
    """One explained step inside an attack path."""

    source: str
    target: str
    relationship_type: RelationshipType

    reason: str
    evidence: str | None = None
    configuration: str | None = None
    impact: str | None = None

    permissions: list[str] = []


def explain_hop(
    relationship: Relationship,
    source_asset: CloudAsset | None,
    target_asset: CloudAsset | None,
) -> AttackPathHop:
    target_name = (
        target_asset.name
        if target_asset is not None
        else relationship.target
    )

    reason = _reason(
        relationship,
        target_name,
    )

    return AttackPathHop(
        source=relationship.source,
        target=relationship.target,
        relationship_type=(
            relationship.relationship_type
        ),
        reason=reason,
        evidence=relationship.evidence,
        configuration=_configuration(
            relationship
        ),
        impact=_impact(
            relationship,
            target_name,
        ),
        permissions=list(
            relationship.permissions
        ),
    )


def explain_path_summary(
    source: str,
    target: str,
    hop_count: int,
    sensitive_target: bool,
) -> str:
    target_description = (
        "a resource classified as sensitive"
        if sensitive_target
        else "the target resource"
    )

    return (
        f"Internet-originated relationship chain "
        f"from {source} to {target} "
        f"({target_description}) across "
        f"{hop_count} hops."
    )


def _reason(
    relationship: Relationship,
    target_name: str,
) -> str:
    relationship_type = (
        relationship.relationship_type
    )

    if (
        relationship_type
        == RelationshipType.EXPOSED_TO
    ):
        return (
            "Security-group configuration allows "
            "public inbound traffic from the "
            "internet."
        )

    if relationship_type == (
        RelationshipType.ASSUMES
    ):
        return (
            "The workload is attached to IAM "
            f"role {target_name} through an "
            "instance profile."
        )

    if relationship_type in (
        RelationshipType.CAN_READ,
        RelationshipType.CAN_WRITE,
        RelationshipType.CAN_ACCESS,
    ):
        actions = ", ".join(
            relationship.permissions
        )

        return (
            "An IAM policy grants the identity "
            f"{actions} on this resource."
        )

    return (
        "A security-relevant relationship was "
        "detected between these resources."
    )


def _configuration(
    relationship: Relationship,
) -> str | None:
    """
    Describe the originating configuration.

    The evidence recorded at edge-creation time
    names the responsible configuration (the
    security-group rule, instance profile, or
    IAM policy). It is reused here rather than
    inventing a separate source of truth.
    """
    return relationship.evidence


def _impact(
    relationship: Relationship,
    target_name: str,
) -> str:
    relationship_type = (
        relationship.relationship_type
    )

    if (
        relationship_type
        == RelationshipType.EXPOSED_TO
    ):
        return (
            "Internet-originated traffic can "
            f"reach {target_name}, making it a "
            "potential entry point."
        )

    if relationship_type == (
        RelationshipType.ASSUMES
    ):
        return (
            f"Code running on this workload can "
            f"obtain temporary credentials for "
            f"{target_name}."
        )

    if relationship_type == (
        RelationshipType.CAN_READ
    ):
        return (
            f"The identity can read data from "
            f"{target_name}."
        )

    if relationship_type == (
        RelationshipType.CAN_WRITE
    ):
        return (
            f"The identity can modify or delete "
            f"data in {target_name}."
        )

    return (
        f"The identity can access "
        f"{target_name}."
    )
