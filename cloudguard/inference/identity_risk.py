from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloudguard.findings.scoring import (
    severity_from_score,
)


IDENTITY_TYPES = {
    "iam_role",
    "iam_user",
}


@dataclass
class IdentityRisk:
    identity_id: str
    identity_name: str
    identity_type: str

    risk_score: int
    severity: str

    permissions: list[str] = field(
        default_factory=list
    )

    connected_assets: list[str] = field(
        default_factory=list
    )

    exposed_workloads: list[str] = field(
        default_factory=list
    )

    sensitive_resources: list[str] = field(
        default_factory=list
    )

    attack_paths: list[list[str]] = field(
        default_factory=list
    )

    risk_factors: list[str] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "identity_name": (
                self.identity_name
            ),
            "identity_type": (
                self.identity_type
            ),
            "risk_score": self.risk_score,
            "severity": self.severity,
            "permissions": sorted(
                set(self.permissions)
            ),
            "connected_assets": sorted(
                set(self.connected_assets)
            ),
            "exposed_workloads": sorted(
                set(self.exposed_workloads)
            ),
            "sensitive_resources": sorted(
                set(self.sensitive_resources)
            ),
            "attack_paths": (
                self.attack_paths
            ),
            "risk_factors": (
                self.risk_factors
            ),
            "metadata": self.metadata,
        }


def calculate_identity_risk(
    *,
    identity_id: str,
    identity_name: str,
    identity_type: str,
    permissions: list[str],
    connected_assets: list[str],
    exposed_workloads: list[str],
    sensitive_resources: list[str],
    attack_paths: list[list[str]],
    metadata: dict[str, Any] | None = None,
) -> IdentityRisk:
    """
    Calculate contextual identity risk.

    The score represents CloudGuard's local
    correlation model. It is not an AWS-native
    risk score and does not claim to represent
    complete effective IAM permissions.
    """

    score = 0
    risk_factors: list[str] = []

    unique_permissions = set(
        permissions
    )

    unique_exposed = set(
        exposed_workloads
    )

    unique_sensitive = set(
        sensitive_resources
    )

    if unique_permissions:
        score += 10

        risk_factors.append(
            "Identity has observed cloud "
            "permissions."
        )

    if unique_exposed:
        score += 30

        risk_factors.append(
            "Identity is associated with an "
            "internet-exposed workload."
        )

    if unique_sensitive:
        score += 30

        risk_factors.append(
            "Identity can reach a resource "
            "classified as sensitive."
        )

    if attack_paths:
        score += 25

        risk_factors.append(
            "Identity participates in a "
            "discovered attack path."
        )

    if _has_broad_permissions(
        unique_permissions
    ):
        score += 20

        risk_factors.append(
            "Observed permissions include "
            "a broad or wildcard action."
        )

    score = min(score, 100)

    severity = severity_from_score(score).lower()

    return IdentityRisk(
        identity_id=identity_id,
        identity_name=identity_name,
        identity_type=identity_type,
        risk_score=score,
        severity=severity,
        permissions=list(
            unique_permissions
        ),
        connected_assets=(
            connected_assets
        ),
        exposed_workloads=list(
            unique_exposed
        ),
        sensitive_resources=list(
            unique_sensitive
        ),
        attack_paths=attack_paths,
        risk_factors=risk_factors,
        metadata=metadata or {},
    )


def _has_broad_permissions(
    permissions: set[str],
) -> bool:
    broad_actions = {
        "*",
        "*:*",
    }

    for permission in permissions:
        normalized = (
            permission
            .strip()
            .lower()
        )

        if normalized in broad_actions:
            return True

        if normalized.endswith(":*"):
            return True

    return False
