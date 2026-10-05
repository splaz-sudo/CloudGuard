"""
Attack Path Engine 2.0

Enhanced graph-based attack path discovery with richer
evidence, confidence scoring, and path categorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import networkx as nx

from cloudguard.graph.attack_paths import (
    AttackPath,
    AttackPathEngine,
)
from cloudguard.graph.explanations import (
    AttackPathHop,
    explain_hop,
    explain_path_summary,
)
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.models.assets import CloudAsset
from cloudguard.models.relationships import Relationship, RelationshipType
from cloudguard.inference.privilege_escalation import (
    EscalationPath,
    find_privilege_escalation_paths,
)


class PathCategory(str, Enum):
    INTERNET_TO_WORKLOAD = "internet_to_workload"
    INTERNET_TO_LOAD_BALANCER = "internet_to_load_balancer"
    WORKLOAD_TO_IAM = "workload_to_iam"
    IAM_TO_SENSITIVE = "iam_to_sensitive"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CROSS_ACCOUNT = "cross_account"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class AttackPath2(AttackPath):
    """Enhanced attack path with categorization and confidence."""

    path_category: PathCategory = PathCategory.INTERNET_TO_WORKLOAD
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    assumptions: list[str] = field(default_factory=list)
    escalation_paths: list = field(default_factory=list)
    risk_contribution: int = 0
    remediation_opportunities: list[str] = field(default_factory=list)


@dataclass
class PathConstraint:
    """Constraints for path discovery."""
    max_depth: int = 8
    max_paths_per_target: int = 50
    max_total_paths: int = 500
    require_sensitive_target: bool = True
    exclude_categories: set[PathCategory] = field(default_factory=set)


class AttackPathEngine2:
    """
    Enhanced attack path engine with categorization, confidence,
    and privilege escalation integration.
    """

    def __init__(
        self,
        security_graph: SecurityGraph,
        constraint: PathConstraint | None = None,
    ) -> None:
        self.security_graph = security_graph
        self.constraint = constraint or PathConstraint()
        self.base_engine = AttackPathEngine(security_graph)

    def find_paths_to_sensitive_assets(
        self,
        source: str = "internet",
        assets: list[CloudAsset] | None = None,
        escalation_paths: list = None,
    ) -> list[AttackPath2]:
        """
        Discover attack paths from source to sensitive assets.

        Enhanced with categorization, confidence scoring,
        and privilege escalation integration.
        """
        if assets is None:
            assets = []

        # Find sensitive assets
        sensitive_assets = [
            asset for asset in assets
            if asset.sensitive
        ]

        if not sensitive_assets:
            return []

        all_paths: list[AttackPath2] = []

        for target_asset in sensitive_assets:
            # Skip if internet is the target
            if target_asset.id == "internet":
                continue

            # Check if path exists
            if not nx.has_path(
                self.security_graph.graph,
                source,
                target_asset.id,
            ):
                continue

            # Find paths
            raw_paths = nx.all_simple_paths(
                self.security_graph.graph,
                source=source,
                target=target_asset.id,
                cutoff=self.constraint.max_depth,
            )

            paths_found = 0
            for node_path in raw_paths:
                if paths_found >= self.constraint.max_paths_per_target:
                    break

                relationships = self._get_relationships(node_path)
                if not relationships:
                    continue

                # Categorize the path
                category = self._categorize_path(node_path, relationships)
                if category in self.constraint.exclude_categories:
                    continue

                # Calculate confidence
                confidence = self._calculate_confidence(node_path, relationships)

                # Generate assumptions
                assumptions = self._identify_assumptions(node_path, relationships)

                # Calculate risk contribution
                risk_contribution = self._calculate_risk_contribution(
                    node_path, relationships
                )

                # Identify remediation opportunities
                remediation_opportunities = self._identify_remediation_opportunities(
                    node_path, relationships
                )

                # Build enhanced path
                enhanced_path = AttackPath2(
                    source=source,
                    target=target_asset.id,
                    nodes=node_path,
                    hop_count=len(node_path) - 1,
                    sensitive_target=True,
                    relationships=relationships,
                    path_id=self._generate_path_id(node_path),
                    severity=self._severity_from_risk(risk_contribution),
                    risk_score=risk_contribution,
                    hops=self._explain_hops(node_path, relationships),
                    explanation=explain_path_summary(
                        source, target_asset.id, len(node_path) - 1, True
                    ),
                    path_category=category,
                    confidence=confidence,
                    assumptions=assumptions,
                    risk_contribution=risk_contribution,
                    remediation_opportunities=remediation_opportunities,
                )

                # Add relevant escalation paths
                if escalation_paths:
                    relevant_escalations = self._find_relevant_escalations(
                        enhanced_path, escalation_paths
                    )
                    enhanced_path.escalation_paths = relevant_escalations

                all_paths.append(enhanced_path)
                paths_found += 1

        # Sort by risk contribution (descending), then confidence
        all_paths.sort(
            key=lambda p: (
                -p.risk_contribution,
                -self._confidence_rank(p.confidence),
            )
        )

        return all_paths

    def _get_relationships(self, node_path: list[str]) -> list[Relationship]:
        """Extract relationships for a node path."""
        relationships = []
        for i in range(len(node_path) - 1):
            rel = self.security_graph.get_relationship(
                node_path[i],
                node_path[i + 1],
            )
            if rel:
                relationships.append(rel)
        return relationships

    def _categorize_path(
        self,
        node_path: list[str],
        relationships: list[Relationship],
    ) -> PathCategory:
        """Categorize an attack path based on its structure."""
        if not relationships:
            return PathCategory.INTERNET_TO_WORKLOAD

        first_rel = relationships[0]
        last_rel = relationships[-1]

        # Check for privilege escalation
        for rel in relationships:
            if rel.relationship_type in {
                RelationshipType.CAN_WRITE,
                RelationshipType.CAN_READ,
            }:
                # Check if this involves IAM privilege escalation
                pass

        # Check for cross-account
        for node in node_path:
            if "arn:aws:iam::" in node and ":role/" in node:
                # Could be cross-account
                pass

        # Simple categorization based on first and last relationship
        if first_rel.relationship_type == RelationshipType.EXPOSED_TO:
            # Starts with Internet exposure
            if any(r.relationship_type == RelationshipType.ASSUMES for r in relationships):
                return PathCategory.INTERNET_TO_WORKLOAD

        if first_rel.relationship_type == RelationshipType.EXPOSED_TO:
            if any(r.relationship_type in {
                RelationshipType.CAN_READ,
                RelationshipType.CAN_WRITE,
            } for r in relationships):
                return PathCategory.IAM_TO_SENSITIVE

        # Check for load balancer exposure
        for rel in relationships:
            if "load_balancer" in rel.target.lower() or \
               "load_balancer" in rel.source.lower():
                return PathCategory.INTERNET_TO_LOAD_BALANCER

        # Check for privilege escalation
        for rel in relationships:
            if rel.relationship_type in {
                RelationshipType.CAN_WRITE,
                RelationshipType.CAN_READ,
            } and "iam:" in str(rel.permissions):
                return PathCategory.PRIVILEGE_ESCALATION

        # Default
        return PathCategory.INTERNET_TO_WORKLOAD

    def _calculate_confidence(
        self,
        node_path: list[str],
        relationships: list[Relationship],
    ) -> ConfidenceLevel:
        """Calculate confidence level for an attack path."""
        confidence_factors = []

        # Factor 1: Direct evidence for each hop
        for rel in relationships:
            if rel.evidence and len(rel.evidence) > 20:
                confidence_factors.append("detailed_evidence")
            else:
                confidence_factors.append("limited_evidence")

        # Factor 2: Path length
        if len(relationships) <= 3:
            confidence_factors.append("short_path")
        elif len(relationships) <= 5:
            confidence_factors.append("medium_path")
        else:
            confidence_factors.append("long_path")

        # Factor 3: Direct Internet exposure
        has_direct_exposure = any(
            r.relationship_type == RelationshipType.EXPOSED_TO
            for r in relationships
        )
        if has_direct_exposure:
            confidence_factors.append("direct_exposure")

        # Factor 4: Privilege escalation
        has_escalation = any(
            "iam:" in str(p).lower() for r in relationships for p in r.permissions
        )
        if has_escalation:
            confidence_factors.append("privilege_escalation")

        # Score the confidence
        high_indicators = {
            "detailed_evidence", "short_path", "direct_exposure", "privilege_escalation"
        }
        low_indicators = {"limited_evidence", "long_path"}

        high_count = sum(1 for f in confidence_factors if f in high_indicators)
        low_count = sum(1 for f in confidence_factors if f in low_indicators)

        if high_count >= 2 and low_count == 0:
            return ConfidenceLevel.HIGH
        elif high_count >= 1 or low_count == 0:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

    def _identify_assumptions(
        self,
        node_path: list[str],
        relationships: list[Relationship],
    ) -> list[str]:
        """Identify assumptions made in the attack path."""
        assumptions = []

        for rel in relationships:
            if not rel.evidence or len(rel.evidence) < 10:
                assumptions.append(
                    f"Limited evidence for {rel.source} -> {rel.target}: "
                    f"{rel.relationship_type.value}"
                )

            if rel.relationship_type in {RelationshipType.CAN_READ, RelationshipType.CAN_WRITE}:
                if not rel.permissions:
                    assumptions.append(
                        f"IAM permission {rel.relationship_type.value} inferred "
                        f"without explicit permission evidence"
                    )

            if "condition" in str(rel.evidence).lower() or \
               "condition" in str(rel.permissions).lower():
                assumptions.append(
                    f"IAM conditions on {rel.source} -> {rel.target} not fully evaluated"
                )

        # Check for permissions boundary
        assumptions.append("Permissions boundaries not evaluated")
        assumptions.append("SCPs not evaluated")
        assumptions.append("Resource policies not evaluated")

        return assumptions

    def _calculate_risk_contribution(
        self,
        node_path: list[str],
        relationships: list[Relationship],
    ) -> int:
        """Calculate risk contribution of this attack path."""
        base_risk = 50

        # Adjust for path length
        if len(relationships) <= 2:
            base_risk += 20
        elif len(relationships) <= 4:
            base_risk += 10

        # Adjust for sensitive target
        # (The target is already known to be sensitive)

        # Adjust for privilege escalation
        if any("iam:" in str(p).lower() for r in relationships for p in r.permissions):
            base_risk += 15

        # Adjust for direct Internet exposure
        if any(r.relationship_type == RelationshipType.EXPOSED_TO for r in relationships):
            base_risk += 10

        return min(base_risk, 100)

    def _identify_remediation_opportunities(
        self,
        node_path: list[str],
        relationships: list[Relationship],
    ) -> list[str]:
        """Identify remediation opportunities for this path."""
        opportunities = []

        for rel in relationships:
            if rel.relationship_type == RelationshipType.EXPOSED_TO:
                opportunities.append(
                    f"Restrict security group ingress for {rel.target}"
                )
            elif rel.relationship_type == RelationshipType.ASSUMES:
                opportunities.append(
                    f"Review instance profile attachment for {rel.source}"
                )
            elif rel.relationship_type in {RelationshipType.CAN_READ, RelationshipType.CAN_WRITE}:
                opportunities.append(
                    f"Narrow IAM permissions: {', '.join(rel.permissions)} on {rel.target}"
                )

        return opportunities

    def _find_relevant_escalations(
        self,
        path: AttackPath2,
        escalation_paths: list,
    ) -> list:
        """Find privilege escalation paths relevant to this attack path."""
        relevant = []

        path_nodes = set(path.nodes)
        path_permissions = set()
        for rel in path.relationships:
            path_permissions.update(rel.permissions)

        for esc in escalation_paths:
            if esc.principal_id in path_nodes:
                relevant.append(esc)
            elif any(perm in path_permissions for perm in esc.satisfied_prerequisites):
                relevant.append(esc)

        return relevant

    def _explain_hops(
        self,
        node_path: list[str],
        relationships: list[Relationship],
    ) -> list[AttackPathHop]:
        """Generate hop explanations for the path."""
        hops = []
        for i, rel in enumerate(relationships):
            source_asset = self.security_graph.get_asset(node_path[i])
            target_asset = self.security_graph.get_asset(node_path[i + 1])
            hops.append(explain_hop(rel, source_asset, target_asset))
        return hops

    def _generate_path_id(self, node_path: list[str]) -> str:
        """Generate a stable path ID."""
        import hashlib
        digest = hashlib.sha1(
            ">".join(node_path).encode("utf-8")
        ).hexdigest()
        return f"PATH2-{digest[:12]}"

    def _severity_from_risk(self, risk: int) -> str:
        if risk >= 90:
            return "CRITICAL"
        elif risk >= 70:
            return "HIGH"
        elif risk >= 40:
            return "MEDIUM"
        elif risk > 0:
            return "LOW"
        return "INFO"

    def _confidence_rank(self, confidence: ConfidenceLevel) -> int:
        return {
            ConfidenceLevel.HIGH: 3,
            ConfidenceLevel.MEDIUM: 2,
            ConfidenceLevel.LOW: 1,
            ConfidenceLevel.UNKNOWN: 0,
        }.get(confidence, 0)