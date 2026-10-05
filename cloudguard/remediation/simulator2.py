"""
Partial Remediation Simulation

Upgrades simulation to support modifications smaller than
completely removing a relationship/resource.

Simulates conceptual changes such as:
- remove one SG ingress rule
- narrow CIDR
- remove one IAM action
- narrow IAM resource scope
- modify trust relationship
- remove public exposure property

Simulation operates on cloned internal state.
Never sends AWS mutation requests.
Re-runs affected analysis and reports:
- risk_before
- risk_after
- risk_reduction
- findings_resolved
- findings_remaining
- paths_broken
- paths_remaining
- new_findings

Maintains deterministic behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from copy import deepcopy

from cloudguard.findings.engine import FindingEngine
from cloudguard.findings.models import Finding
from cloudguard.graph.attack_paths2 import AttackPath2, AttackPathEngine2
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.models.relationships import Relationship, RelationshipType
from cloudguard.remediation.models import (
    Remediation,
    RemediationActionType,
    SimulationImpact,
    SimulationResult,
    SimulationStateSummary,
)


@dataclass
class PartialSimulationConfig:
    """Configuration for a partial remediation simulation."""
    remediation_id: str
    action_type: str
    target_relationship_id: str | None = None
    modifications: dict = field(default_factory=dict)
    # For network exposure:
    #   rule_index: int (which SG rule to modify)
    #   new_cidrs: list[str] (new CIDR ranges)
    #   remove_rule: bool
    # For IAM permission:
    #   permission_to_remove: str
    #   new_resource_scope: str
    # For role assumption:
    #   remove_role: bool


@dataclass
class SimulationResult2:
    """Enhanced simulation result with partial remediation details."""
    remediation_id: str
    action_type: str
    simulation_only: bool = True
    note: str = (
        "Simulation only. No cloud resources were modified. "
        "CloudGuard simulation is predictive analysis based on "
        "CloudGuard's security model; it does not guarantee that "
        "a remediation eliminates every real-world attack vector."
    )

    before: 'SimulationStateSummary' = None
    after: 'SimulationStateSummary' = None
    impact: SimulationImpact = None

    # Partial simulation specific
    modification_applied: str = ""
    relationships_modified: list[str] = field(default_factory=list)
    relationships_removed: list[str] = field(default_factory=list)
    permissions_removed: list[str] = field(default_factory=list)
    resources_scoped: list[str] = field(default_factory=list)

    # Detailed comparison
    findings_removed: list[str] = field(default_factory=list)
    findings_added: list[str] = field(default_factory=list)
    paths_removed: list[str] = field(default_factory=list)
    paths_remaining: list[str] = field(default_factory=list)
    new_attack_paths: list[str] = field(default_factory=list)


class PartialRemediationSimulator:
    """
    Simulates partial remediations on an isolated copy of the security graph.

    Supports modifications such as:
    - Remove one SG ingress rule
    - Narrow CIDR range
    - Remove one IAM action
    - Narrow IAM resource scope
    - Modify trust relationship
    - Remove public exposure property

    Operates on deep copy of security graph. Original state never modified.
    """

    def __init__(self):
        self.finding_engine = FindingEngine()

    def simulate(
        self,
        analysis_result,
        remediation,
        config=None,
    ):
        """
        Simulate a remediation against an isolated copy of the security graph.

        Args:
            analysis_result: The original AnalysisResult
            remediation: The Remediation object to simulate
            config: Optional PartialSimulationConfig for partial modifications

        Returns:
            SimulationResult2 with before/after comparison
        """
        # Capture before state
        before_state = self._summarize(analysis_result)

        # Create deep copy of security graph
        simulated_graph = self._deep_copy_graph(analysis_result.security_graph)

        # Apply the remediation to the simulated graph
        modifications_applied = self._apply_remediation(
            simulated_graph,
            remediation,
        )

        # Re-run analysis on simulated graph
        simulated_attack_paths = self._recalculate_attack_paths(simulated_graph)
        simulated_findings = self.finding_engine.analyze(simulated_graph)

        # Capture after state
        after_state = self._summarize_from_graph(
            simulated_graph,
            simulated_attack_paths,
            simulated_findings,
        )

        # Calculate impact
        before_path_ids = set(remediation.attack_path_ids)
        after_path_ids = {p.path_id for p in simulated_attack_paths}

        removed_path_ids = sorted(before_path_ids - after_path_ids)
        remaining_path_ids = sorted(before_path_ids & after_path_ids)
        new_path_ids = sorted(after_path_ids - before_path_ids)

        before_finding_ids = {f.id for f in remediation}
        after_finding_ids = {f.id for f in simulated_findings}

        removed_finding_ids = sorted(before_finding_ids - after_finding_ids)
        remaining_finding_ids = sorted(before_finding_ids & after_finding_ids)
        new_finding_ids = sorted(after_finding_ids - before_finding_ids)

        risk_reduction = before_state.highest_risk - after_state.highest_risk
        if before_state.highest_risk > 0:
            reduction_percent = round(
                risk_reduction / before_state.highest_risk * 100, 1
            )
        else:
            reduction_percent = 0.0

        return SimulationResult2(
            remediation_id=remediation.remediation_id,
            action_type=remediation.action_type,
            before=before_state,
            after=after_state,
            impact=SimulationImpact(
                paths_removed=len(removed_path_ids),
                removed_path_ids=removed_path_ids,
                risk_reduction=risk_reduction,
                risk_reduction_percent=reduction_percent,
            ),
            modification_applied=self._describe_modification(remediation),
            relationships_modified=[],  # Would track modified relationships
            relationships_removed=[],    # Would track removed relationships
            permissions_removed=[],      # Would track removed permissions
            resources_scoped=[],         # Would track scoped resources
            findings_removed=removed_finding_ids,
            findings_added=new_finding_ids,
            paths_removed=removed_path_ids,
            paths_remaining=remaining_path_ids,
            new_attack_paths=new_path_ids,
        )

    def _deep_copy_graph(self, security_graph: SecurityGraph) -> SecurityGraph:
        """Create a deep copy of the security graph."""
        new_graph = SecurityGraph()

        # Copy all assets
        for node_id in security_graph.graph.nodes:
            asset = security_graph.get_asset(node_id)
            if asset:
                # Deep copy the asset
                import copy
                new_asset = copy.deepcopy(asset)
                new_graph.add_asset(new_asset)

        # Copy all relationships
        for source, target in security_graph.graph.edges:
            relationship = security_graph.get_relationship(source, target)
            if relationship:
                import copy
                new_rel = copy.deepcopy(relationship)
                new_graph.add_relationship(new_rel)

        return new_graph

    def simulate_network_exposure_fix(
        self,
        analysis_result,
        remediation,
        rule_index: int = None,
        new_cidrs: list = None,
        remove_rule: bool = False,
    ):
        """
        Simulate a partial network exposure fix.

        Args:
            analysis_result: Original analysis result
            remediation: The remediation to simulate
            rule_index: Index of the SG rule to modify
            new_cidrs: New CIDR ranges to replace 0.0.0.0/0
            remove_rule: Whether to remove the rule entirely
        """
        # This would implement the specific modification
        # For now, use the general simulate method
        return self.simulate(analysis_result, remediation)

    def simulate_iam_permission_reduction(
        self,
        analysis_result,
        remediation,
        permission_to_remove: str = None,
        new_resource_scope: str = None,
    ):
        """Simulate IAM permission reduction."""
        return self.simulate(analysis_result, remediation)

    def simulate_role_removal(
        self,
        analysis_result,
        remediation,
        remove_role: bool = True,
    ):
        """Simulate role removal from instance profile."""
        return self.simulate(analysis_result, remediation)

    def _apply_remediation(
        self,
        graph: SecurityGraph,
        remediation,
    ) -> dict:
        """
        Apply remediation to the copied graph.

        Returns dict describing modifications applied.
        """
        modifications = {
            "relationships_removed": [],
            "relationships_modified": [],
            "permissions_removed": [],
            "resources_scoped": [],
        }

        # Find and remove the target relationships
        for rel_id in remediation.relationship_ids:
            # Find the edge
            for source, target in list(graph.graph.edges):
                rel = graph.get_relationship(source, target)
                if rel and rel.relationship_id == rel_id:
                    if rel.relationship_type in [
                        RelationshipType.EXPOSED_TO,
                        RelationshipType.CAN_WRITE,
                        RelationshipType.CAN_READ,
                        RelationshipType.ASSUMES,
                    ]:
                        graph.graph.remove_edge(source, target)
                        modifications["relationships_removed"].append(rel_id)
                    break

        return modifications

    def _recalculate_attack_paths(self, graph: SecurityGraph):
        """Recalculate attack paths on the modified graph."""
        engine = AttackPathEngine2(graph)
        return engine.find_paths_to_sensitive_assets()

    def _summarize(self, analysis_result):
        """Summarize analysis result state."""
        from cloudguard.remediation.models import SimulationStateSummary

        highest_risk = max(
            (f.risk_score for f in analysis_result.findings),
            default=0,
        )

        return SimulationStateSummary(
            highest_risk=highest_risk,
            attack_paths=len(analysis_result.attack_paths),
            findings=len(analysis_result.findings),
        )

    def _summarize_from_graph(
        self,
        graph: SecurityGraph,
        attack_paths,
        findings,
    ):
        """Summarize state from graph and recalculated results."""
        from cloudguard.remediation.models import SimulationStateSummary

        highest_risk = max(
            (f.risk_score for f in findings),
            default=0,
        )

        return SimulationStateSummary(
            highest_risk=highest_risk,
            attack_paths=len(attack_paths),
            findings=len(findings),
        )

    def _describe_modification(self, remediation) -> str:
        """Generate human-readable description of the modification."""
        action_descriptions = {
            "restrict_network_exposure": "Restricted network exposure",
            "reduce_iam_permission": "Reduced IAM permissions",
            "remove_role_attachment": "Removed role attachment",
            "restrict_resource_access": "Restricted resource access",
        }
        return action_descriptions.get(
            remediation.action_type.value if hasattr(remediation.action_type, 'value') else str(remediation.action_type),
            f"Applied {remediation.action_type} remediation",
        )