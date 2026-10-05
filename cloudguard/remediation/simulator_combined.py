"""
Combined Remediation Simulation

Allows simulation of multiple proposed remediations together.

Example:
    Fix A + Fix B + Fix C

Calculates:
    - Combined paths removed
    - Remaining paths
    - Risk before/after
    - Net reduction
    - Overlapping effects (benefits not simply summed)

Deterministic results. Stored scans remain immutable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from copy import deepcopy
from itertools import combinations

from cloudguard.findings.engine import FindingEngine
from cloudguard.graph.attack_paths2 import AttackPathEngine2
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.remediation.models import (
    Remediation,
    SimulationImpact,
    SimulationResult,
    SimulationStateSummary,
)
from cloudguard.remediation.simulator2 import PartialRemediationSimulator
from cloudguard.remediation.engine2 import RemediationEngine2
from cloudguard.services.analysis import AnalysisResult


@dataclass
class CombinedSimulationConfig:
    """Configuration for combined remediation simulation."""
    remediation_ids: list[str]
    # Whether to simulate all combinations or just the full set
    simulate_all_combinations: bool = False
    # Max number of remediations to combine (prevent combinatorial explosion)
    max_combination_size: int = 5


@dataclass
class CombinedSimulationResult:
    """Result of simulating multiple remediations together."""
    remediation_ids: list[str]
    individual_results: dict[str, 'SimulationResult2']
    combined_result: 'SimulationResult2'
    combination_analysis: dict = field(default_factory=dict)
    # Overlap analysis
    overlap_analysis: dict = field(default_factory=dict)
    # Ranking
    ranked_by_effectiveness: list[tuple[str, float]] = field(default_factory=list)


class CombinedRemediationSimulator:
    """
    Simulates multiple remediations together to calculate
    combined effect with proper overlap handling.
    """

    def __init__(self):
        self.single_simulator = PartialRemediationSimulator()
        self.remediation_engine = RemediationEngine2()

    def simulate_combined(
        self,
        analysis_result: AnalysisResult,
        remediation_ids: list[str],
        simulate_all_combinations: bool = False,
        max_combination_size: int = 5,
    ) -> CombinedSimulationResult:
        """
        Simulate multiple remediations together.

        Args:
            analysis_result: The analysis result to simulate against
            remediation_ids: List of remediation IDs to combine
            simulate_all_combinations: Whether to simulate all subsets
            max_combination_size: Maximum size of combination

        Returns:
            CombinedSimulationResult with individual and combined results
        """
        # First, get all remediation objects
        all_remediations = self.remediation_engine.generate(analysis_result)
        remediation_map = {r.remediation_id: r for r in all_remediations}

        # Filter to requested remediations
        selected_remediations = [
            remediation_map[rid]
            for rid in remediation_ids
            if rid in remediation_map
        ]

        if not selected_remediations:
            return CombinedSimulationResult(
                remediation_ids=remediation_ids,
                individual_results={},
                combined_result=None,
            )

        # Simulate individual remediations
        individual_results = {}
        for remediation in selected_remediations:
            result = self.single_simulator.simulate(
                analysis_result, remediation
            )
            individual_results[remediation.remediation_id] = result

        # Simulate combined remediation
        combined_result = self._simulate_combined(
            analysis_result,
            selected_remediations,
        )

        # Analyze overlap
        overlap_analysis = self._analyze_overlap(
            individual_results, combined_result
        )

        # Rank by effectiveness
        ranked = self._rank_combinations(
            individual_results, combined_result
        )

        return CombinedSimulationResult(
            remediation_ids=remediation_ids,
            individual_results=individual_results,
            combined_result=combined_result,
            overlap_analysis=overlap_analysis,
            ranked_by_effectiveness=ranked,
        )

    def simulate_all_combinations(
        self,
        analysis_result: AnalysisResult,
        remediation_ids: list[str],
        max_combination_size: int = 5,
    ) -> list[CombinedSimulationResult]:
        """
        Simulate all combinations of remediations up to max size.

        Useful for finding the optimal combination.
        """
        results = []

        # Generate all combinations up to max size
        for size in range(1, min(max_combination_size, len(remediation_ids)) + 1):
            for combo in combinations(remediation_ids, size):
                result = self.simulate_combined(
                    analysis_result,
                    list(combo),
                    simulate_all_combinations=False,
                )
                results.append(result)

        # Sort by total risk reduction (descending)
        results.sort(
            key=lambda r: r.combined_result.impact.risk_reduction
            if r.combined_result else 0,
            reverse=True,
        )

        return results

    def _simulate_combined(
        self,
        analysis_result: AnalysisResult,
        remediations: list[Remediation],
    ):
        """
        Apply multiple remediations to a single graph copy
        and recalculate.
        """
        # Get before state
        before_state = self._summarize(analysis_result)

        # Deep copy the graph
        simulated_graph = self._deep_copy_graph(analysis_result.security_graph)

        # Apply all remediations to the same graph copy
        all_modifications = {
            "relationships_removed": [],
            "relationships_modified": [],
            "permissions_removed": [],
            "resources_scoped": [],
        }

        for remediation in remediations:
            mods = self._apply_single_remediation(
                simulated_graph, remediation
            )
            for key in all_modifications:
                all_modifications[key].extend(mods.get(key, []))

        # Recalculate
        simulated_attack_paths = self._recalculate_attack_paths(simulated_graph)
        simulated_findings = FindingEngine().analyze(simulated_graph)

        after_state = self._summarize_from_graph(
            simulated_graph, simulated_attack_paths, simulated_findings
        )

        # Calculate combined impact
        before_path_ids = set()
        for r in remediations:
            before_path_ids.update(r.attack_path_ids)

        after_path_ids = {p.path_id for p in simulated_attack_paths}
        removed_path_ids = sorted(before_path_ids - after_path_ids)
        remaining_path_ids = sorted(before_path_ids & after_path_ids)
        new_path_ids = sorted(after_path_ids - before_path_ids)

        before_finding_ids = set()
        for r in remediations:
            before_finding_ids.update(r.finding_ids)

        after_finding_ids = {f.id for f in simulated_findings}
        removed_finding_ids = sorted(before_finding_ids - after_finding_ids)
        new_finding_ids = sorted(after_finding_ids - before_finding_ids)

        risk_reduction = before_state.highest_risk - after_state.highest_risk
        if before_state.highest_risk > 0:
            reduction_percent = round(
                risk_reduction / before_state.highest_risk * 100, 1
            )
        else:
            reduction_percent = 0.0

        # Create a combined remediation ID
        combined_id = "COMBINED-" + "-".join(
            sorted(r.remediation_id for r in remediations)
        )[:50]

        return SimulationResult(
            remediation_id=combined_id,
            action_type=remediations[0].action_type,
            simulation_only=True,
            note=(
                "Combined simulation only. No cloud resources were modified. "
                "CloudGuard simulation is predictive analysis based on "
                "CloudGuard's security model; it does not guarantee that "
                "a remediation eliminates every real-world attack vector."
            ),
            before=before_state,
            after=after_state,
            impact=SimulationImpact(
                paths_removed=len(removed_path_ids),
                removed_path_ids=removed_path_ids,
                risk_reduction=risk_reduction,
                risk_reduction_percent=reduction_percent,
            ),
        )

    def _analyze_overlap(
        self,
        individual_results: dict,
        combined_result,
    ) -> dict:
        """Analyze overlap between individual and combined effects."""
        # Sum of individual risk reductions
        individual_risk_sum = sum(
            r.impact.risk_reduction for r in individual_results.values()
        )

        combined_risk = combined_result.impact.risk_reduction if combined_result else 0

        # Calculate overlap (double-counted benefit)
        overlap = individual_risk_sum - combined_risk

        # Path overlap
        individual_paths = set()
        for r in individual_results.values():
            individual_paths.update(r.impact.removed_path_ids)

        combined_paths = set(
            combined_result.impact.removed_path_ids
        ) if combined_result else set()

        path_overlap = len(individual_paths) - len(combined_paths)

        return {
            "individual_risk_sum": individual_risk_sum,
            "combined_risk": combined_risk,
            "risk_overlap": overlap,
            "risk_overlap_percent": round(
                overlap / individual_risk_sum * 100, 1
            ) if individual_risk_sum > 0 else 0,
            "individual_paths_removed": len(individual_paths),
            "combined_paths_removed": len(combined_paths),
            "path_overlap": path_overlap,
            "synergistic": combined_risk > individual_risk_sum,
        }

    def _rank_combinations(
        self,
        individual_results: dict,
        combined_result,
    ) -> list[tuple[str, float]]:
        """Rank remediation combinations by effectiveness."""
        # For now, just return individual remediations ranked by risk reduction
        ranked = []
        for rid, result in individual_results.items():
            ranked.append((
                rid,
                result.impact.risk_reduction,
            ))
        ranked.sort(key=lambda x: -x[1])
        return ranked

    def _deep_copy_graph(self, security_graph: SecurityGraph) -> SecurityGraph:
        """Create a deep copy of the security graph."""
        new_graph = SecurityGraph()
        for node_id in security_graph.graph.nodes:
            asset = security_graph.get_asset(node_id)
            if asset:
                new_graph.add_asset(deepcopy(asset))
        for source, target in security_graph.graph.edges:
            relationship = security_graph.get_relationship(source, target)
            if relationship:
                new_graph.add_relationship(deepcopy(relationship))
        return new_graph

    def _apply_all_remediations(self, graph: SecurityGraph, remediations: list):
        """Apply all remediations to the graph."""
        for remediation in remediations:
            self._apply_single_remediation(graph, remediation)

    def _apply_single_remediation(self, graph: SecurityGraph, remediation):
        """Apply a single remediation to the graph."""
        modifications = {
            "relationships_removed": [],
            "relationships_modified": [],
            "permissions_removed": [],
            "resources_scoped": [],
        }

        for rel_id in remediation.relationship_ids:
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

    def _summarize_from_graph(self, graph, attack_paths, findings):
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