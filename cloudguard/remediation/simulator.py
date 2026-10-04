import copy

from cloudguard.findings.engine import FindingEngine
from cloudguard.findings.models import Finding
from cloudguard.graph.attack_paths import (
    AttackPath,
    AttackPathEngine,
)
from cloudguard.graph.security_graph import (
    SecurityGraph,
)
from cloudguard.remediation.models import (
    Remediation,
    SimulationImpact,
    SimulationResult,
    SimulationStateSummary,
)
from cloudguard.services.analysis import (
    AnalysisResult,
)


class RemediationSimulator:
    """
    Evaluates the predicted impact of a
    remediation against an isolated, in-memory
    deep copy of the security graph.

    The virtual remediation removes the
    relationship(s) the remediation targets
    (for example the internet-exposure edge, or
    an excessive IAM permission edge). Attack
    paths and findings are then recalculated on
    the copy.

    The original analysis state is never
    mutated, no AWS API calls are made, and
    nothing is persisted.
    """

    def simulate(
        self,
        analysis_result: AnalysisResult,
        remediation: Remediation,
    ) -> SimulationResult:

        before = self._summarize(
            analysis_result.attack_paths,
            analysis_result.findings,
        )

        before_path_ids = {
            path.path_id
            for path in (
                analysis_result.attack_paths
            )
        }

        simulated_graph = self._apply_virtual_remediation(
            analysis_result.security_graph,
            remediation,
        )

        simulated_paths = (
            AttackPathEngine(
                simulated_graph
            ).find_paths_to_sensitive_assets()
        )

        simulated_findings = (
            FindingEngine().analyze(
                simulated_graph
            )
        )

        after = self._summarize(
            simulated_paths,
            simulated_findings,
        )

        after_path_ids = {
            path.path_id
            for path in simulated_paths
        }

        removed_path_ids = sorted(
            before_path_ids - after_path_ids
        )

        risk_reduction = (
            before.highest_risk
            - after.highest_risk
        )

        if before.highest_risk > 0:
            reduction_percent = round(
                risk_reduction
                / before.highest_risk
                * 100,
                1,
            )
        else:
            reduction_percent = 0.0

        return SimulationResult(
            remediation_id=(
                remediation.remediation_id
            ),
            action_type=(
                remediation.action_type
            ),
            before=before,
            after=after,
            impact=SimulationImpact(
                paths_removed=len(
                    removed_path_ids
                ),
                removed_path_ids=(
                    removed_path_ids
                ),
                risk_reduction=(
                    risk_reduction
                ),
                risk_reduction_percent=(
                    reduction_percent
                ),
            ),
        )

    def _apply_virtual_remediation(
        self,
        security_graph: SecurityGraph,
        remediation: Remediation,
    ) -> SecurityGraph:
        """
        Return a deep copy of the graph with the
        remediation's target relationships
        removed. The original graph is not
        touched.
        """

        simulated_graph = copy.deepcopy(
            security_graph
        )

        target_ids = set(
            remediation.relationship_ids
        )

        edges_to_remove = []

        for source, target in (
            simulated_graph.graph.edges
        ):
            relationship = (
                simulated_graph
                .get_relationship(
                    source,
                    target,
                )
            )

            if relationship is None:
                continue

            if (
                relationship.relationship_id
                in target_ids
            ):
                edges_to_remove.append(
                    (source, target)
                )

        for source, target in edges_to_remove:
            simulated_graph.graph.remove_edge(
                source,
                target,
            )

        return simulated_graph

    @staticmethod
    def _summarize(
        attack_paths: list[AttackPath],
        findings: list[Finding],
    ) -> SimulationStateSummary:

        highest_risk = max(
            (
                finding.risk_score
                for finding in findings
            ),
            default=0,
        )

        return SimulationStateSummary(
            highest_risk=highest_risk,
            attack_paths=len(attack_paths),
            findings=len(findings),
        )
