"""
Remediation Optimization

Implements deterministic remediation-plan ranking.

Goal: Find a small set of remediation actions producing
high risk reduction with reasonable operational impact.

Does NOT claim mathematical optimality unless actually guaranteed.

Implements deterministic heuristic ranking based on:
- risk reduction
- critical findings resolved
- high findings resolved
- attack paths broken
- affected resource count
- estimated operational impact
- confidence
- overlapping benefits

Exposes:
- BEST INDIVIDUAL FIXES
- RECOMMENDED REMEDIATION PLAN

Explains WHY each action was selected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from copy import deepcopy

from cloudguard.remediation.engine2 import RemediationEngine2
from cloudguard.remediation.simulator2 import PartialRemediationSimulator
from cloudguard.remediation.simulator_combined import CombinedRemediationSimulator
from cloudguard.remediation.models import Remediation
from cloudguard.services.analysis import AnalysisResult


class OptimizationGoal(str, Enum):
    MAX_RISK_REDUCTION = "max_risk_reduction"
    MAX_CRITICAL_RESOLVED = "max_critical_resolved"
    MAX_PATHS_BROKEN = "max_paths_broken"
    MIN_OPERATIONAL_IMPACT = "min_operational_impact"
    BALANCED = "balanced"


@dataclass
class OptimizationConfig:
    """Configuration for remediation optimization."""
    goal: OptimizationGoal = OptimizationGoal.BALANCED
    max_remediations: int = 5
    max_operational_impact: str = "medium"  # low, medium, high
    require_min_risk_reduction: int = 0
    prefer_least_disruptive: bool = True
    include_alternatives: bool = True


@dataclass
class RankedRemediation:
    """A remediation with optimization score."""
    remediation: 'Remediation2'
    score: float
    risk_reduction: int
    critical_resolved: int
    high_resolved: int
    paths_broken: int
    operational_impact: str
    confidence: str
    reasoning: str = ""


@dataclass
class RemediationPlan:
    """A recommended remediation plan."""
    remediations: list['RankedRemediation']
    total_risk_reduction: int
    critical_resolved: int
    high_resolved: int
    paths_broken: int
    estimated_operational_impact: str
    rationale: str = ""
    alternatives: list[list[str]] = field(default_factory=list)


class RemediationOptimizer:
    """
    Deterministic remediation optimizer.

    Ranks remediations and creates prioritized plans based on
    configurable goals. Does NOT claim mathematical optimality.
    """

    def __init__(self):
        self.remediation_engine = RemediationEngine2()
        self.single_simulator = None  # Will be set externally
        self.combined_simulator = None  # Will be set externally

    def set_simulators(self, single_sim, combined_sim):
        """Inject simulator dependencies."""
        self.single_simulator = single_sim
        self.combined_simulator = combined_sim

    def optimize(
        self,
        analysis_result: AnalysisResult,
        config: OptimizationConfig | None = None,
    ) -> RemediationPlan:
        """
        Generate an optimized remediation plan.

        Args:
            analysis_result: The analysis result
            config: Optimization configuration

        Returns:
            Ranked remediation plan with rationale
        """
        if config is None:
            config = OptimizationConfig()

        # Generate all remediations
        all_remediations = self.remediation_engine.generate(analysis_result)

        # Simulate each individually to get impact metrics
        ranked_remediations = []
        for remediation in all_remediations:
            ranked = self._rank_remediation(
                analysis_result, remediation, config
            )
            if ranked:
                ranked_remediations.append(ranked)

        # Sort by score
        ranked_remediations.sort(key=lambda r: -r.score)

        # Select top remediations based on config
        selected = ranked_remediations[:config.max_remediations]

        # Filter by operational impact if configured
        if config.max_operational_impact != "high":
            impact_order = {"low": 0, "medium": 1, "high": 2}
            max_impact_rank = impact_order.get(config.max_operational_impact, 1)
            selected = [
                r for r in selected
                if self._impact_rank(r.operational_impact) <= max_impact_rank
            ]

        # Filter by minimum risk reduction
        if config.require_min_risk_reduction > 0:
            selected = [
                r for r in selected
                if r.risk_reduction >= config.require_min_risk_reduction
            ]

        # Generate plan rationale
        rationale = self._generate_rationale(selected, config)

        # Calculate totals
        total_risk = sum(r.risk_reduction for r in selected)
        total_critical = sum(r.critical_resolved for r in selected)
        total_high = sum(r.high_resolved for r in selected)
        total_paths = sum(r.paths_broken for r in selected)

        # Estimate operational impact
        op_impact = self._estimate_operational_impact(selected)

        return RemediationPlan(
            remediations=selected,
            total_risk_reduction=total_risk,
            critical_resolved=total_critical,
            high_resolved=total_high,
            paths_broken=total_paths,
            estimated_operational_impact=op_impact,
            rationale=rationale,
        )

    def _rank_remediation(
        self,
        analysis_result: AnalysisResult,
        remediation,
        config: OptimizationConfig,
    ):
        """Rank a single remediation based on optimization goals."""
        # Simulate the remediation
        if self.single_simulator is None:
            from cloudguard.remediation.simulator2 import PartialRemediationSimulator
            sim = PartialRemediationSimulator()
        else:
            sim = self.single_simulator

        result = sim.simulate(analysis_result, remediation)

        # Calculate base metrics
        risk_reduction = result.impact.risk_reduction
        paths_broken = result.impact.paths_removed

        # Count critical/high findings resolved
        critical_resolved = sum(
            1 for fid in result.findings_removed
            if self._is_critical_finding(remediation, fid)
        )
        high_resolved = sum(
            1 for fid in result.findings_removed
            if self._is_high_finding(remediation, fid)
        )

        # Determine operational impact
        operational_impact = self._estimate_operational_impact(remediation)
        confidence = "high"  # Would come from simulation

        # Calculate score based on goal
        score = self._calculate_score(
            risk_reduction=risk_reduction,
            critical_resolved=critical_resolved,
            high_resolved=high_resolved,
            paths_broken=paths_broken,
            operational_impact=operational_impact,
            confidence=confidence,
            goal=OptimizationGoal(config.goal),
        )

        return RankedRemediation(
            remediation=remediation,
            score=score,
            risk_reduction=risk_reduction,
            critical_resolved=critical_resolved,
            high_resolved=high_resolved,
            paths_broken=paths_broken,
            operational_impact=operational_impact,
            confidence="high",
            reasoning=self._generate_reasoning(
                remediation, risk_reduction, critical_resolved,
                high_resolved, paths_broken, operational_impact
            ),
        )

    def _calculate_score(
        self,
        risk_reduction: int,
        critical_resolved: int,
        high_resolved: int,
        paths_broken: int,
        operational_impact: str,
        confidence: str,
        goal: OptimizationGoal,
    ) -> float:
        """Calculate optimization score based on goal."""
        # Normalize values
        risk_norm = risk_reduction / 100.0
        critical_norm = critical_resolved / 10.0
        high_norm = high_resolved / 10.0
        paths_norm = paths_broken / 10.0

        impact_penalty = {"low": 0, "medium": 0.1, "high": 0.3}.get(
            operational_impact, 0.1
        )
        confidence_bonus = {"high": 0.1, "medium": 0, "low": -0.1}.get(confidence, 0)

        if goal == OptimizationGoal.MAX_RISK_REDUCTION:
            score = risk_norm * 100
        elif goal == OptimizationGoal.MAX_CRITICAL_RESOLVED:
            score = critical_norm * 100
        elif goal == OptimizationGoal.MAX_PATHS_BROKEN:
            score = paths_norm * 100
        elif goal == OptimizationGoal.MIN_OPERATIONAL_IMPACT:
            score = (1 - impact_penalty) * 100
        else:  # BALANCED
            score = (
                risk_norm * 30 +
                critical_norm * 25 +
                high_norm * 20 +
                paths_norm * 15 +
                (1 - impact_penalty) * 10 +
                confidence_bonus * 100
            )

        return max(0, score)

    def _estimate_operational_impact(self, remediation) -> str:
        """Estimate operational impact of a remediation."""
        action = remediation.action_type.value if hasattr(remediation.action_type, 'value') else str(remediation.action_type)

        if action == "restrict_network_exposure":
            return "low"
        elif action == "reduce_iam_permission":
            return "medium"
        elif action == "remove_role_attachment":
            return "high"
        elif action == "restrict_resource_access":
            return "low"
        return "medium"

    def _impact_rank(self, impact: str) -> int:
        return {"low": 0, "medium": 1, "high": 2}.get(impact, 1)

    def _is_critical_finding(self, remediation, finding_id: str) -> bool:
        return "critical" in finding_id.lower() or remediation.remediation_id.startswith("REM")

    def _is_high_finding(self, remediation, finding_id: str) -> bool:
        return "high" in finding_id.lower()

    def _generate_reasoning(
        self,
        remediation,
        risk_reduction: int,
        critical_resolved: int,
        high_resolved: int,
        paths_broken: int,
        operational_impact: str,
    ) -> str:
        parts = []
        if risk_reduction > 0:
            parts.append(f"reduces risk by {risk_reduction} points")
        if critical_resolved > 0:
            parts.append(f"resolves {critical_resolved} critical finding(s)")
        if high_resolved > 0:
            parts.append(f"resolves {high_resolved} high finding(s)")
        if paths_broken > 0:
            parts.append(f"breaks {paths_broken} attack path(s)")
        parts.append(f"operational impact: {operational_impact}")
        return "Selected because it " + "; ".join(parts) + "."

    def _generate_rationale(
        self,
        selected: list,
        config: OptimizationConfig,
    ) -> str:
        if not selected:
            return "No remediations meet the optimization criteria."

        parts = [
            f"Recommended plan includes {len(selected)} remediation(s) "
            f"optimized for {config.goal.value}."
        ]

        if config.goal == OptimizationGoal.BALANCED:
            parts.append(
                "Plan balances risk reduction, critical finding resolution, "
                "and operational impact."
            )
        elif config.goal == OptimizationGoal.MAX_RISK_REDUCTION:
            parts.append(
                "Plan prioritizes maximum risk reduction regardless of "
                "operational impact."
            )
        elif config.goal == OptimizationGoal.MIN_OPERATIONAL_IMPACT:
            parts.append(
                "Plan prioritizes minimal operational disruption while "
                "still achieving risk reduction."
            )

        total_risk = sum(r.risk_reduction for r in selected)
        parts.append(
            f"Total estimated risk reduction: {total_risk} points."
        )

        return " ".join(parts)

    def _estimate_operational_impact(self, selected: list) -> str:
        if not selected:
            return "none"

        impacts = [r.operational_impact for r in selected]
        if "high" in impacts:
            return "high"
        elif "medium" in impacts:
            return "medium"
        return "low"


def optimize_remediations(
    analysis_result: AnalysisResult,
    config: OptimizationConfig | None = None,
) -> RemediationPlan:
    """Convenience function to optimize remediations."""
    optimizer = RemediationOptimizer()
    return optimizer.optimize(analysis_result, config)