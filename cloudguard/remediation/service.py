from cloudguard.remediation.engine import (
    RemediationEngine,
)
from cloudguard.remediation.models import (
    Remediation,
    SimulationResult,
)
from cloudguard.remediation.simulator import (
    RemediationSimulator,
)
from cloudguard.services.analysis import (
    AnalysisResult,
)


class RemediationNotFoundError(Exception):
    def __init__(
        self,
        remediation_id: str,
    ) -> None:
        super().__init__(
            f"Unknown remediation: "
            f"{remediation_id}"
        )
        self.remediation_id = remediation_id


class RemediationService:
    """
    Coordinates remediation generation,
    simulation, and prioritization for a
    completed CloudGuard analysis.

    Prioritization ranks remediations by
    measurable simulated impact:

    1. attack paths eliminated (descending)
    2. absolute risk-score reduction
       (descending)
    3. remediation id (ascending, deterministic
       tie-break)

    The risk score is CloudGuard's
    prioritization score, not a statistical
    probability.
    """

    def __init__(self) -> None:
        self.engine = RemediationEngine()
        self.simulator = RemediationSimulator()

    def get_remediations(
        self,
        analysis_result: AnalysisResult,
    ) -> list[Remediation]:

        remediations = self.engine.generate(
            analysis_result
        )

        highest_risk = self._highest_risk(
            analysis_result
        )

        for remediation in remediations:
            remediation.risk_before = (
                highest_risk
            )

        return remediations

    def get_prioritized(
        self,
        analysis_result: AnalysisResult,
    ) -> list[Remediation]:

        remediations = self.get_remediations(
            analysis_result
        )

        for remediation in remediations:
            simulation = (
                self.simulator.simulate(
                    analysis_result,
                    remediation,
                )
            )

            remediation.paths_removed = (
                simulation
                .impact
                .paths_removed
            )
            remediation.risk_after = (
                simulation
                .after
                .highest_risk
            )
            remediation.risk_reduction = (
                simulation
                .impact
                .risk_reduction
            )
            remediation.risk_reduction_percent = (
                simulation
                .impact
                .risk_reduction_percent
            )

        remediations.sort(
            key=lambda item: (
                -(item.paths_removed or 0),
                -(item.risk_reduction or 0),
                item.remediation_id,
            )
        )

        for rank, remediation in enumerate(
            remediations,
            start=1,
        ):
            remediation.priority = rank

        return remediations

    def simulate(
        self,
        analysis_result: AnalysisResult,
        remediation_id: str,
    ) -> SimulationResult:

        remediations = self.engine.generate(
            analysis_result
        )

        for remediation in remediations:
            if (
                remediation.remediation_id
                == remediation_id
            ):
                return self.simulator.simulate(
                    analysis_result,
                    remediation,
                )

        raise RemediationNotFoundError(
            remediation_id
        )

    @staticmethod
    def _highest_risk(
        analysis_result: AnalysisResult,
    ) -> int:
        return max(
            (
                finding.risk_score
                for finding in (
                    analysis_result.findings
                )
            ),
            default=0,
        )
