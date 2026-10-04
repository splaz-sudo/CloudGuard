from cloudguard.compliance.engine import (
    ComplianceEngine,
)
from cloudguard.compliance.models import (
    ComplianceReport,
)
from cloudguard.services.analysis import (
    AnalysisResult,
)


class ComplianceAnalysisService:
    """
    Converts CloudGuard security findings into
    evidence-based compliance mappings.
    """

    def __init__(self) -> None:
        self.engine = ComplianceEngine()

    def analyze(
        self,
        analysis_result: AnalysisResult,
    ) -> ComplianceReport:
        return self.engine.analyze(
            analysis_result.findings
        )