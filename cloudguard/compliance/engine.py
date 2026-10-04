from dataclasses import dataclass

from cloudguard.compliance.models import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceReport,
    ComplianceStatus,
    FrameworkSummary,
)
from cloudguard.findings.models import (
    Finding,
    FindingCategory,
)


@dataclass(frozen=True)
class ControlDefinition:
    framework: ComplianceFramework
    control_id: str
    title: str
    description: str
    categories: tuple[FindingCategory, ...]


class ComplianceEngine:
    """
    Maps CloudGuard findings to relevant security
    framework controls.

    This engine does not claim to perform a complete
    framework audit. A control is marked
    NON_COMPLIANT only when CloudGuard has concrete
    finding evidence mapped to that control.

    Controls without sufficient evidence remain
    NOT_ASSESSED.
    """

    CONTROL_DEFINITIONS = (
        ControlDefinition(
            framework=(
                ComplianceFramework.CIS_AWS
            ),
            control_id="CG-CIS-NET-01",
            title=(
                "Restrict unnecessary public "
                "network exposure"
            ),
            description=(
                "Cloud workloads should not expose "
                "network services to the public "
                "internet unless the exposure is "
                "explicitly required and controlled."
            ),
            categories=(
                FindingCategory.NETWORK,
            ),
        ),
        ControlDefinition(
            framework=(
                ComplianceFramework.CIS_AWS
            ),
            control_id="CG-CIS-IAM-01",
            title=(
                "Limit identity permissions and "
                "privileged access paths"
            ),
            description=(
                "Cloud identities should follow "
                "least-privilege principles and "
                "should not create unnecessary "
                "access paths to sensitive "
                "resources."
            ),
            categories=(
                FindingCategory.IAM,
                FindingCategory.ATTACK_PATH,
            ),
        ),
        ControlDefinition(
            framework=(
                ComplianceFramework.NIST_CSF
            ),
            control_id="PR.AA",
            title=(
                "Identity Management, "
                "Authentication, and Access Control"
            ),
            description=(
                "Access to physical and logical "
                "assets should be limited to "
                "authorized users, services, and "
                "processes."
            ),
            categories=(
                FindingCategory.IAM,
                FindingCategory.ATTACK_PATH,
            ),
        ),
        ControlDefinition(
            framework=(
                ComplianceFramework.NIST_CSF
            ),
            control_id="PR.PS",
            title="Platform Security",
            description=(
                "Cloud platforms and services "
                "should be securely configured and "
                "protected against unnecessary "
                "exposure."
            ),
            categories=(
                FindingCategory.NETWORK,
                FindingCategory.CONFIGURATION,
                FindingCategory.STORAGE,
            ),
        ),
    )

    def analyze(
        self,
        findings: list[Finding],
    ) -> ComplianceReport:
        controls = [
            self._evaluate_control(
                definition,
                findings,
            )
            for definition
            in self.CONTROL_DEFINITIONS
        ]

        frameworks = [
            self._build_summary(
                framework,
                controls,
            )
            for framework
            in ComplianceFramework
        ]

        mapped_findings = len(
            {
                finding_id
                for control in controls
                for finding_id
                in control.related_findings
            }
        )

        return ComplianceReport(
            frameworks=frameworks,
            controls=controls,
            mapped_findings=mapped_findings,
        )

    def _evaluate_control(
        self,
        definition: ControlDefinition,
        findings: list[Finding],
    ) -> ComplianceControl:
        related = [
            finding
            for finding in findings
            if finding.category
            in definition.categories
        ]

        if related:
            status = (
                ComplianceStatus.NON_COMPLIANT
            )
        else:
            status = (
                ComplianceStatus.NOT_ASSESSED
            )

        affected_assets = sorted(
            {
                asset_id
                for finding in related
                for asset_id
                in finding.affected_assets
            }
        )

        evidence = self._unique(
            [
                item
                for finding in related
                for item in finding.evidence
            ]
        )

        remediation = self._unique(
            [
                finding.remediation
                for finding in related
                if finding.remediation
            ]
        )

        return ComplianceControl(
            framework=definition.framework,
            control_id=definition.control_id,
            title=definition.title,
            description=definition.description,
            status=status,
            related_findings=[
                finding.id
                for finding in related
            ],
            affected_assets=affected_assets,
            evidence=evidence,
            remediation=remediation,
        )

    def _build_summary(
        self,
        framework: ComplianceFramework,
        controls: list[ComplianceControl],
    ) -> FrameworkSummary:
        framework_controls = [
            control
            for control in controls
            if control.framework == framework
        ]

        non_compliant = sum(
            control.status
            == ComplianceStatus.NON_COMPLIANT
            for control in framework_controls
        )

        not_assessed = sum(
            control.status
            == ComplianceStatus.NOT_ASSESSED
            for control in framework_controls
        )

        return FrameworkSummary(
            framework=framework,
            total_controls=len(
                framework_controls
            ),
            non_compliant=non_compliant,
            not_assessed=not_assessed,
        )

    @staticmethod
    def _unique(
        values: list[str],
    ) -> list[str]:
        return list(dict.fromkeys(values))