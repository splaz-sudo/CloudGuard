from __future__ import annotations

from typing import Any

from cloudguard.compliance.models import (
    ComplianceReport,
)
from cloudguard.reporting.models import (
    ReportAttackPath,
    ReportComplianceSummary,
    ReportFinding,
    ReportIdentityRisk,
    ReportNetworkRisk,
    ReportSummary,
    SecurityReport,
)


class SecurityReportEngine:
    """
    Builds a structured security assessment from
    CloudGuard's existing analysis results.

    The engine does not perform additional cloud
    discovery. It reports the evidence already
    produced by CloudGuard.
    """

    def build(
        self,
        *,
        analysis_result: Any,
        identity_risks: list[Any],
        network_risks: list[Any],
        compliance_report: ComplianceReport,
    ) -> SecurityReport:

        findings = analysis_result.findings

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            severity = self._enum_value(
                finding.severity
            ).lower()

            if severity in severity_counts:
                severity_counts[severity] += 1

        highest_risk_score = max(
            (
                finding.risk_score
                for finding in findings
            ),
            default=0,
        )

        assets = self._collect_assets(
            analysis_result
        )

        sensitive_assets = sum(
            bool(
                asset.get(
                    "sensitive",
                    False,
                )
            )
            for asset in assets
        )

        internet_exposed_assets = sum(
            bool(
                asset.get(
                    "internet_exposed",
                    False,
                )
            )
            for asset in assets
        )

        summary = ReportSummary(
            mode="local",
            total_assets=len(assets),
            total_relationships=(
                analysis_result
                .security_graph
                .relationship_count
            ),
            sensitive_assets=(
                sensitive_assets
            ),
            internet_exposed_assets=(
                internet_exposed_assets
            ),
            attack_paths=len(
                analysis_result.attack_paths
            ),
            findings=len(findings),
            critical_findings=(
                severity_counts["critical"]
            ),
            high_findings=(
                severity_counts["high"]
            ),
            medium_findings=(
                severity_counts["medium"]
            ),
            low_findings=(
                severity_counts["low"]
            ),
            info_findings=(
                severity_counts["info"]
            ),
            highest_risk_score=(
                highest_risk_score
            ),
        )

        report_findings = [
            ReportFinding(
                id=finding.id,
                title=finding.title,
                description=(
                    finding.description
                ),
                severity=self._enum_value(
                    finding.severity
                ),
                category=self._enum_value(
                    finding.category
                ),
                risk_score=(
                    finding.risk_score
                ),
                affected_assets=list(
                    finding.affected_assets
                ),
                evidence=list(
                    finding.evidence
                ),
                remediation=(
                    finding.remediation
                ),
            )
            for finding in findings
        ]

        report_findings.sort(
            key=lambda item: (
                item.risk_score
            ),
            reverse=True,
        )

        attack_paths = [
            ReportAttackPath(
                nodes=list(path.nodes),
                hop_count=path.hop_count,
                sensitive_target=(
                    path.sensitive_target
                ),
            )
            for path
            in analysis_result.attack_paths
        ]

        identity_report = [
            ReportIdentityRisk(
                identity_id=(
                    risk.identity_id
                ),
                identity_name=(
                    risk.identity_name
                ),
                identity_type=(
                    risk.identity_type
                ),
                risk_score=(
                    risk.risk_score
                ),
                severity=(
                    risk.severity
                ),
                permissions=list(
                    risk.permissions
                ),
                exposed_workloads=list(
                    risk.exposed_workloads
                ),
                sensitive_resources=list(
                    risk.sensitive_resources
                ),
                attack_paths=[
                    list(path)
                    for path
                    in risk.attack_paths
                ],
                risk_factors=list(
                    risk.risk_factors
                ),
            )
            for risk in identity_risks
        ]

        network_report = [
            ReportNetworkRisk(
                asset_id=risk.asset_id,
                asset_name=risk.asset_name,
                risk_score=(
                    risk.risk_score
                ),
                severity=risk.severity,
                public_ip=risk.public_ip,
                security_groups=list(
                    risk.security_groups
                ),
                exposed_services=[
                    self._to_dict(service)
                    for service
                    in risk.exposed_services
                ],
                attached_identities=list(
                    risk.attached_identities
                ),
                sensitive_resources=list(
                    risk.sensitive_resources
                ),
                attack_paths=[
                    list(path)
                    for path
                    in risk.attack_paths
                ],
                risk_factors=list(
                    risk.risk_factors
                ),
            )
            for risk in network_risks
        ]

        compliance_summary = (
            self._build_compliance_summary(
                compliance_report
            )
        )

        compliance_controls = [
            control.model_dump(
                mode="json"
            )
            for control
            in compliance_report.controls
        ]

        return SecurityReport(
            summary=summary,
            assets=assets,
            attack_paths=attack_paths,
            findings=report_findings,
            identity_risks=identity_report,
            network_risks=network_report,
            compliance=(
                compliance_summary
            ),
            compliance_controls=(
                compliance_controls
            ),
            limitations=[
                (
                    "Local assessment mode uses "
                    "simulated AWS resources."
                ),
                (
                    "IAM analysis represents "
                    "permissions observed by the "
                    "current CloudGuard model and "
                    "does not claim complete AWS "
                    "effective-permission evaluation."
                ),
                (
                    "Compliance mappings are "
                    "evidence-based indicators and "
                    "do not represent certification, "
                    "attestation, or a complete "
                    "framework audit."
                ),
            ],
        )

    @staticmethod
    def _collect_assets(
        analysis_result: Any,
    ) -> list[dict]:

        assets: list[dict] = []

        graph = (
            analysis_result.security_graph
        )

        for node_id in graph.graph.nodes:
            asset = graph.get_asset(
                node_id
            )

            if asset is None:
                continue

            assets.append(
                asset.model_dump(
                    mode="json"
                )
            )

        return assets

    @staticmethod
    def _build_compliance_summary(
        report: ComplianceReport,
    ) -> ReportComplianceSummary:

        non_compliant = 0
        not_assessed = 0

        for control in report.controls:
            status = (
                SecurityReportEngine
                ._enum_value(
                    control.status
                )
            )

            if status == "NON_COMPLIANT":
                non_compliant += 1

            elif status == "NOT_ASSESSED":
                not_assessed += 1

        return ReportComplianceSummary(
            frameworks=len(
                report.frameworks
            ),
            mapped_controls=len(
                report.controls
            ),
            non_compliant_controls=(
                non_compliant
            ),
            not_assessed_controls=(
                not_assessed
            ),
            mapped_findings=(
                report.mapped_findings
            ),
        )

    @staticmethod
    def _to_dict(
        value: Any,
    ) -> dict:

        if hasattr(value, "model_dump"):
            return value.model_dump(
                mode="json"
            )

        if hasattr(value, "to_dict"):
            return value.to_dict()

        return dict(
            vars(value)
        )

    @staticmethod
    def _enum_value(
        value: Any,
    ) -> str:

        enum_value = getattr(
            value,
            "value",
            value,
        )

        return str(enum_value)