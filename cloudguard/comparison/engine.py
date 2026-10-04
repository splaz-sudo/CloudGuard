from cloudguard.comparison.models import (
    AttackPathChange,
    ChangeStatus,
    ComparisonResult,
    FindingChange,
    RemediationVerification,
)
from cloudguard.remediation.models import (
    Remediation,
)
from cloudguard.scans.models import ScanSnapshot


class ComparisonEngine:
    """
    Compares two immutable scan snapshots.

    Findings match by deterministic
    fingerprint; attack paths match by
    deterministic path identity. All output
    lists are sorted for determinism.
    """

    def compare(
        self,
        snapshot_a: ScanSnapshot,
        snapshot_b: ScanSnapshot,
    ) -> ComparisonResult:

        findings_a = {
            finding.fingerprint: finding
            for finding in snapshot_a.findings
        }

        findings_b = {
            finding.fingerprint: finding
            for finding in snapshot_b.findings
        }

        new_findings = [
            self._finding_change(
                findings_b[key],
                ChangeStatus.NEW,
            )
            for key in sorted(
                findings_b.keys()
                - findings_a.keys()
            )
        ]

        resolved_findings = [
            self._finding_change(
                findings_a[key],
                ChangeStatus.RESOLVED,
            )
            for key in sorted(
                findings_a.keys()
                - findings_b.keys()
            )
        ]

        unchanged_findings = [
            self._finding_change(
                findings_b[key],
                ChangeStatus.UNCHANGED,
            )
            for key in sorted(
                findings_a.keys()
                & findings_b.keys()
            )
        ]

        paths_a = {
            path.path_id: path
            for path in snapshot_a.attack_paths
        }

        paths_b = {
            path.path_id: path
            for path in snapshot_b.attack_paths
        }

        new_paths = [
            self._path_change(
                paths_b[key],
                ChangeStatus.NEW,
            )
            for key in sorted(
                paths_b.keys()
                - paths_a.keys()
            )
        ]

        resolved_paths = [
            self._path_change(
                paths_a[key],
                ChangeStatus.RESOLVED,
            )
            for key in sorted(
                paths_a.keys()
                - paths_b.keys()
            )
        ]

        unchanged_paths = [
            self._path_change(
                paths_b[key],
                ChangeStatus.UNCHANGED,
            )
            for key in sorted(
                paths_a.keys()
                & paths_b.keys()
            )
        ]

        risk_before = (
            snapshot_a.record.highest_risk
        )
        risk_after = (
            snapshot_b.record.highest_risk
        )

        return ComparisonResult(
            scan_a=snapshot_a.record.scan_id,
            scan_b=snapshot_b.record.scan_id,
            risk_before=risk_before,
            risk_after=risk_after,
            risk_delta=(
                risk_after - risk_before
            ),
            findings_before=len(
                snapshot_a.findings
            ),
            findings_after=len(
                snapshot_b.findings
            ),
            new_findings=new_findings,
            unchanged_findings=(
                unchanged_findings
            ),
            resolved_findings=(
                resolved_findings
            ),
            paths_before=len(
                snapshot_a.attack_paths
            ),
            paths_after=len(
                snapshot_b.attack_paths
            ),
            new_paths=new_paths,
            unchanged_paths=unchanged_paths,
            resolved_paths=resolved_paths,
        )

    def verify_remediation(
        self,
        snapshot_a: ScanSnapshot,
        snapshot_b: ScanSnapshot,
        remediation: Remediation,
    ) -> RemediationVerification:
        """
        Checks whether the findings and attack
        paths a remediation targeted are still
        observed in the newer scan.
        """

        comparison = self.compare(
            snapshot_a,
            snapshot_b,
        )

        linked_findings = set(
            remediation.finding_ids
        )
        linked_paths = set(
            remediation.attack_path_ids
        )

        resolved_finding_ids = sorted(
            change.finding_id
            for change in (
                comparison.resolved_findings
            )
            if change.finding_id
            in linked_findings
        )

        remaining_finding_ids = sorted(
            change.finding_id
            for change in (
                comparison.unchanged_findings
            )
            if change.finding_id
            in linked_findings
        )

        resolved_path_ids = sorted(
            change.path_id
            for change in (
                comparison.resolved_paths
            )
            if change.path_id in linked_paths
        )

        remaining_path_ids = sorted(
            change.path_id
            for change in (
                comparison.unchanged_paths
            )
            if change.path_id in linked_paths
        )

        fully_resolved = (
            not remaining_finding_ids
            and not remaining_path_ids
            and (
                resolved_finding_ids
                or resolved_path_ids
            )
        )

        return RemediationVerification(
            remediation_id=(
                remediation.remediation_id
            ),
            scan_a=snapshot_a.record.scan_id,
            scan_b=snapshot_b.record.scan_id,
            status=(
                ChangeStatus.RESOLVED
                if fully_resolved
                else ChangeStatus.UNCHANGED
            ),
            resolved_finding_ids=(
                resolved_finding_ids
            ),
            remaining_finding_ids=(
                remaining_finding_ids
            ),
            resolved_path_ids=(
                resolved_path_ids
            ),
            remaining_path_ids=(
                remaining_path_ids
            ),
        )

    @staticmethod
    def _finding_change(
        finding,
        status: ChangeStatus,
    ) -> FindingChange:
        return FindingChange(
            fingerprint=finding.fingerprint,
            status=status,
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity.value,
            risk_score=finding.risk_score,
        )

    @staticmethod
    def _path_change(
        path,
        status: ChangeStatus,
    ) -> AttackPathChange:
        return AttackPathChange(
            path_id=path.path_id,
            status=status,
            source=path.source,
            target=path.target,
            nodes=list(path.nodes),
            risk_score=path.risk_score,
        )
