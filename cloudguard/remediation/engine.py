from cloudguard.findings.models import (
    FindingCategory,
)
from cloudguard.models.assets import AssetType
from cloudguard.models.relationships import (
    Relationship,
    RelationshipType,
)
from cloudguard.remediation.models import (
    Remediation,
    RemediationActionType,
)
from cloudguard.services.analysis import (
    AnalysisResult,
)


class RemediationEngine:
    """
    Generates structured remediation candidates
    from conditions CloudGuard actually detected
    in the security graph.

    Supported conditions:

    - Public internet exposure
      (internet --exposed_to--> workload)
      -> restrict the offending security-group
         ingress.

    - IAM write access to a sensitive resource
      (identity --can_write--> sensitive asset)
      -> reduce the granted permissions.

    Remediations are advisory only. CloudGuard
    does not modify cloud resources.
    """

    def generate(
        self,
        analysis_result: AnalysisResult,
    ) -> list[Remediation]:

        graph = analysis_result.security_graph

        remediations: list[Remediation] = []

        for source, target in graph.graph.edges:
            relationship = (
                graph.get_relationship(
                    source,
                    target,
                )
            )

            if relationship is None:
                continue

            if (
                relationship.relationship_type
                == RelationshipType.EXPOSED_TO
            ):
                remediations.append(
                    self._network_exposure(
                        analysis_result,
                        relationship,
                    )
                )

            elif (
                relationship.relationship_type
                == RelationshipType.CAN_WRITE
                and self._is_sensitive(
                    analysis_result,
                    target,
                )
            ):
                remediations.append(
                    self._iam_write_to_sensitive(
                        analysis_result,
                        relationship,
                    )
                )

        remediations.sort(
            key=lambda item: item.remediation_id
        )

        return remediations

    def _network_exposure(
        self,
        analysis_result: AnalysisResult,
        relationship: Relationship,
    ) -> Remediation:

        target = relationship.target

        finding_ids = [
            finding.id
            for finding in (
                analysis_result.findings
            )
            if finding.category
            == FindingCategory.NETWORK
            and target
            in finding.affected_assets
        ]

        attack_path_ids = (
            self._paths_using(
                analysis_result,
                relationship,
            )
        )

        evidence = [
            item
            for item in [
                relationship.evidence
            ]
            if item
        ]

        return Remediation(
            remediation_id=(
                "REM-RESTRICT-NETWORK-EXPOSURE-"
                f"{target}"
            ),
            title=(
                "Restrict public internet "
                f"exposure of {target}"
            ),
            description=(
                f"{target} is reachable from the "
                "public internet because its "
                "security-group configuration "
                "permits public inbound traffic. "
                "Restrict the offending ingress "
                "rule to trusted networks."
            ),
            action_type=(
                RemediationActionType
                .RESTRICT_NETWORK_EXPOSURE
            ),
            affected_resources=[target],
            finding_ids=finding_ids,
            attack_path_ids=attack_path_ids,
            relationship_ids=[
                relationship.relationship_id
            ],
            evidence=evidence,
            manual_steps=[
                "Identify the security group(s) "
                f"attached to {target}.",
                "Remove or scope the public "
                "inbound rule(s) identified in "
                "the evidence so only trusted "
                "source ranges are allowed.",
                "If a public IP is not required, "
                "disassociate it from the "
                "workload.",
                "Re-run CloudGuard analysis to "
                "verify the exposure is "
                "resolved.",
            ],
            expected_effect=(
                "Internet-originated reachability "
                f"to {target} is removed. Attack "
                "paths entering through this "
                "exposure are eliminated."
            ),
            paths_affected=len(
                attack_path_ids
            ),
        )

    def _iam_write_to_sensitive(
        self,
        analysis_result: AnalysisResult,
        relationship: Relationship,
    ) -> Remediation:

        source = relationship.source
        target = relationship.target

        attack_path_ids = (
            self._paths_using(
                analysis_result,
                relationship,
            )
        )

        permissions = ", ".join(
            relationship.permissions
        )

        evidence = []

        if relationship.evidence:
            evidence.append(
                relationship.evidence
            )

        evidence.append(
            f"Permissions: {permissions}"
        )

        return Remediation(
            remediation_id=(
                "REM-REDUCE-IAM-PERMISSION-"
                f"{source}-{target}"
            ),
            title=(
                f"Reduce IAM write permissions "
                f"of {source} on {target}"
            ),
            description=(
                f"{source} has write permissions "
                f"({permissions}) on {target}, "
                "which is classified as "
                "sensitive. Reduce the granted "
                "permissions to the minimum "
                "required."
            ),
            action_type=(
                RemediationActionType
                .REDUCE_IAM_PERMISSION
            ),
            affected_resources=[
                source,
                target,
            ],
            finding_ids=[],
            attack_path_ids=attack_path_ids,
            relationship_ids=[
                relationship.relationship_id
            ],
            evidence=evidence,
            manual_steps=[
                "Review the IAM policy "
                "identified in the evidence.",
                f"Remove or scope the write "
                f"permission(s) ({permissions}) "
                f"on {target} to least "
                "privilege.",
                "Re-run CloudGuard analysis to "
                "verify the permission change.",
            ],
            expected_effect=(
                f"{source} can no longer modify "
                f"or delete data in {target}. "
                "Attack paths relying on this "
                "write access are eliminated."
            ),
            paths_affected=len(
                attack_path_ids
            ),
        )

    @staticmethod
    def _paths_using(
        analysis_result: AnalysisResult,
        relationship: Relationship,
    ) -> list[str]:

        relationship_id = (
            relationship.relationship_id
        )

        path_ids: list[str] = []

        for path in (
            analysis_result.attack_paths
        ):
            uses_relationship = any(
                item.relationship_id
                == relationship_id
                for item in (
                    path.relationships
                )
            )

            if uses_relationship:
                path_ids.append(
                    path.path_id
                )

        return sorted(path_ids)

    @staticmethod
    def _is_sensitive(
        analysis_result: AnalysisResult,
        asset_id: str,
    ) -> bool:

        asset = (
            analysis_result
            .security_graph
            .get_asset(asset_id)
        )

        if asset is None:
            return False

        if asset.asset_type == AssetType.INTERNET:
            return False

        return asset.sensitive
