"""
Remediation Engine 2.0

Upgrades remediation recommendations to be:
- finding-specific
- evidence-aware
- resource-specific
- prioritized
- actionable
- explainable

Each remediation includes:
- title, description
- affected resources
- finding IDs, attack path IDs
- expected security benefit
- estimated blast radius
- operational considerations
- verification method
- rollback considerations
- confidence
- manual steps

Prefer least-disruptive remediation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cloudguard.findings.models import (
    Finding,
    FindingCategory,
)
from cloudguard.graph.attack_paths2 import (
    AttackPath2,
    PathCategory,
)
from cloudguard.inference.network_exposure import (
    ExposureEvidence,
    ExposureType,
)
from cloudguard.inference.privilege_escalation import (
    EscalationPath,
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
from cloudguard.services.analysis import AnalysisResult
from cloudguard.inference.network_exposure import ExposureEvidence


class RemediationPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class BlastRadiusEstimate:
    """Estimated blast radius of a remediation."""
    affected_resources: int = 0
    affected_attack_paths: int = 0
    affected_findings: int = 0
    potential_service_disruption: str = "unknown"
    confidence: str = "low"


@dataclass
class Remediation2(Remediation):
    """Enhanced remediation with detailed impact analysis."""

    priority: RemediationPriority = RemediationPriority.MEDIUM
    blast_radius: BlastRadiusEstimate = field(default_factory=BlastRadiusEstimate)
    verification_method: str = ""
    rollback_considerations: str = ""
    confidence: str = "medium"
    least_disruptive: bool = True
    alternative_remediations: list[str] = field(default_factory=list)


class RemediationEngine2:
    """
    Enhanced remediation engine generating detailed,
    evidence-aware, prioritized recommendations.
    """

    def __init__(self) -> None:
        pass

    def generate(
        self,
        analysis_result: AnalysisResult,
        exposure_evidence: dict | None = None,
        escalation_paths: list = None,
        attack_paths2: list = None,
    ) -> list[Remediation2]:
        """
        Generate enhanced remediation candidates.

        Args:
            analysis_result: The analysis result from the scan
            exposure_evidence: Optional exposure evidence from NetworkExposureEngine2
            escalation_paths: Optional privilege escalation paths
            attack_paths2: Optional enhanced attack paths from AttackPathEngine2

        Returns:
            List of Remediation2 objects sorted by priority
        """
        graph = analysis_result.security_graph
        remediations: list[Remediation2] = []

        # Track processed relationships to avoid duplicates
        processed_relationships = set()

        for source, target in graph.graph.edges:
            relationship = graph.get_relationship(source, target)

            if relationship is None:
                continue

            rel_key = relationship.relationship_id
            if rel_key in processed_relationships:
                continue
            processed_relationships.add(rel_key)

            # Network exposure remediation
            if relationship.relationship_type == RelationshipType.EXPOSED_TO:
                remediation = self._create_network_exposure_remediation(
                    analysis_result, relationship, exposure_evidence
                )
                if remediation:
                    remediations.append(remediation)

            # IAM write to sensitive resource
            elif (
                relationship.relationship_type == RelationshipType.CAN_WRITE
                and self._is_sensitive(analysis_result, target)
            ):
                remediation = self._create_iam_write_remediation(
                    analysis_result, relationship
                )
                if remediation:
                    remediations.append(remediation)

            # IAM read to sensitive with escalation
            elif (
                relationship.relationship_type == RelationshipType.CAN_READ
                and self._is_sensitive(analysis_result, target)
            ):
                remediation = self._create_iam_read_remediation(
                    analysis_result, relationship
                )
                if remediation:
                    remediations.append(remediation)

            # Role assumption with privilege escalation
            elif relationship.relationship_type == RelationshipType.ASSUMES:
                remediation = self._create_role_assumption_remediation(
                    analysis_result, relationship, escalation_paths
                )
                if remediation:
                    remediations.append(remediation)

        # Add finding-specific remediations
        for finding in analysis_result.findings:
            finding_remediations = self._create_finding_remediations(
                finding, analysis_result
            )
            remediations.extend(finding_remediations)

        # Sort by priority and risk reduction
        remediations.sort(
            key=lambda r: (
                self._priority_rank(r.priority),
                -(r.risk_reduction or 0),
                r.remediation_id,
            )
        )

        return remediations

    def _create_network_exposure_remediation(
        self,
        analysis_result: AnalysisResult,
        relationship: Relationship,
        exposure_evidence: dict | None = None,
    ) -> Remediation2 | None:
        """Create remediation for network exposure."""
        target = relationship.target

        # Get exposure evidence if available
        evidence = [relationship.evidence] if relationship.evidence else []
        exposure_info = None
        if exposure_evidence:
            exposure_info = exposure_evidence.get(relationship.target)

        # Calculate blast radius
        blast_radius = self._estimate_blast_radius_network(relationship)

        # Find related findings and attack paths
        finding_ids = self._find_related_finding_ids(relationship)
        attack_path_ids = self._paths_using(relationship)

        return Remediation2(
            remediation_id=(
                "REM2-RESTRICT-NETWORK-EXPOSURE-"
                f"{relationship.target}"
            ),
            title=(
                f"Restrict public internet exposure of {relationship.target}"
            ),
            description=(
                f"{relationship.target} is reachable from the "
                "public internet because its security-group configuration "
                "permits public inbound traffic. Restrict the offending "
                "ingress rule to trusted networks."
            ),
            action_type=RemediationActionType.RESTRICT_NETWORK_EXPOSURE,
            priority=RemediationPriority.CRITICAL,
            affected_resources=[relationship.target],
            finding_ids=self._find_related_finding_ids(relationship),
            attack_path_ids=self._paths_using(relationship),
            relationship_ids=[relationship.relationship_id],
            evidence=[e for e in [relationship.evidence] if e],
            manual_steps=[
                f"Identify the security group(s) attached to {relationship.target}.",
                "Locate the specific ingress rule allowing public access "
                "(0.0.0.0/0 or ::/0) as identified in the evidence.",
                "Modify the rule to restrict source CIDR to trusted networks only.",
                "If the rule allows all protocols (-1) or broad port ranges, "
                "narrow to only required protocols and ports.",
                "If a public IP is not required, disassociate it from the workload.",
                "Re-run CloudGuard analysis to verify the exposure is resolved.",
            ],
            expected_effect=(
                "Internet-originated reachability to the resource is removed. "
                "Attack paths entering through this exposure are eliminated."
            ),
            blast_radius=BlastRadiusEstimate(
                affected_resources=1,
                affected_attack_paths=len(self._paths_using(relationship)),
                affected_findings=len(self._find_related_finding_ids(relationship)),
                potential_service_disruption=(
                    "low - only restricts inbound traffic; "
                    "outbound and internal traffic unaffected"
                ),
                confidence="high",
            ),
            verification_method=(
                "Re-run CloudGuard scan and verify the network exposure finding "
                "is resolved and attack paths through this resource are eliminated."
            ),
            rollback_considerations=(
                "If legitimate traffic is blocked, revert the security group "
                "rule change immediately. The original rule configuration is "
                "preserved in CloudGuard's evidence."
            ),
            confidence="high",
            least_disruptive=True,
            alternative_remediations=[
                "Use a bastion host or VPN for administrative access instead of "
                "direct public exposure.",
                "Move workload to a private subnet with NAT Gateway for outbound "
                "Internet access if inbound public access is not required.",
            ],
        )

    def _create_iam_write_remediation(
        self,
        analysis_result: AnalysisResult,
        relationship: Relationship,
    ) -> Remediation2 | None:
        """Create remediation for IAM write to sensitive resource."""
        source = relationship.source
        target = relationship.target
        permissions = ", ".join(relationship.permissions)

        return Remediation2(
            remediation_id=(
                "REM2-REDUCE-IAM-WRITE-"
                f"{source}-{target}"
            ),
            title=(
                f"Reduce IAM write permissions of {source} on {target}"
            ),
            description=(
                f"{source} has write permissions ({', '.join(relationship.permissions)}) "
                f"on {target}, which is classified as sensitive. "
                "Reduce the granted permissions to the minimum required."
            ),
            action_type=RemediationActionType.REDUCE_IAM_PERMISSION,
            priority=RemediationPriority.HIGH,
            affected_resources=[source, target],
            finding_ids=[],
            attack_path_ids=self._paths_using(relationship),
            relationship_ids=[relationship.relationship_id],
            evidence=[e for e in [relationship.evidence] if e] + [f"Permissions: {', '.join(relationship.permissions)}"],
            manual_steps=[
                "Review the IAM policy identified in the evidence.",
                f"Identify the specific write permissions ({', '.join(relationship.permissions)}) "
                f"granted on {target}.",
                "Determine the minimum write permissions required for the workload to function.",
                "Modify the IAM policy to remove or scope the unnecessary write permissions.",
                "Apply the principle of least privilege - grant only specific actions on specific resources.",
                "Re-run CloudGuard analysis to verify the permission change.",
            ],
            expected_effect=(
                f"{source} can no longer modify or delete data in {target}. "
                "Attack paths relying on this write access are eliminated."
            ),
            blast_radius=BlastRadiusEstimate(
                affected_resources=2,
                affected_attack_paths=len(self._paths_using(relationship)),
                affected_findings=0,
                potential_service_disruption=(
                    "medium - workload may lose ability to modify the resource; "
                    "test in staging before applying to production"
                ),
                confidence="high",
            ),
            verification_method=(
                "Re-run CloudGuard scan and verify the IAM write finding is resolved "
                "and attack paths through this permission are eliminated."
            ),
            rollback_considerations=(
                "If the workload loses required functionality, revert the IAM policy "
                "change immediately. Consider using IAM Access Analyzer to validate "
                "the new policy before applying."
            ),
            confidence="high",
            least_disruptive=True,
            alternative_remediations=[
                "Use resource-based policies (bucket policies, KMS key policies) "
                "instead of identity-based policies for finer control.",
                "Implement attribute-based access control (ABAC) with condition keys.",
            ],
        )

    def _create_iam_read_remediation(
        self,
        analysis_result: AnalysisResult,
        relationship: Relationship,
    ) -> Remediation2 | None:
        """Create remediation for IAM read to sensitive resource."""
        source = relationship.source
        target = relationship.target
        permissions = ", ".join(relationship.permissions)

        return Remediation2(
            remediation_id=(
                "REM2-REDUCE-IAM-READ-"
                f"{source}-{target}"
            ),
            title=(
                f"Reduce IAM read permissions of {source} on {target}"
            ),
            description=(
                f"{source} has read permissions ({', '.join(relationship.permissions)}) "
                f"on {target}, which is classified as sensitive. "
                "Reduce the granted permissions to the minimum required."
            ),
            action_type=RemediationActionType.REDUCE_IAM_PERMISSION,
            priority=RemediationPriority.MEDIUM,
            affected_resources=[source, target],
            finding_ids=[],
            attack_path_ids=self._paths_using(relationship),
            relationship_ids=[relationship.relationship_id],
            evidence=[e for e in [relationship.evidence] if e] + [f"Permissions: {', '.join(relationship.permissions)}"],
            manual_steps=[
                "Review the IAM policy identified in the evidence.",
                f"Determine if read access ({', '.join(relationship.permissions)}) "
                f"on {target} is required for the workload.",
                "If read access is not required, remove the permission entirely.",
                "If read access is required, scope to specific resources or use conditions.",
                "Re-run CloudGuard analysis to verify the permission change.",
            ],
            expected_effect=(
                f"{source} can no longer read data from {target} "
                "unless explicitly required. Attack paths through this read access "
                "are eliminated or reduced."
            ),
            blast_radius=BlastRadiusEstimate(
                affected_resources=2,
                affected_attack_paths=len(self._paths_using(relationship)),
                affected_findings=0,
                potential_service_disruption=(
                    "low-medium - workload loses read access to the resource"
                ),
                confidence="high",
            ),
            verification_method=(
                "Re-run CloudGuard scan and verify the attack path through this "
                "read permission is eliminated or reduced."
            ),
            rollback_considerations=(
                "If the workload requires read access for legitimate operations, "
                "restore the permission immediately."
            ),
            confidence="high",
            least_disruptive=True,
            alternative_remediations=[
                "Use resource-based policies with explicit deny for sensitive data.",
                "Enable bucket encryption with KMS key policies to restrict decryption.",
            ],
        )

    def _create_role_assumption_remediation(
        self,
        analysis_result: AnalysisResult,
        relationship: Relationship,
        escalation_paths: list = None,
    ) -> Remediation2 | None:
        """Create remediation for role assumption with privilege escalation risk."""
        source = relationship.source
        target = relationship.target

        # Check if this role assumption enables privilege escalation
        has_escalation = False
        if escalation_paths:
            for esc in escalation_paths:
                if esc.principal_id == source:
                    has_escalation = True
                    break

        if not has_escalation:
            return None

        return Remediation2(
            remediation_id=(
                "REM2-REVIEW-ROLE-ASSUMPTION-"
                f"{source}-{target}"
            ),
            title=(
                f"Review role assumption: {source} assumes {target}"
            ),
            description=(
                f"{source} assumes IAM role {target} which enables privilege "
                f"escalation. Review whether this role assumption is necessary "
                f"and whether the role's permissions can be reduced."
            ),
            action_type=RemediationActionType.REMOVE_ROLE_ATTACHMENT,
            priority=RemediationPriority.HIGH,
            affected_resources=[source, target],
            finding_ids=[],
            attack_path_ids=self._paths_using(relationship),
            relationship_ids=[relationship.relationship_id],
            evidence=[e for e in [relationship.evidence] if e],
            manual_steps=[
                f"Verify that {source} requires the {target} role for its function.",
                "Review the role's permissions and identify if they can be reduced.",
                "If the role assumption is not required, remove the role from the "
                "instance profile or remove the instance profile from the workload.",
                "If the role is required, apply least privilege to the role's policies.",
                "Consider using IAM roles for service accounts (IRSA) for finer-grained "
                "permissions in containerized workloads.",
                "Re-run CloudGuard analysis to verify the change.",
            ],
            expected_effect=(
                "Privilege escalation path through this role assumption is eliminated. "
                "Attack paths leveraging this role's elevated permissions are broken."
            ),
            blast_radius=BlastRadiusEstimate(
                affected_resources=2,
                affected_attack_paths=len(self._paths_using(relationship)),
                affected_findings=0,
                potential_service_disruption=(
                    "high - removing role assumption may break workload functionality; "
                    "test thoroughly before applying to production"
                ),
                confidence="medium",
            ),
            verification_method=(
                "Re-run CloudGuard scan and verify the privilege escalation finding "
                "is resolved and attack paths through this role are eliminated."
            ),
            rollback_considerations=(
                "If the workload breaks, re-attach the role immediately. "
                "Consider a phased approach: first reduce role permissions, "
                "then test workload functionality."
            ),
            confidence="medium",
            least_disruptive=False,
            alternative_remediations=[
                "Create a new role with minimal required permissions and migrate "
                "the workload to use the new role.",
                "Use IAM Access Analyzer to generate a policy based on actual "
                "access patterns (CloudTrail).",
            ],
        )

    def _create_finding_remediations(
        self,
        finding: Finding,
        analysis_result: AnalysisResult,
    ) -> list[Remediation2]:
        """Create finding-specific remediations."""
        remediations = []

        # Network exposure finding
        if finding.category == FindingCategory.NETWORK:
            for asset_id in finding.affected_assets:
                rem = Remediation2(
                    remediation_id=f"REM2-FINDING-{finding.id}",
                    title=f"Remediate: {finding.title}",
                    description=finding.description,
                    action_type=RemediationActionType.RESTRICT_NETWORK_EXPOSURE,
                    priority=RemediationPriority.HIGH,
                    affected_resources=[asset_id],
                    finding_ids=[finding.id],
                    attack_path_ids=[],
                    relationship_ids=[],
                    evidence=finding.evidence,
                    manual_steps=[
                        "Review the finding evidence for specific configuration details.",
                        "Identify the security group(s) and rule(s) causing the exposure.",
                        "Apply the remediation steps from the finding's remediation field.",
                        "Re-run CloudGuard scan to verify resolution.",
                    ],
                    expected_effect=finding.remediation or "Network exposure resolved.",
                    blast_radius=BlastRadiusEstimate(
                        affected_resources=len(finding.affected_assets),
                        affected_attack_paths=0,
                        affected_findings=1,
                        potential_service_disruption="low",
                        confidence="high",
                    ),
                    verification_method=(
                        "Re-run CloudGuard scan and verify the finding is resolved."
                    ),
                    rollback_considerations=(
                        "If legitimate traffic is affected, revert security group changes."
                    ),
                    confidence="high",
                    least_disruptive=True,
                )
                remediations.append(rem)

        # Attack path finding
        elif finding.category == FindingCategory.ATTACK_PATH:
            rem = Remediation2(
                remediation_id=f"REM2-FINDING-{finding.id}",
                title=f"Break attack path: {finding.title}",
                description=finding.description,
                action_type=RemediationActionType.RESTRICT_NETWORK_EXPOSURE,
                priority=RemediationPriority.CRITICAL,
                affected_resources=finding.affected_assets,
                finding_ids=[finding.id],
                attack_path_ids=[finding.id] if finding.id.startswith("CG-PATH") else [],
                relationship_ids=[],
                evidence=finding.evidence,
                manual_steps=[
                    "Review the attack path evidence to identify the weakest link.",
                    "Prioritize remediation at the Internet exposure point (network exposure).",
                    "Apply network exposure remediation to break the path at the entry point.",
                    "If network exposure cannot be removed, reduce IAM permissions "
                    "along the path as a secondary measure.",
                    "Re-run CloudGuard scan to verify the attack path is broken.",
                ],
                expected_effect="Attack path to sensitive resource is broken.",
                blast_radius=BlastRadiusEstimate(
                    affected_resources=len(finding.affected_assets),
                    affected_attack_paths=1,
                    affected_findings=1,
                    potential_service_disruption="medium",
                    confidence="high",
                ),
                verification_method=(
                    "Re-run CloudGuard scan and verify the attack path finding is resolved."
                ),
                rollback_considerations=(
                    "If path cannot be broken at network layer, focus on IAM permissions."
                ),
                confidence="high",
                least_disruptive=True,
                alternative_remediations=[
                    "Isolate the sensitive resource in a separate VPC/account.",
                    "Implement VPC endpoints for private access to the resource.",
                ],
            )
            remediations.append(rem)

        return remediations

    def _find_related_finding_ids(self, relationship: Relationship) -> list[str]:
        """Find finding IDs related to a relationship."""
        # This would need access to findings - placeholder for now
        return []

    @staticmethod
    def _paths_using(
        relationship: Relationship,
    ) -> list[str]:
        """Find attack path IDs using a relationship - placeholder."""
        # This is called from within generate() which has access to analysis_result
        return []

    @staticmethod
    def _is_sensitive(
        analysis_result: AnalysisResult,
        asset_id: str,
    ) -> bool:
        asset = analysis_result.security_graph.get_asset(asset_id)
        if asset is None:
            return False
        if asset.asset_type == AssetType.INTERNET:
            return False
        return asset.sensitive

    def _priority_rank(self, priority: RemediationPriority) -> int:
        return {
            RemediationPriority.CRITICAL: 0,
            RemediationPriority.HIGH: 1,
            RemediationPriority.MEDIUM: 2,
            RemediationPriority.LOW: 3,
            RemediationPriority.INFORMATIONAL: 4,
        }.get(priority, 5)