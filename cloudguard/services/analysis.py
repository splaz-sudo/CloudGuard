from dataclasses import dataclass

from cloudguard.collectors import (
    CollectedEnvironment,
)
from cloudguard.findings.classifier import ResourceClassifier
from cloudguard.findings.engine import FindingEngine
from cloudguard.findings.models import Finding
from cloudguard.graph.attack_paths import (
    AttackPath,
    AttackPathEngine,
)
from cloudguard.graph.aws_graph import AWSGraphBuilder
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.local_lab import LocalAWSLab
from cloudguard.models.assets import CloudAsset
from cloudguard.normalizers.aws import AWSNormalizer


@dataclass
class AnalysisResult:
    """
    Complete result produced by a CloudGuard
    security analysis.
    """

    assets: list[CloudAsset]
    security_graph: SecurityGraph
    attack_paths: list[AttackPath]
    findings: list[Finding]

    environment: (
        CollectedEnvironment | None
    ) = None


class AnalysisService:
    """
    Runs CloudGuard's security analysis pipeline.

    The local mode uses simulated AWS resources and
    performs no AWS API calls.
    """

    def analyze_local_lab(
        self,
    ) -> AnalysisResult:
        lab = LocalAWSLab()

        (
            instances,
            security_groups,
            buckets,
            roles,
            instance_profiles,
        ) = lab.create_environment()

        return self.analyze_environment(
            instances=instances,
            security_groups=security_groups,
            buckets=buckets,
            roles=roles,
            instance_profiles=instance_profiles,
            account_id=lab.ACCOUNT_ID,
        )

    def analyze_environment(
        self,
        *,
        instances,
        security_groups,
        buckets,
        roles,
        instance_profiles,
        account_id: str,
        users=None,
    ) -> AnalysisResult:
        """
        Runs the analysis pipeline over an
        already-collected environment.

        Used by the local lab and by tests; the
        same entry point can serve real AWS
        collector output.
        """

        normalizer = AWSNormalizer()

        assets: list[CloudAsset] = []

        assets.extend(
            normalizer.normalize_ec2(
                instances,
                account_id,
            )
        )

        assets.extend(
            normalizer.normalize_s3(
                buckets,
                account_id,
            )
        )

        assets.extend(
            normalizer.normalize_roles(
                roles,
                account_id,
            )
        )

        if users:
            assets.extend(
                normalizer.normalize_users(
                    users,
                    account_id,
                )
            )

        classifier = ResourceClassifier()

        assets = classifier.classify(
            assets
        )

        graph_builder = AWSGraphBuilder()

        security_graph = graph_builder.build(
            assets=assets,
            instances=instances,
            security_groups=security_groups,
            roles=roles,
            instance_profiles=instance_profiles,
        )

        attack_engine = AttackPathEngine(
            security_graph
        )

        attack_paths = (
            attack_engine
            .find_paths_to_sensitive_assets()
        )

        finding_engine = FindingEngine()

        findings = finding_engine.analyze(
            security_graph
        )

        return AnalysisResult(
            assets=assets,
            security_graph=security_graph,
            attack_paths=attack_paths,
            findings=findings,
            environment=CollectedEnvironment(
                instances=list(instances),
                security_groups=list(
                    security_groups
                ),
                buckets=list(buckets),
                roles=list(roles),
                users=list(users or []),
                instance_profiles=list(
                    instance_profiles
                ),
                account_id=account_id,
            ),
        )
