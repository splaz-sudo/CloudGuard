import networkx as nx

from cloudguard.findings.models import (
    Finding,
    FindingCategory,
    Severity,
)
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.models.assets import AssetType
from cloudguard.models.relationships import RelationshipType


class FindingEngine:
    """
    Analyzes CloudGuard's security graph and produces
    security findings from discovered relationships.
    """

    def analyze(
        self,
        security_graph: SecurityGraph,
    ) -> list[Finding]:
        findings: list[Finding] = []

        findings.extend(
            self._find_internet_exposed_workloads(
                security_graph
            )
        )

        findings.extend(
            self._find_sensitive_attack_paths(
                security_graph
            )
        )

        return findings

    def _find_internet_exposed_workloads(
        self,
        security_graph: SecurityGraph,
    ) -> list[Finding]:
        findings: list[Finding] = []

        graph = security_graph.graph

        if "internet" not in graph:
            return findings

        for target_id in graph.successors("internet"):
            asset = security_graph.get_asset(target_id)

            if asset is None:
                continue

            if asset.asset_type != AssetType.EC2:
                continue

            relationship = (
                security_graph.get_relationship(
                    "internet",
                    target_id,
                )
            )

            if relationship is None:
                continue

            if (
                relationship.relationship_type
                != RelationshipType.EXPOSED_TO
            ):
                continue

            evidence = [
                "The workload is reachable from the internet."
            ]

            if relationship.evidence:
                evidence.append(
                    relationship.evidence
                )

            findings.append(
                Finding(
                    id=f"CG-NET-{target_id}",
                    title="Internet-exposed EC2 workload",
                    description=(
                        "An EC2 workload is reachable "
                        "from the public internet based "
                        "on its network configuration."
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.NETWORK,
                    affected_assets=[
                        target_id
                    ],
                    evidence=evidence,
                    remediation=(
                        "Restrict security-group ingress "
                        "to trusted networks and remove "
                        "unnecessary public exposure."
                    ),
                    risk_score=80,
                )
            )

        return findings

    def _find_sensitive_attack_paths(
        self,
        security_graph: SecurityGraph,
    ) -> list[Finding]:
        findings: list[Finding] = []

        graph = security_graph.graph

        if "internet" not in graph:
            return findings

        for target_id in graph.nodes:
            target = security_graph.get_asset(
                target_id
            )

            if target is None:
                continue

            if not target.sensitive:
                continue

            if target_id == "internet":
                continue

            if not nx.has_path(
                graph,
                "internet",
                target_id,
            ):
                continue

            paths = nx.all_simple_paths(
                graph,
                source="internet",
                target=target_id,
                cutoff=8,
            )

            for path_number, path in enumerate(
                paths,
                start=1,
            ):
                evidence: list[str] = []

                for index in range(
                    len(path) - 1
                ):
                    source_id = path[index]
                    destination_id = path[
                        index + 1
                    ]

                    relationship = (
                        security_graph.get_relationship(
                            source_id,
                            destination_id,
                        )
                    )

                    if relationship is None:
                        continue

                    evidence.append(
                        f"{source_id} "
                        f"--"
                        f"{relationship.relationship_type.value}"
                        f"--> "
                        f"{destination_id}"
                    )

                    if relationship.permissions:
                        evidence.append(
                            "Permissions: "
                            + ", ".join(
                                relationship.permissions
                            )
                        )

                    if relationship.evidence:
                        evidence.append(
                            relationship.evidence
                        )

                findings.append(
                    Finding(
                        id=(
                            f"CG-PATH-"
                            f"{target_id}-"
                            f"{path_number}"
                        ),
                        title=(
                            "Internet attack path to "
                            "sensitive resource"
                        ),
                        description=(
                            "CloudGuard discovered a "
                            "security relationship chain "
                            "from the public internet to "
                            "a sensitive cloud resource."
                        ),
                        severity=Severity.CRITICAL,
                        category=(
                            FindingCategory.ATTACK_PATH
                        ),
                        affected_assets=list(path),
                        evidence=evidence,
                        remediation=(
                            "Break the attack path by "
                            "restricting public exposure, "
                            "reducing IAM permissions, "
                            "or isolating the sensitive "
                            "resource."
                        ),
                        risk_score=95,
                    )
                )

        return findings
